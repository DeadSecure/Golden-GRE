#!/usr/bin/env bash
# End-to-end test: two network namespaces joined by a veth pair stand in for two servers. Brings real
# tunnels up with scripts/golden-gre-up.sh, runs the relays, moves data across, checks the firewall
# state and the health check, then tears down and checks nothing is left behind. Also covers a second
# tunnel on the same hosts, the icmp facade, and every failure path of the bringup.
# Needs root plus iproute2, iptables, ethtool, ping, curl, python3, gcc. Every namespace and config
# name carries this run's PID, so it never touches pre-existing state.
set -euo pipefail

cd "$(dirname "$0")/.."
UP=scripts/golden-gre-up.sh
DOWN=scripts/golden-gre-down.sh
CHECK=scripts/golden-gre-check.sh
RELAYSH=scripts/golden-gre-relay.sh

fail(){ echo "FAIL: $*" >&2; exit 1; }
ok(){ echo "ok: $*"; }

A="gg-a-$$" B="gg-b-$$" C="gg-c-$$"
CA="e2e-a-$$" CB="e2e-b-$$" CC="e2e-c-$$" CA2="e2e-a2-$$" CB2="e2e-b2-$$" CX="e2e-x-$$" CD="e2e-d-$$" CM="e2e-m-$$" R1="e2e-r1-$$" R2="e2e-r2-$$"
S1="e2e-s1-$$" S2="e2e-s2-$$" SB1="e2e-sb1-$$" SB2="e2e-sb2-$$" P1="e2e-p1-$$" P2="e2e-p2-$$"
tmp="$(mktemp -d)"
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  for ns in "$A" "$B" "$C"; do ip netns del "$ns" 2>/dev/null || true; done
  for c in "$CA" "$CB" "$CC" "$CA2" "$CB2" "$CX" "$CD" "$CM" "$R1" "$R2" "$S1" "$S2" "$SB1" "$SB2" "$P1" "$P2"; do rm -f "/etc/golden-gre/$c.conf"; done
  rm -rf "$tmp"
}
trap cleanup EXIT

gcc -O2 -Wall -pthread -o "$tmp/relay" relay/golden-gre-relay.c relay/monocypher.c
export GOLDEN_GRE_RELAY="$tmp/relay"

start_relay() { # namespace instance -> background relay, pid in $RELAY_PID
  ip netns exec "$1" "$RELAYSH" "$2" >"$tmp/relay-$2.log" 2>&1 &
  RELAY_PID=$!
  pids+=("$RELAY_PID")
}

# --- two "servers" on a shared underlay -------------------------------------
ip netns add "$A"
ip netns add "$B"
ip link add veth-a netns "$A" type veth peer name veth-b netns "$B"
ip -n "$A" addr add 192.0.2.1/24 dev veth-a
ip -n "$B" addr add 192.0.2.2/24 dev veth-b
ip -n "$A" addr add 192.0.2.11/24 dev veth-a   # second address pair, for a second tunnel
ip -n "$B" addr add 192.0.2.12/24 dev veth-b
for ns in "$A" "$B"; do ip -n "$ns" link set lo up; done
ip -n "$A" link set veth-a up
ip -n "$B" link set veth-b up

mkdir -p /etc/golden-gre
cat >"/etc/golden-gre/$CA.conf" <<'EOF'
DEV=gre1
LOCAL_PUB=192.0.2.1
REMOTE_PUB=192.0.2.2
TUN_ADDR=10.99.99.1/30
ROUTES="198.18.0.0/24"
NAT_SRC=10.99.99.0/30
GRE_KEY=42
FEC=8:4
EOF
cat >"/etc/golden-gre/$CB.conf" <<'EOF'
DEV=gre1
LOCAL_PUB=192.0.2.2
REMOTE_PUB=192.0.2.1
TUN_ADDR=10.99.99.2/30
GRE_KEY=42
EOF

# --- up ----------------------------------------------------------------------
ip netns exec "$A" "$UP" "$CA"
ip netns exec "$B" "$UP" "$CB"
start_relay "$A" "$CA"; RELAY_A=$RELAY_PID
start_relay "$B" "$CB"
# A DROP inserted ahead of our rules (Docker/ufw reload) must not survive a re-run.
ip netns exec "$A" iptables -I FORWARD -j DROP
ip netns exec "$A" "$UP" "$CA" >/dev/null   # second run must be harmless

ip netns exec "$A" ping -c 3 -W 2 -q 10.99.99.2 >/dev/null || fail "no ping across the tunnel (first packets must pass: no learning delay)"
ok "ping across the tunnel, from the first packet"
grep -q 'fec 8:4' "$tmp/relay-$CA.log" || fail "FEC=8:4 in the config did not reach the relay: $(cat "$tmp/relay-$CA.log")"
ok "FEC from the config reaches the relay; the peer decodes without the setting"

ip -n "$A" -d link show gre1 | grep -q 'encap fou encap-sport 5599 encap-dport 5601' \
  || fail "tunnel is not GRE-in-FOU on the loopback relay ports"
ok "loopback GRE-in-FOU toward the relay"

ip -n "$A" -d link show gre1 | grep -q 'ikey 0.0.0.42 okey 0.0.0.42' || fail "GRE_KEY not applied"
ok "GRE_KEY applied"

ip netns exec "$A" ip fou show | grep -q 'port 5599 ipproto 47 local 127.0.0.1' \
  || fail "FOU listener is not bound to loopback only"
ok "FOU listener on loopback only"

ip -n "$A" route show 198.18.0.0/24 | grep -q 'dev gre1' || fail "ROUTES not installed"
ok "ROUTES installed"

rules="$(ip netns exec "$A" iptables-save)"
for want in \
  '-A FORWARD -i gre1 -j ACCEPT' \
  '-A FORWARD -o gre1 -j ACCEPT' \
  '-A FORWARD -o gre1 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu' \
  '-A FORWARD -i gre1 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu' \
  '-A POSTROUTING -s 10.99.99.0/30 ! -o gre1 -j MASQUERADE' \
  "-A INPUT -s 192.0.2.2/32 -p udp -m udp --dport 53 -m comment --comment \"golden-gre:$CA\" -j ACCEPT"; do
  grep -qxF -- "$want" <<<"$rules" || fail "missing rule: $want"
  [ "$(grep -cxF -- "$want" <<<"$rules")" = 1 ] || fail "duplicated after re-run: $want"
done
grep -qE -- '-A INPUT .*--dport 53 .*-j DROP' <<<"$rules" && fail "a DROP on the DNS port would break a local resolver"
ok "FORWARD accept, MSS clamp, MASQUERADE and the peer-only INPUT accept present exactly once; no DROP"

top="$(ip netns exec "$A" iptables -S FORWARD | sed -n '2,3p')"
for want in '-A FORWARD -i gre1 -j ACCEPT' '-A FORWARD -o gre1 -j ACCEPT'; do
  grep -qxF -- "$want" <<<"$top" || fail "FORWARD accepts are not ahead of the DROP: $top"
done
ip netns exec "$A" iptables -D FORWARD -j DROP
ok "re-run moves FORWARD accepts back above a DROP"

# --- data, not just ping -------------------------------------------------------
head -c 20000000 /dev/urandom >"$tmp/blob"
(cd "$tmp" && ip netns exec "$B" python3 -m http.server 8000 --bind 10.99.99.2 >/dev/null 2>&1) &
pids+=("$!")
sleep 1
got="$(ip netns exec "$A" curl -s --max-time 60 -o "$tmp/got" -w '%{size_download}' http://10.99.99.2:8000/blob)"
[ "$got" = 20000000 ] || fail "20 MB transfer through the tunnel returned $got bytes"
cmp -s "$tmp/blob" "$tmp/got" || fail "transferred data differs"
ok "20 MB transferred through the tunnel, bit for bit"

# --- port forwarding: A's public ports to services on B, through the tunnel -----
# The client is B's second address (192.0.2.12): anything but the peer's own address is forwarded.
ip netns exec "$B" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.99.99.2", 9000))
while True:
    d, a = s.recvfrom(2048); s.sendto(b"echo:" + d, a)' >/dev/null 2>&1 &
pids+=("$!")
# Commas, with and without a space, separate entries too.
echo 'FORWARD="8080=8000,8000, 9000:9001"' >>"/etc/golden-gre/$CA.conf"
ip netns exec "$A" "$UP" "$CA" >/dev/null
ip netns exec "$A" "$UP" "$CA" >/dev/null   # a re-run must not duplicate the rules
fwd="$(ip netns exec "$A" iptables-save -t nat | grep -F "golden-gre-fwd:$CA" || true)"
[ "$(grep -c -- "-j DNAT" <<<"$fwd")" = 6 ] || fail "want 6 DNAT rules (3 entries x tcp/udp), got: $fwd"
[ "$(grep -c MASQUERADE <<<"$fwd")" = 1 ] || fail "want 1 MASQUERADE for forwarded traffic, got: $fwd"
got="$(ip netns exec "$B" curl -s --max-time 20 --interface 192.0.2.12 -o "$tmp/got" -w '%{size_download}' http://192.0.2.1:8080/blob)"
if ! { [ "$got" = 20000000 ] && cmp -s "$tmp/blob" "$tmp/got"; }; then fail "TCP 8080=8000 through A returned $got bytes"; fi
got="$(ip netns exec "$B" curl -s --max-time 20 --interface 192.0.2.12 -o /dev/null -w '%{http_code}' http://192.0.2.1:8000/blob)"
[ "$got" = 200 ] || fail "TCP 8000 (same port) through A returned HTTP $got"
got="$(ip netns exec "$B" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("192.0.2.12", 0)); s.settimeout(5)
s.sendto(b"hi", ("192.0.2.1", 9000)); print(s.recvfrom(2048)[0].decode())' 2>&1)"
[ "$got" = "echo:hi" ] || fail "UDP 9000 (range 9000:9001) through A returned: $got"
# The peer's own address is never forwarded: that is the relay's traffic (UDP 53) and the peer's SSH.
ip netns exec "$B" curl -s --max-time 5 --interface 192.0.2.2 -o /dev/null http://192.0.2.1:8000/ \
  && fail "traffic from the peer's own address was forwarded"
ok "forwarded TCP (P=Q and same port) and UDP (range) reach the peer's services; the peer's own traffic is not forwarded"

sed -i 's/^FORWARD=.*/FORWARD="8080=8000"/' "/etc/golden-gre/$CA.conf"
ip netns exec "$A" "$UP" "$CA" >/dev/null
fwd="$(ip netns exec "$A" iptables-save -t nat | grep -F "golden-gre-fwd:$CA" || true)"
[ "$(grep -c -- "-j DNAT" <<<"$fwd")" = 2 ] || fail "removed entries left DNAT rules behind: $fwd"
for bad in 0 70000 22 80:70 abc 8080=0; do
  sed -i "s/^FORWARD=.*/FORWARD=\"$bad\"/" "/etc/golden-gre/$CA.conf"
  ip netns exec "$A" "$UP" "$CA" >/dev/null 2>&1 && fail "up accepted FORWARD=\"$bad\""
done
sed -i 's/^FORWARD=.*/FORWARD="8080=8000"/' "/etc/golden-gre/$CA.conf"
ip netns exec "$A" ping -c 3 -W 2 -q 10.99.99.2 >/dev/null || fail "a refused FORWARD entry tore down the live tunnel"
ok "changed FORWARD drops old rules; invalid entries and port 22 are refused without tearing the tunnel down"

# --- a failing re-run on a live tunnel must not tear it down -------------------
# systemd still shows such a tunnel active, so nothing would bring it back.
echo 'ROUTES="10.50.0.0/33"' >>"/etc/golden-gre/$CA.conf"
ip netns exec "$A" "$UP" "$CA" >/dev/null 2>&1 && fail "up succeeded with an invalid ROUTES entry"
sed -i '$d' "/etc/golden-gre/$CA.conf"
ip netns exec "$A" ping -c 3 -W 2 -q 10.99.99.2 >/dev/null || fail "a failed re-run tore down a live tunnel"
ok "a failing re-run leaves a live tunnel up"

# --- health check ------------------------------------------------------------
ip netns exec "$A" "$CHECK" "$CA" >/dev/null || fail "check failed on a healthy tunnel"
ip netns exec "$B" "$CHECK" "$CB" >/dev/null || fail "check failed from the .2 end (peer derivation)"
ok "check passes on a healthy tunnel"

sed -i 's/^GRE_KEY=42$/GRE_KEY=43/' "/etc/golden-gre/$CB.conf"
ip netns exec "$B" "$UP" "$CB" >/dev/null
ip netns exec "$A" "$CHECK" "$CA" >/dev/null 2>&1 && fail "check passed although the GRE keys differ"
ok "mismatched GRE_KEY blocks traffic and check reports it"
sed -i 's/^GRE_KEY=43$/GRE_KEY=42/' "/etc/golden-gre/$CB.conf"
ip netns exec "$B" "$UP" "$CB" >/dev/null

# --- a second tunnel on the same two hosts -------------------------------------
# Own addresses (the relay binds one), GRE key, FOU port and relay port.
cat >"/etc/golden-gre/$CA2.conf" <<'EOF'
DEV=gre2
LOCAL_PUB=192.0.2.11
REMOTE_PUB=192.0.2.12
TUN_ADDR=10.99.97.1/30
GRE_KEY=44
FOU_PORT=5600
RELAY_PORT=5602
EOF
cat >"/etc/golden-gre/$CB2.conf" <<'EOF'
DEV=gre2
LOCAL_PUB=192.0.2.12
REMOTE_PUB=192.0.2.11
TUN_ADDR=10.99.97.2/30
GRE_KEY=44
FOU_PORT=5600
RELAY_PORT=5602
EOF
# A tunnel that reuses the first tunnel's FOU port must be refused without touching the first one.
cat >"/etc/golden-gre/$CD.conf" <<'EOF'
DEV=gre3
LOCAL_PUB=192.0.2.11
REMOTE_PUB=192.0.2.12
TUN_ADDR=10.99.95.1/30
GRE_KEY=45
RELAY_PORT=5603
EOF
out="$(ip netns exec "$A" "$UP" "$CD" 2>&1)" && fail "up accepted a FOU port that another tunnel holds"
grep -q 'already in use' <<<"$out" || fail "the shared FOU port is not explained: $out"
ip -n "$A" link show gre3 >/dev/null 2>&1 && fail "refused up left a device behind"
ip netns exec "$A" ping -c 3 -W 2 -q 10.99.99.2 >/dev/null || fail "refusing a second tunnel broke the first"
ip netns exec "$A" ip fou show | grep -q 'port 5599' || fail "refusing a second tunnel removed the first tunnel's FOU listener"
ok "a tunnel sharing another tunnel's FOU port is refused and the first keeps running"

ip netns exec "$A" scripts/preflight.sh "$CA2" >/dev/null || fail "preflight rejected a valid config"
ok "preflight accepts a valid config"
ip netns exec "$A" "$UP" "$CA2"
ip netns exec "$B" "$UP" "$CB2"
start_relay "$A" "$CA2"; RELAY_A2=$RELAY_PID
start_relay "$B" "$CB2"; RELAY_B2=$RELAY_PID
ip netns exec "$A" ping -c 3 -W 2 -q 10.99.97.2 >/dev/null || fail "no ping across the second tunnel"
ip netns exec "$A" ping -c 3 -W 2 -q 10.99.99.2 >/dev/null || fail "the first tunnel stopped working"
ok "two tunnels between the same hosts both carry traffic"
ip netns exec "$A" scripts/preflight.sh "$CA2" >/dev/null 2>&1 && fail "preflight accepted a DNS port that the running relay holds"
ok "preflight reports the DNS port in use"

# --- down --------------------------------------------------------------------
kill "$RELAY_A2" "$RELAY_B2" 2>/dev/null || true
ip netns exec "$A" "$DOWN" "$CA2" >/dev/null
ip netns exec "$B" "$DOWN" "$CB2" >/dev/null
ip netns exec "$A" ping -c 3 -W 2 -q 10.99.99.2 >/dev/null || fail "downing the second tunnel broke the first"
ip -n "$A" link show gre2 >/dev/null 2>&1 && fail "gre2 still exists after down"
ip netns exec "$A" ip fou show | grep -q 'port 5600' && fail "second tunnel's FOU listener left behind"
ip netns exec "$A" iptables-save | grep -q "golden-gre:$CA2" && fail "second tunnel's INPUT rule left behind"
ok "downing one tunnel leaves the other running and removes only its own state"

kill "$RELAY_A" 2>/dev/null || true
ip netns exec "$A" "$DOWN" "$CA"
ip netns exec "$A" "$DOWN" "$CA" >/dev/null   # second run must be harmless
ip -n "$A" link show gre1 >/dev/null 2>&1 && fail "gre1 still exists after down"
ip netns exec "$A" ip fou show | grep -q 'port 5599' && fail "FOU listener left behind"
ip netns exec "$A" iptables-save | grep -qE 'gre1|golden-gre:|golden-gre-fwd:' && fail "iptables rules left behind"
ok "down removed device, FOU listener and rules"

# --- the icmp facade -----------------------------------------------------------
sed -i 's/^TUN_ADDR=10.99.97.1\/30$/TUN_ADDR=10.99.97.1\/30\nFACADE=icmp/' "/etc/golden-gre/$CA2.conf"
sed -i 's/^TUN_ADDR=10.99.97.2\/30$/TUN_ADDR=10.99.97.2\/30\nFACADE=icmp/' "/etc/golden-gre/$CB2.conf"
ip netns exec "$A" "$UP" "$CA2" >/dev/null
ip netns exec "$B" "$UP" "$CB2" >/dev/null
start_relay "$A" "$CA2"
start_relay "$B" "$CB2"
ip netns exec "$A" ping -c 3 -W 2 -q 10.99.97.2 >/dev/null || fail "no ping across a tunnel with the icmp facade"
ip netns exec "$A" iptables-save | grep -qF -- "-A INPUT -s 192.0.2.12/32 -p icmp -m comment --comment \"golden-gre:$CA2\" -j ACCEPT" \
  || fail "icmp facade has no peer-only icmp INPUT accept"
ok "icmp facade carries traffic and opens icmp from the peer only"
kill "${pids[@]: -2}" 2>/dev/null || true
wait "${pids[@]: -2}" 2>/dev/null || true   # the next section's relays bind the same local port
ip netns exec "$A" "$DOWN" "$CA2" >/dev/null
ip netns exec "$B" "$DOWN" "$CB2" >/dev/null
ip netns exec "$A" iptables-save | grep -q "golden-gre:$CA2" && fail "icmp INPUT rule left behind"
ok "down removes the icmp rule"

# --- ICMP_TYPE=8: the wire carries echo requests, for paths that drop unsolicited echo replies ------
# The raw-table rule in A plays the filter: every echo reply reaching A on the underlay is dropped. Echo requests must
# carry the tunnel, and B's kernel must not answer them (its replies would double the traffic).
for c in "$CA2" "$CB2"; do echo 'ICMP_TYPE=8' >>"/etc/golden-gre/$c.conf"; done
ip netns exec "$A" iptables -t raw -I PREROUTING -i veth-a -p icmp --icmp-type echo-reply -j DROP
ip netns exec "$A" "$UP" "$CA2" >/dev/null
ip netns exec "$B" "$UP" "$CB2" >/dev/null
start_relay "$A" "$CA2"
start_relay "$B" "$CB2"
ip netns exec "$A" ping -c 1 -w 5 -q 10.99.97.2 >/dev/null || fail "ICMP_TYPE=8 tunnel never answered behind a filter that drops echo replies"
ip netns exec "$A" ping -c 20 -i 0.05 -W 2 -q 10.99.97.2 >"$tmp/req.ping" 2>&1 || fail "ICMP_TYPE=8 tunnel lost pings: $(cat "$tmp/req.ping")"
grep -q ' 0% packet loss' "$tmp/req.ping" || fail "ICMP_TYPE=8 tunnel lost pings: $(cat "$tmp/req.ping")"
grep -q 'itype 8' "$tmp/relay-$CA2.log" || fail "ICMP_TYPE=8 did not reach the relay: $(cat "$tmp/relay-$CA2.log")"
drops="$(ip netns exec "$A" iptables -t raw -L PREROUTING -vnx | awk '/echo-reply|type 0/ {print $1; exit}')"
[ "$drops" = 0 ] || fail "B's kernel answered the relay's echo requests ($drops echo replies reached A)"
ip netns exec "$B" iptables-save | grep -qF -- "-A OUTPUT -s 192.0.2.12/32 -d 192.0.2.11/32 -p icmp -m icmp --icmp-type 0 -m comment --comment \"golden-gre:$CB2\" -j DROP" \
  || fail "ICMP_TYPE=8 has no OUTPUT drop for the kernel's echo replies to the peer"
ok "ICMP_TYPE=8 carries the tunnel as echo requests, and no kernel echo replies leave for the peer"
kill "${pids[@]: -2}" 2>/dev/null || true
wait "${pids[@]: -2}" 2>/dev/null || true
ip netns exec "$A" iptables -t raw -D PREROUTING -i veth-a -p icmp --icmp-type echo-reply -j DROP
ip netns exec "$A" "$DOWN" "$CA2" >/dev/null
ip netns exec "$B" "$DOWN" "$CB2" >/dev/null
ip netns exec "$B" iptables-save | grep -q "golden-gre:$CB2" && fail "ICMP_TYPE=8 OUTPUT rule left behind"
ok "down removes the echo-reply drop"

# Ends with different ICMP_TYPE: nothing passes, and each relay says why instead of going quiet.
sed -i 's/^ICMP_TYPE=8$/ICMP_TYPE=0/' "/etc/golden-gre/$CB2.conf"
ip netns exec "$A" "$UP" "$CA2" >/dev/null
ip netns exec "$B" "$UP" "$CB2" >/dev/null
start_relay "$A" "$CA2"
start_relay "$B" "$CB2"
ip netns exec "$A" ping -c 3 -i 0.2 -W 1 -q 10.99.97.2 >/dev/null 2>&1 || true
sleep 0.5
grep -q 'got ICMP type 8, ICMP_TYPE here is 0' "$tmp/relay-$CB2.log" || fail "the relay did not report the peer's other ICMP_TYPE: $(cat "$tmp/relay-$CB2.log")"
[ "$(grep -c 'ICMP_TYPE here' "$tmp/relay-$CB2.log")" = 1 ] || fail "the ICMP_TYPE mismatch was reported more than once"
ok "a relay reports once when the peer uses the other ICMP_TYPE"
kill "${pids[@]: -2}" 2>/dev/null || true
wait "${pids[@]: -2}" 2>/dev/null || true
ip netns exec "$A" "$DOWN" "$CA2" >/dev/null
ip netns exec "$B" "$DOWN" "$CB2" >/dev/null
sed -i 's/^ICMP_TYPE=0$/ICMP_TYPE=8/' "/etc/golden-gre/$CB2.conf"

# The tunnel's own firewall rules go by their tag, even after LOCAL_PUB changed in the config.
tagged() { ip netns exec "$B" iptables -S | tr -d '"' | grep -F -- " --comment golden-gre:$CB2 " || true; }
ip netns exec "$B" "$UP" "$CB2" >/dev/null
sed -i 's/^LOCAL_PUB=192.0.2.12$/LOCAL_PUB=192.0.2.2/' "/etc/golden-gre/$CB2.conf"
ip netns exec "$B" "$UP" "$CB2" >/dev/null
[[ $(tagged) != *"-s 192.0.2.12/32"* ]] || fail "a re-run after LOCAL_PUB changed left the old address's rule: $(tagged)"
[[ $(tagged) == *"-s 192.0.2.2/32 -d 192.0.2.11/32"* ]] || fail "a re-run after LOCAL_PUB changed has no rule for the new address: $(tagged)"
sed -i 's/^LOCAL_PUB=192.0.2.2$/LOCAL_PUB=192.0.2.12/' "/etc/golden-gre/$CB2.conf"
ip netns exec "$B" "$DOWN" "$CB2" >/dev/null
[ -z "$(tagged)" ] || fail "down after LOCAL_PUB changed left rules behind: $(tagged)"
ok "rules are removed by the tunnel's tag, whatever the config's addresses are now"

# Two icmp tunnels on one address pair must agree on ICMP_TYPE: the type-8 tunnel's drop of echo replies
# to the peer would eat every packet of a type-0 one.
ip netns exec "$B" "$UP" "$CB2" >/dev/null
cat >"/etc/golden-gre/$CM.conf" <<'EOF'
DEV=gre7
LOCAL_PUB=192.0.2.12
REMOTE_PUB=192.0.2.11
TUN_ADDR=10.99.87.2/30
FACADE=icmp
GRE_KEY=77
FOU_PORT=5631
RELAY_PORT=5632
EOF
out="$(ip netns exec "$B" "$UP" "$CM" 2>&1)" && fail "up accepted icmp replies next to an ICMP_TYPE=8 tunnel on the same address pair"
grep -q "$CB2" <<<"$out" || fail "refusing a mixed ICMP_TYPE pair does not name the other tunnel: $out"
ip -n "$B" link show gre7 >/dev/null 2>&1 && fail "a refused mixed ICMP_TYPE bringup created its device"
ip netns exec "$B" "$DOWN" "$CB2" >/dev/null
ok "icmp tunnels on one address pair with different ICMP_TYPE are refused"

# An ICMP_TYPE other than 0 or 8 is refused by up, preflight and the relay.
sed -i 's/^ICMP_TYPE=8$/ICMP_TYPE=5/' "/etc/golden-gre/$CB2.conf"
ip netns exec "$B" "$UP" "$CB2" >/dev/null 2>&1 && fail "up accepted ICMP_TYPE=5"
ip netns exec "$B" scripts/preflight.sh "$CB2" >/dev/null 2>&1 && fail "preflight accepted ICMP_TYPE=5"
"$tmp/relay" --facade icmp --bind 127.0.0.1 --peer 127.0.0.2 --local 127.0.0.1:5699 --itype 5 >/dev/null 2>&1 \
  && fail "the relay accepted --itype 5"
sed -i 's/^ICMP_TYPE=5$/ICMP_TYPE=8/' "/etc/golden-gre/$CB2.conf"
ok "ICMP_TYPE other than 0 or 8 is refused by up, preflight and the relay"

# --- several icmp tunnels on one public address, to different peers ------------
# A's two tunnels share LOCAL_PUB 192.0.2.1; the peers are B's two addresses. Each relay must take
# only its own peer's packets, and both tunnels must carry traffic at the same time.
shared() { # name dev local remote tun key fou relay
  cat >"/etc/golden-gre/$1.conf" <<EOF
DEV=$2
LOCAL_PUB=$3
REMOTE_PUB=$4
TUN_ADDR=$5
FACADE=icmp
GRE_KEY=$6
FOU_PORT=$7
RELAY_PORT=$8
EOF
}
shared "$S1"  gs1 192.0.2.1  192.0.2.2  10.99.91.1/30 61 5611 5612
shared "$S2"  gs2 192.0.2.1  192.0.2.12 10.99.92.1/30 62 5613 5614
shared "$SB1" gs1 192.0.2.2  192.0.2.1  10.99.91.2/30 61 5611 5612
shared "$SB2" gs2 192.0.2.12 192.0.2.1  10.99.92.2/30 62 5613 5614
for c in "$S1" "$S2"; do ip netns exec "$A" "$UP" "$c" >/dev/null; start_relay "$A" "$c"; done
for c in "$SB1" "$SB2"; do ip netns exec "$B" "$UP" "$c" >/dev/null; start_relay "$B" "$c"; done
# Wait until both relays are up (the first packets can go out before they bind), then demand zero loss.
for t in 10.99.91.2 10.99.92.2; do
  ip netns exec "$A" ping -c 1 -w 5 -q "$t" >/dev/null || fail "tunnel to $t on a shared address never answered"
done
ip netns exec "$A" ping -c 40 -i 0.05 -W 2 -q 10.99.91.2 >"$tmp/s1.ping" 2>&1 & p1=$!
ip netns exec "$A" ping -c 40 -i 0.05 -W 2 -q 10.99.92.2 >"$tmp/s2.ping" 2>&1 & p2=$!
wait "$p1" || fail "tunnel 1 of 2 on a shared address lost pings: $(cat "$tmp/s1.ping")"
wait "$p2" || fail "tunnel 2 of 2 on a shared address lost pings: $(cat "$tmp/s2.ping")"
if ! { grep -q ' 0% packet loss' "$tmp/s1.ping" && grep -q ' 0% packet loss' "$tmp/s2.ping"; }; then
  fail "shared-address tunnels dropped packets: $(cat "$tmp/s1.ping" "$tmp/s2.ping")"
fi
ok "two icmp tunnels on one public address carry traffic to two peers at the same time"
kill "${pids[@]: -4}" 2>/dev/null || true
for c in "$S1" "$S2"; do ip netns exec "$A" "$DOWN" "$c" >/dev/null; done
for c in "$SB1" "$SB2"; do ip netns exec "$B" "$DOWN" "$c" >/dev/null; done

# --- no disguise: plain GRE between the public addresses, no relay -------------------------------
plain() { # name local remote tun
  cat >"/etc/golden-gre/$1.conf" <<EOF
DEV=grp
LOCAL_PUB=$2
REMOTE_PUB=$3
TUN_ADDR=$4
FACADE=none
GRE_KEY=81
EOF
}
plain "$P1" 192.0.2.1 192.0.2.2 10.99.71.1/30
plain "$P2" 192.0.2.2 192.0.2.1 10.99.71.2/30
ip netns exec "$A" scripts/preflight.sh "$P1" >/dev/null || fail "preflight rejected FACADE=none"
ip netns exec "$A" "$UP" "$P1" >/dev/null
ip netns exec "$B" "$UP" "$P2" >/dev/null
ip -n "$A" -d link show grp | grep -q 'gre remote 192.0.2.2 local 192.0.2.1' \
  || fail "FACADE=none is not GRE between the public addresses: $(ip -n "$A" -d link show grp)"
[ -z "$(ip netns exec "$A" ip fou show)" ] || fail "FACADE=none added a FOU listener: $(ip netns exec "$A" ip fou show)"
ip netns exec "$A" iptables-save | grep -qF -- "-A INPUT -s 192.0.2.2/32 -p gre -m comment --comment \"golden-gre:$P1\" -j ACCEPT" \
  || fail "FACADE=none has no peer-only GRE INPUT accept"
# The unit's main process: with no relay to run it must still stay up, or Restart=always rebuilds the tunnel.
start_relay "$A" "$P1"
start_relay "$B" "$P2"
ip netns exec "$A" ping -c 3 -W 2 -q 10.99.71.2 >/dev/null || fail "no ping across a FACADE=none tunnel"
kill -0 "$RELAY_PID" 2>/dev/null || fail "golden-gre-relay.sh exited with FACADE=none: $(cat "$tmp/relay-$P2.log")"
ok "no disguise: plain GRE between the public addresses, GRE from the peer only, no FOU listener, no relay"
kill "${pids[@]: -2}" 2>/dev/null || true
wait "${pids[@]: -2}" 2>/dev/null || true
ip netns exec "$A" "$DOWN" "$P1" >/dev/null
ip netns exec "$B" "$DOWN" "$P2" >/dev/null
ip -n "$A" link show grp >/dev/null 2>&1 && fail "grp still exists after down"
ip netns exec "$A" iptables-save | grep -q "golden-gre:$P1" && fail "FACADE=none INPUT rule left behind"
ok "down removes the plain GRE device and its rule"

# --- dns facade on a path that passes only the first 6 packets of each flow ------------------------
# connbytes in each host's mangle PREROUTING plays the filter (in INPUT it would sit below the tunnel's
# own accept). Without SPORT_ROTATE one source port carries the whole tunnel and is cut; with
# SPORT_ROTATE=5 every source port stays under the limit. DNS_PORTS is written with a space after the
# comma, as the README allows. The .11/.12 pair: a relay of the first section may still hold .1/.2:53.
rot() { # name local remote tun
  cat >"/etc/golden-gre/$1.conf" <<EOF
DEV=grr
LOCAL_PUB=$2
REMOTE_PUB=$3
TUN_ADDR=$4
GRE_KEY=71
FOU_PORT=5621
RELAY_PORT=5622
DNS_PORTS="53, 853"
RATE=3000
EOF
}
rot "$R1" 192.0.2.11 192.0.2.12 10.99.81.1/30
rot "$R2" 192.0.2.12 192.0.2.11 10.99.81.2/30
CUT=(-p udp -m multiport --dports "53,853" -m connbytes --connbytes 7: --connbytes-dir original --connbytes-mode packets -j DROP)
for ns in "$A" "$B"; do ip netns exec "$ns" iptables -t mangle -I PREROUTING "${CUT[@]}"; done
ip netns exec "$A" "$UP" "$R1" >/dev/null || fail "up refused DNS_PORTS=\"53, 853\""
ip netns exec "$B" "$UP" "$R2" >/dev/null || fail "up refused DNS_PORTS=\"53, 853\""
for port in 53 853; do
  ip netns exec "$A" iptables -S INPUT | grep -F "golden-gre:$R1" | grep -q "$port" || fail "DNS_PORTS: no INPUT accept for port $port"
done
start_relay "$A" "$R1"
start_relay "$B" "$R2"
ip netns exec "$A" ping -c 30 -i 0.05 -W 1 -q 10.99.81.2 >"$tmp/cut.ping" 2>&1 || true
grep -q ' 0% packet loss' "$tmp/cut.ping" && fail "the simulated filter did not cut a single-port dns tunnel; the test proves nothing"
kill "${pids[@]: -2}" 2>/dev/null || true
wait "${pids[@]: -2}" 2>/dev/null || true
for c in "$R1" "$R2"; do echo 'SPORT_ROTATE=5' >>"/etc/golden-gre/$c.conf"; done
start_relay "$A" "$R1"
start_relay "$B" "$R2"
ip netns exec "$A" ping -c 1 -w 5 -q 10.99.81.2 >/dev/null || fail "SPORT_ROTATE=5 tunnel never answered behind a 6-packets-per-flow filter"
ip netns exec "$A" ping -c 60 -i 0.05 -W 1 -q 10.99.81.2 >"$tmp/rot.ping" 2>&1 || fail "SPORT_ROTATE=5 tunnel lost pings: $(cat "$tmp/rot.ping")"
grep -q ' 0% packet loss' "$tmp/rot.ping" || fail "SPORT_ROTATE=5 tunnel lost pings: $(cat "$tmp/rot.ping")"
grep -q 'rotate 5, 2 ports, rate 3000' "$tmp/relay-$R1.log" || fail "SPORT_ROTATE, DNS_PORTS or RATE did not reach the relay: $(cat "$tmp/relay-$R1.log")"
ok "SPORT_ROTATE keeps a dns tunnel alive on a path that cuts each flow after 6 packets; DNS_PORTS takes \"53, 853\""
kill "${pids[@]: -2}" 2>/dev/null || true
wait "${pids[@]: -2}" 2>/dev/null || true
for ns in "$A" "$B"; do ip netns exec "$ns" iptables -t mangle -D PREROUTING "${CUT[@]}"; done
ip netns exec "$A" "$DOWN" "$R1" >/dev/null
ip netns exec "$B" "$DOWN" "$R2" >/dev/null
ip netns exec "$A" iptables -S | grep -q "golden-gre:$R1" && fail "down left the DNS_PORTS accept behind"
ip netns exec "$A" scripts/preflight.sh "$R1" >/dev/null || fail "preflight rejected a valid DNS_PORTS config"
(ip netns exec "$A" python3 -c 'import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("192.0.2.11",853)); time.sleep(5)' &)
sleep 0.5
ip netns exec "$A" scripts/preflight.sh "$R1" >"$tmp/pf.out" 2>&1 && fail "preflight missed a busy port in DNS_PORTS: $(cat "$tmp/pf.out")"
grep -q ':853 is already in use' "$tmp/pf.out" || fail "preflight does not name the busy DNS_PORTS port: $(cat "$tmp/pf.out")"
ok "down removes the DNS_PORTS accept; preflight checks every port in DNS_PORTS"

# --- a bringup that fails partway must roll back everything it created --------
# MTU is applied after the FOU listener, INPUT rule, device and address exist.
echo 'MTU=bogus' >>"/etc/golden-gre/$CA.conf"
ip netns exec "$A" "$UP" "$CA" >/dev/null 2>&1 && fail "up succeeded with an invalid MTU"
ip -n "$A" link show gre1 >/dev/null 2>&1 && fail "failed up left gre1 behind"
ip netns exec "$A" ip fou show | grep -q 'port 5599' && fail "failed up left the FOU listener behind"
ip netns exec "$A" iptables-save | grep -qE 'gre1|golden-gre:' && fail "failed up left iptables rules behind"
ok "failed bringup rolls back device, FOU listener and rules"

# --- a bringup stopped mid-run (systemctl stop during start) must roll back too -
# An ethtool shim holds up at the GSO step, after listener, rules and device
# exist. SIGTERM goes to the whole process group, as systemd sends it to the cgroup.
sed -i '/^MTU=bogus$/d' "/etc/golden-gre/$CA.conf"
shim="$(mktemp -d)"
printf '#!/bin/sh\nexec sleep 30\n' >"$shim/ethtool"
chmod +x "$shim/ethtool"
ip netns exec "$A" env PATH="$shim:$PATH" setsid "$UP" "$CA" >/dev/null 2>&1 &
pid=$!
for _ in $(seq 50); do ip -n "$A" link show gre1 >/dev/null 2>&1 && break; sleep 0.1; done
ip -n "$A" link show gre1 >/dev/null 2>&1 || fail "up never reached the device step"
kill -TERM -- "-$pid"
rc=0; wait "$pid" || rc=$?
rm -rf "$shim"
[ "$rc" -ne 0 ] || fail "up exited 0 after SIGTERM"
ip -n "$A" link show gre1 >/dev/null 2>&1 && fail "stopped up left gre1 behind"
ip netns exec "$A" ip fou show | grep -q 'port 5599' && fail "stopped up left the FOU listener behind"
ip netns exec "$A" iptables-save | grep -qE 'gre1|golden-gre:' && fail "stopped up left iptables rules behind"
ok "bringup stopped by SIGTERM rolls back"

# --- early boot: the local address or the route is not there yet -----------------
ip netns add "$C"
ip -n "$C" link set lo up
cat >"/etc/golden-gre/$CC.conf" <<'EOF'
DEV=gre1
LOCAL_PUB=192.0.2.9
REMOTE_PUB=198.51.100.9
TUN_ADDR=10.99.98.1/30
EOF
ip netns exec "$C" "$UP" "$CC" 2>/dev/null && fail "up succeeded although LOCAL_PUB is not on this host"
ip -n "$C" link show gre1 >/dev/null 2>&1 && fail "failed up left gre1 behind"
ok "LOCAL_PUB not configured yet: up fails before creating anything"

ip -n "$C" link add dummy0 type dummy
ip -n "$C" addr add 192.0.2.9/32 dev dummy0
ip -n "$C" link set dummy0 up
out="$(ip netns exec "$C" "$UP" "$CC" 2>&1)" && fail "up succeeded with no route to the peer"
grep -q 'no route' <<<"$out" || fail "missing route is not explained: $out"
ip -n "$C" link show gre1 >/dev/null 2>&1 && fail "failed up left gre1 behind"
ok "no route to the peer: up fails before creating anything"

# --- IPv4 only -----------------------------------------------------------------
cat >"/etc/golden-gre/$CX.conf" <<'EOF'
DEV=gre1
LOCAL_PUB=2001:db8::1
REMOTE_PUB=2001:db8::2
TUN_ADDR=10.99.96.1/30
EOF
out="$(ip netns exec "$A" "$UP" "$CX" 2>&1)" && fail "up accepted IPv6 endpoints"
grep -q 'IPv4' <<<"$out" || fail "IPv6 endpoints are not explained: $out"
ok "IPv6 endpoints are rejected with an explanation"

# --- payload encryption (--keyfile): two relays over loopback, every behaviour ---
out="$(python3 tests/crypto_test.py "$tmp/relay" kdf 2>&1)" || fail "crypto kdf: $out"
for facade in dns icmp; do
  for case in deliver encrypted markers wrongkey legacy; do
    [ "$facade" = icmp ] && [ "$case" = encrypted ] && continue  # icmp capture is covered by markers
    out="$(python3 tests/crypto_test.py "$tmp/relay" "$facade" "$case" 2>&1)" || fail "crypto $facade/$case: $out"
  done
done
ok "payload encryption: deliver, encrypted, random markers, wrong-key drop and legacy pass for dns and icmp"

echo "e2e: PASS"
