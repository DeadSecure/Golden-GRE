#!/usr/bin/env bash
# Easy manager (golden-gre.sh): both servers must derive matching tunnel settings from the same two IPs,
# typed in either order. As root, also runs the real setup dialog in two network namespaces (each with
# its own /etc/golden-gre) and checks that a ping crosses the tunnel it built, and that a second tunnel
# on the same public address is refused. Without root only the first part runs.
set -euo pipefail

cd "$(dirname "$0")/.."
fail(){ echo "FAIL: $*" >&2; exit 1; }
ok(){ echo "ok: $*"; }

# shellcheck source=golden-gre.sh
. ./golden-gre.sh

valid_ip 203.0.113.10 || fail "rejected 203.0.113.10"
for bad in 256.1.1.1 1.2.3 1.2.3.4.5 a.b.c.d "" " 1.2.3.4" 1.2.3.4/30 05.6.7.8; do
  if valid_ip "$bad"; then fail "accepted '$bad' as an IPv4 address"; fi
done
for ip in 10.0.0.5 172.31.1.1 192.168.1.1 100.64.0.1 169.254.1.1; do is_private "$ip" || fail "$ip is private"; done
for ip in 203.0.113.10 172.32.0.1 100.128.0.1 11.0.0.1; do if is_private "$ip"; then fail "$ip is not private"; fi; done
ok "IPv4 validation"

for good in 443 "2053:2096" "8080=80" 65535 1; do valid_forward "$good" || fail "rejected forward entry '$good'"; done
for bad in 0 65536 22 "20:30" "90:80" "8080=0" "8080=" abc "443 " "1-2"; do
  if valid_forward "$bad"; then fail "accepted forward entry '$bad'"; fi
done
ok "forward entry validation (port 22 and ranges over it refused)"

# Commas separate entries too: 443,1080,2087 (hand-edited configs included).
CONF_DIR_SAVED=$CONF_DIR CONF_DIR=$(mktemp -d)
printf 'FORWARD="443,1080, 2087  8080=80"\n' >"$CONF_DIR/t.conf"
[ "$(fwd_list t)" = "443 1080 2087 8080=80" ] || fail "fwd_list gave '$(fwd_list t)' for a comma-separated FORWARD"
rm -rf "$CONF_DIR"; CONF_DIR=$CONF_DIR_SAVED
ok "comma-separated FORWARD entries read as a list"

S1=203.0.113.10 S2=198.51.100.20
pair_params "$S1" "$S2" "$S1"; key1=$PAIR_KEY addr1=$PAIR_ADDR peer1=$PAIR_PEER
pair_params "$S2" "$S1" "$S1"
[ "$PAIR_KEY $PAIR_ADDR $PAIR_PEER" = "$key1 $addr1 $peer1" ] || fail "typing the IPs in the other order changed this end's settings"
pair_params "$S1" "$S2" "$S2"; key2=$PAIR_KEY addr2=$PAIR_ADDR peer2=$PAIR_PEER
[ "$key1" = "$key2" ] || fail "the two ends derive different GRE keys ($key1, $key2)"
if ! { [ "${addr1%/*}" = "$peer2" ] && [ "${addr2%/*}" = "$peer1" ]; }; then fail "overlay addresses do not pair up: $addr1/$peer1 vs $addr2/$peer2"; fi
[ "$(peer_of "$addr1")" = "$peer1" ] || fail "peer_of $addr1 gave $(peer_of "$addr1"), want $peer1"
case "$addr2" in 10.99.*/30) ;; *) fail "overlay $addr2 is not a /30 in 10.99.0.0/16" ;; esac
last=${addr2%/*}; last=${last##*.}
[ $(( last & 3 )) -eq 1 ] || fail "the lower IP ($S2) should take the first host of the /30, got $addr2"
ok "both ends derive one GRE key and one /30, in either order"

[ "$(id -u)" -eq 0 ] || { echo "skip: namespace run needs root"; exit 0; }

A="ggm-a-$$" B="ggm-b-$$"
tmp="$(mktemp -d)"
cleanup() {
  for ns in "$A" "$B"; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$ns" 2>/dev/null || true
    rm -rf "/etc/netns/$ns"
  done
  rm -rf "$tmp"
}
trap cleanup EXIT

gcc -O2 -Wall -pthread -o "$tmp/relay" relay/golden-gre-relay.c
export GOLDEN_GRE_RELAY="$tmp/relay" PATH="$PWD/scripts:$PATH"

ip netns add "$A"
ip netns add "$B"
ip link add veth-a netns "$A" type veth peer name veth-b netns "$B"
ip -n "$A" addr add 192.0.2.1/24 dev veth-a
ip -n "$B" addr add 192.0.2.2/24 dev veth-b
for ns in "$A" "$B"; do ip -n "$ns" link set lo up; done
ip -n "$A" link set veth-a up
ip -n "$B" link set veth-b up
# Many addresses on server 2: `ip addr` prints more than a pipe buffer, so a check that greps it through
# a pipe and stops early (grep -q) kills ip, and pipefail read that as "address not on this host".
for i in $(seq 1 150); do
  ip -n "$B" link add "d$i" type dummy
  ip -n "$B" addr add "10.200.$i.1/24" dev "d$i"
done

# `ip netns exec` bind-mounts /etc/netns/<ns>/golden-gre over /etc/golden-gre: one config dir per "server".
mkdir -p /etc/golden-gre "/etc/netns/$A/golden-gre" "/etc/netns/$B/golden-gre"

# The real setup dialog, answers on stdin. systemd runs units in the root namespace only, so start the
# tunnel the way the setup and the unit do: preflight, device, then the relay.
run_setup() { # namespace
  # shellcheck disable=SC2016 # expands in the inner shell
  ip netns exec "$1" bash -c '
    . ./golden-gre.sh
    start_tunnel() {
      preflight.sh "$1" >/dev/null || { preflight.sh "$1"; return 1; }
      golden-gre-up.sh "$1" >/dev/null && { golden-gre-relay.sh "$1" >/dev/null 2>&1 & }
    }
    setup_tunnel'
}

# Answers: server 1 IP, server 2 IP, disguise (Enter = the default, ICMP requests). Setup does not ask about FEC.
printf '192.0.2.1\n192.0.2.2\n\n' | run_setup "$A" >"$tmp/a.out" 2>&1 || { cat "$tmp/a.out"; fail "setup failed on server 1"; }
# Server 2 types the IPs in the other order on purpose.
printf '192.0.2.2\n192.0.2.1\n\n' | run_setup "$B" >"$tmp/b.out" 2>&1 || { cat "$tmp/b.out"; fail "setup failed on server 2"; }

confA="/etc/netns/$A/golden-gre/192.0.2.2.conf" confB="/etc/netns/$B/golden-gre/192.0.2.1.conf"
if ! { [ -r "$confA" ] && [ -r "$confB" ]; }; then fail "setup did not write the configs (want $confA and $confB)"; fi
if grep -q '^FEC=' "$confA" "$confB"; then fail "setup wrote FEC; it is off until turned on in Manage tunnels"; fi
if grep -q 'Enable FEC' "$tmp/a.out" "$tmp/b.out"; then fail "setup still asks about FEC"; fi
for c in "$confA" "$confB"; do
  if ! { grep -qx 'FACADE=icmp' "$c" && grep -qx 'ICMP_TYPE=8' "$c"; }; then fail "the default disguise did not write FACADE=icmp and ICMP_TYPE=8 to $c"; fi
done
grep -q 'disguise icmp-request' "$tmp/a.out" || { cat "$tmp/a.out"; fail "the pair check does not name the disguise icmp-request"; }
[ "$(grep '^GRE_KEY=' "$confA")" = "$(grep '^GRE_KEY=' "$confB")" ] || fail "the two configs have different GRE keys"
grep -q 'answers' "$tmp/b.out" || { cat "$tmp/b.out"; fail "setup on server 2 did not report the peer answering"; }

peerB="$(peer_of "$(sed -n 's/^TUN_ADDR=//p' "$confA")")"
ip netns exec "$A" ping -c 3 -W 2 -q "$peerB" >/dev/null || fail "no ping across the tunnel setup built"
ok "setup on both servers built a working tunnel"

# More tunnels listed after the clashing one: the check must still see the first (a check that stops
# reading early kills the writer, and under pipefail that read as "no clash").
for i in 1 2 3 4 5; do
  printf 'DEV=gre9%s\nLOCAL_PUB=192.0.2.7%s\nREMOTE_PUB=192.0.2.8%s\nTUN_ADDR=10.250.%s.1/30\nGRE_KEY=7%s\n' \
    "$i" "$i" "$i" "$i" "$i" >"/etc/netns/$A/golden-gre/zz$i.conf"
done
# Several tunnels on one public address: any number with icmp, at most one with dns (the dns relay
# owns LOCAL_PUB:53). Answers: IPs, disguise (Enter = ICMP requests, 2 = DNS, 3 = ICMP replies).
printf '192.0.2.1\n192.0.2.9\n\n' | run_setup "$A" >"$tmp/a2.out" 2>&1 || { cat "$tmp/a2.out"; fail "a second icmp tunnel on 192.0.2.1 was refused"; }
c9="/etc/netns/$A/golden-gre/192.0.2.9.conf"
if ! { grep -qx 'LOCAL_PUB=192.0.2.1' "$c9" && grep -qx 'FACADE=icmp' "$c9"; }; then fail "second icmp tunnel config is wrong: $(cat "$c9")"; fi
printf '192.0.2.1\n192.0.2.6\n3\n' | run_setup "$A" >"$tmp/a6.out" 2>&1 || { cat "$tmp/a6.out"; fail "an ICMP replies tunnel was refused"; }
c6="/etc/netns/$A/golden-gre/192.0.2.6.conf"
if ! grep -qx 'FACADE=icmp' "$c6" || grep -q '^ICMP_TYPE=8' "$c6"; then fail "disguise 3 did not write ICMP replies (FACADE=icmp, no ICMP_TYPE=8): $(cat "$c6")"; fi
[ "$(grep '^DEV=' "$c9")" != "$(grep '^DEV=' "$confA")" ] || fail "second tunnel reuses the first one's device"
ip netns exec "$A" ping -c 3 -W 2 -q "$peerB" >/dev/null || fail "adding a second icmp tunnel on the same address broke the first"
printf '192.0.2.1\n192.0.2.8\n2\n' | run_setup "$A" >"$tmp/a3.out" 2>&1 || { cat "$tmp/a3.out"; fail "a dns tunnel next to icmp ones was refused"; }
grep -qx 'FACADE=dns' "/etc/netns/$A/golden-gre/192.0.2.8.conf" || fail "the dns tunnel was not written with FACADE=dns"
if printf '192.0.2.1\n192.0.2.7\n2\n' | run_setup "$A" >"$tmp/a4.out" 2>&1; then
  fail "a second dns tunnel on the same public address was accepted"
fi
[ ! -e "/etc/netns/$A/golden-gre/192.0.2.7.conf" ] || fail "a refused setup still wrote its config"
grep -q 'already has a DNS tunnel on 192.0.2.1 (tunnel 192.0.2.8)' "$tmp/a4.out" || { cat "$tmp/a4.out"; fail "dns refusal does not say why"; }
ok "several icmp tunnels share a public address with at most one dns tunnel; the first keeps working"

# Disguise 4: none, plain GRE. The peer is not set up, so setup prints what its firewall must let in.
printf '192.0.2.1\n192.0.2.5\n4\n' | run_setup "$A" >"$tmp/a5.out" 2>&1 || { cat "$tmp/a5.out"; fail "a tunnel with no disguise was refused"; }
c5="/etc/netns/$A/golden-gre/192.0.2.5.conf"
grep -qx 'FACADE=none' "$c5" || fail "disguise 4 did not write FACADE=none: $(cat "$c5")"
grep -q 'disguise none' "$tmp/a5.out" || { cat "$tmp/a5.out"; fail "the pair check does not name the disguise none"; }
grep -q 'GRE (IP protocol 47)' "$tmp/a5.out" || { cat "$tmp/a5.out"; fail "no-disguise setup does not say the firewall must let GRE in"; }
# shellcheck disable=SC2016 # expands in the inner shell
if ip netns exec "$A" bash -c '. ./golden-gre.sh; systemctl() { return 1; }; toggle_fec 192.0.2.5' >"$tmp/fec.out" 2>&1; then
  fail "FEC was turned on for a tunnel with no relay"
fi
if grep -q '^FEC=' "$c5"; then fail "a refused FEC toggle still wrote FEC"; fi
ok "setup writes no disguise as FACADE=none; FEC, which needs the relay, is refused"

# A port forwarded by one tunnel on an address cannot be forwarded by another tunnel on it.
echo 'FORWARD="443"' >>"$c9"
# shellcheck disable=SC2016 # expands in the inner shell
ip netns exec "$A" bash -c '. ./golden-gre.sh; systemctl() { return 1; }; add_forwards 192.0.2.8' \
  <<<'443,8443' >"$tmp/f.out" 2>&1
grep -q "overlaps '443' on tunnel 192.0.2.9" "$tmp/f.out" || { cat "$tmp/f.out"; fail "a port another tunnel on the same address forwards was not refused"; }
grep -qx 'FORWARD="8443"' "/etc/netns/$A/golden-gre/192.0.2.8.conf" || { cat "$tmp/f.out"; fail "the free port was not added"; }
ok "a port forwarded by another tunnel on the same address is refused, free ones are added"

# shellcheck disable=SC2016 # expands in the inner shell
if ip netns exec "$A" bash -c '. ./golden-gre.sh; systemctl() { return 1; }; set_disguise 192.0.2.9 dns' >"$tmp/t.out" 2>&1; then
  fail "switching to dns was allowed while another dns tunnel holds the address"
fi
grep -qx 'FACADE=icmp' "$c9" || fail "a refused disguise switch still changed the config"
grep -q 'Tunnel 192.0.2.8 already uses DNS' "$tmp/t.out" || { cat "$tmp/t.out"; fail "refused switch does not say why"; }
ok "switching to dns is refused while another dns tunnel holds the address"

# --- the menu under real systemd: install, setup, FEC, delete, uninstall ------------------------------
# It installs and then uninstalls Golden GRE on this host, so it runs only when asked (the CI runner).
[ "${GOLDEN_GRE_TEST_UNINSTALL:-}" = 1 ] || { echo "skip: menu run under systemd (set GOLDEN_GRE_TEST_UNINSTALL=1; it uninstalls)"; exit 0; }
[ -z "$(tunnel_names)" ] || fail "tunnels already configured in $CONF_DIR"
U="golden-gre@192.0.2.1" CONF="$CONF_DIR/192.0.2.1.conf"
src="$(src_for 192.0.2.1)"   # an unreachable documentation peer, as in tests/systemd.sh
rm -f "$SELF"

# first run: installs, sets up a tunnel (dns disguise, no FEC), exits
printf '%s\n' y "$src" 192.0.2.1 2 0 | bash ./golden-gre.sh >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "first run failed"; }
[ -x "$SELF" ] || fail "first run did not install the golden-gre command"
systemctl is-active -q "$U" || { cat "$tmp/menu.out"; journalctl -u "$U" -n 20 --no-pager; fail "$U is not running after setup"; }
systemctl is-enabled -q "$U" || fail "$U is not enabled at boot"
ok "first run installs, sets up a tunnel, and systemd runs it"

# manage -> tunnel 1 -> FEC on -> back, back, exit
printf '%s\n' 2 1 8 0 '' 0 | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "menu failed"; }
grep -qx 'FEC=10:5' "$CONF" || { cat "$tmp/menu.out"; fail "FEC on did not reach the config"; }
systemctl is-active -q "$U" || fail "$U is not running after the FEC restart"
ok "FEC toggle writes the config and restarts the tunnel"

# manage -> tunnel 1 -> disguise -> 1 (ICMP requests) -> back, back, exit
rules() { iptables -S INPUT | grep -F "golden-gre:192.0.2.1" || true; }
echo_drop() { iptables -S OUTPUT | grep -F "golden-gre:192.0.2.1" || true; }
[[ $(rules) == *"--dport 53"* ]] || fail "no UDP 53 accept for the dns disguise before the switch"
printf '%s\n' 2 1 7 1 0 '' 0 | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "menu failed"; }
if ! { grep -qx 'FACADE=icmp' "$CONF" && grep -qx 'ICMP_TYPE=8' "$CONF"; }; then cat "$tmp/menu.out"; fail "switch to ICMP requests did not write FACADE=icmp and ICMP_TYPE=8"; fi
systemctl is-active -q "$U" || fail "$U is not running after the disguise switch"
[[ $(rules) == *"-p icmp"* ]] || fail "no ICMP accept after switching to icmp: $(rules)"
[[ $(rules) != *"--dport 53"* ]] || fail "the dns disguise's UDP 53 accept was left behind: $(rules)"
[[ $(echo_drop) == *"--icmp-type 0"* ]] || fail "ICMP requests has no drop for the kernel's echo replies: $(echo_drop)"
# -> 3 (ICMP replies): the echo-reply drop must go
printf '%s\n' 2 1 7 3 0 '' 0 | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "menu failed"; }
if ! grep -qx 'FACADE=icmp' "$CONF" || grep -q '^ICMP_TYPE=8' "$CONF"; then cat "$tmp/menu.out"; fail "switch to ICMP replies left ICMP_TYPE=8"; fi
[ -z "$(echo_drop)" ] || fail "ICMP replies left the echo-reply drop behind: $(echo_drop)"
# -> 4 (none): plain GRE, and the unit stays up with no relay to run
printf '%s\n' 2 1 7 4 0 '' 0 | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "menu failed"; }
grep -qx 'FACADE=none' "$CONF" || { cat "$tmp/menu.out"; fail "switch to no disguise did not write FACADE=none"; }
sleep 2
systemctl is-active -q "$U" || { journalctl -u "$U" -n 20 --no-pager; fail "$U is not running with no disguise"; }
[[ $(rules) == *"-p gre"* && $(rules) != *"-p icmp"* ]] || fail "wrong accept rules after switching to no disguise: $(rules)"
# -> 2 (DNS)
printf '%s\n' 2 1 7 2 0 '' 0 | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "menu failed"; }
grep -qx 'FACADE=dns' "$CONF" || fail "switching back did not write FACADE=dns"
[[ $(rules) == *"--dport 53"* && $(rules) != *"-p icmp"* ]] || fail "wrong accept rules after switching back to dns: $(rules)"
ok "disguise menu moves the tunnel between ICMP requests, ICMP replies and DNS, and swaps the firewall rules"

# manage -> tunnel 1 -> port forwarding: add, refuse 22 and an overlap, remove one, no-op remove, clear
# Both nat chains, this tunnel's tag exactly (192.0.2.1 must not match 192.0.2.10).
fwd_rules() { iptables -t nat -S | tr -d '"' | grep -c -- " --comment golden-gre-fwd:192\.0\.2\.1 " || true; }
printf '%s\n' 2 1 9 1 '8443,2053:2096' 1 22 1 2060 0 0 '' 0 | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "menu failed"; }
grep -qx 'FORWARD="8443 2053:2096"' "$CONF" || { cat "$tmp/menu.out"; fail "adding ports did not write FORWARD=\"8443 2053:2096\""; }
grep -q 'SSH' "$tmp/menu.out" || { cat "$tmp/menu.out"; fail "refusing port 22 does not say why"; }
grep -q "overlaps '2053:2096'" "$tmp/menu.out" || { cat "$tmp/menu.out"; fail "2060 inside 2053:2096 was not refused as an overlap"; }
systemctl is-active -q "$U" || fail "$U is not running after adding ports"
[ "$(fwd_rules)" = 5 ] || fail "want 5 rules (2 entries x tcp/udp DNAT + 1 MASQUERADE), got $(fwd_rules)"
printf '%s\n' 2 1 9 2 8443 2 9999 0 0 '' 0 | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "menu failed"; }
grep -qx 'FORWARD="2053:2096"' "$CONF" || { cat "$tmp/menu.out"; fail "removing 8443 did not leave FORWARD=\"2053:2096\""; }
grep -q 'Nothing matched' "$tmp/menu.out" || { cat "$tmp/menu.out"; fail "removing an unlisted port did not say nothing matched"; }
[ "$(grep -c 'Restarted' "$tmp/menu.out")" = 1 ] || { cat "$tmp/menu.out"; fail "want exactly one restart (the real removal), not one for the no-op"; }
[ "$(fwd_rules)" = 3 ] || fail "want 3 rules after removing one entry, got $(fwd_rules)"
printf '%s\n' 2 1 9 3 y 0 0 '' 0 | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "menu failed"; }
if grep -q '^FORWARD=' "$CONF"; then fail "remove all left a FORWARD line"; fi
[ "$(fwd_rules)" = 0 ] || fail "remove all left $(fwd_rules) forwarding rules"
ok "port forwarding menu adds, refuses 22 and overlaps, removes (no restart when nothing matched) and clears; the rules follow"

# manage -> tunnel 1 -> delete, confirm -> exit
printf '%s\n' 2 1 11 y 0 | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "menu failed"; }
[ ! -e "$CONF" ] || fail "delete left $CONF"
if systemctl is-active -q "$U" || systemctl is-enabled -q "$U" 2>/dev/null; then fail "delete left $U running or enabled"; fi
ok "delete stops, disables and removes the tunnel"

# uninstall, confirm, delete settings
printf '%s\n' 5 y y | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "uninstall failed"; }
for f in "$SELF" "$SBIN/golden-gre-relay" "$SBIN/golden-gre-up.sh" /etc/systemd/system/golden-gre@.service /etc/sysctl.d/99-golden-gre.conf "$CONF_DIR"; do
  [ ! -e "$f" ] || fail "uninstall left $f"
done
ok "uninstall removes everything install put on the host"
