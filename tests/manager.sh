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

# Answers: server 1 IP, server 2 IP, disguise (Enter = the default, icmp), FEC.
printf '192.0.2.1\n192.0.2.2\n\ny\n' | run_setup "$A" >"$tmp/a.out" 2>&1 || { cat "$tmp/a.out"; fail "setup failed on server 1"; }
# Server 2 types the IPs in the other order on purpose.
printf '192.0.2.2\n192.0.2.1\n\nn\n' | run_setup "$B" >"$tmp/b.out" 2>&1 || { cat "$tmp/b.out"; fail "setup failed on server 2"; }

confA="/etc/netns/$A/golden-gre/192.0.2.2.conf" confB="/etc/netns/$B/golden-gre/192.0.2.1.conf"
if ! { [ -r "$confA" ] && [ -r "$confB" ]; }; then fail "setup did not write the configs (want $confA and $confB)"; fi
grep -qx 'FEC=10:5' "$confA" || fail "FEC=yes on server 1 did not write FEC=10:5"
if grep -q '^FEC=' "$confB"; then fail "FEC=no on server 2 still wrote FEC"; fi
for c in "$confA" "$confB"; do grep -qx 'FACADE=icmp' "$c" || fail "the default disguise did not write FACADE=icmp to $c"; done
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
if printf '192.0.2.1\n192.0.2.9\nn\n' | run_setup "$A" >"$tmp/a2.out" 2>&1; then
  fail "a second tunnel on the same public address was accepted"
fi
[ ! -e "/etc/netns/$A/golden-gre/192.0.2.9.conf" ] || fail "a refused setup still wrote its config"
grep -q 'already has a tunnel on 192.0.2.1' "$tmp/a2.out" || { cat "$tmp/a2.out"; fail "refusal does not say why"; }
ok "a second tunnel on the same public address is refused"

# --- the menu under real systemd: install, setup, FEC, delete, uninstall ------------------------------
# It installs and then uninstalls Golden GRE on this host, so it runs only when asked (the CI runner).
[ "${GOLDEN_GRE_TEST_UNINSTALL:-}" = 1 ] || { echo "skip: menu run under systemd (set GOLDEN_GRE_TEST_UNINSTALL=1; it uninstalls)"; exit 0; }
[ -z "$(tunnel_names)" ] || fail "tunnels already configured in $CONF_DIR"
U="golden-gre@192.0.2.1" CONF="$CONF_DIR/192.0.2.1.conf"
src="$(src_for 192.0.2.1)"   # an unreachable documentation peer, as in tests/systemd.sh
rm -f "$SELF"

# first run: installs, sets up a tunnel (dns disguise, no FEC), exits
printf '%s\n' y "$src" 192.0.2.1 2 n 0 | bash ./golden-gre.sh >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "first run failed"; }
[ -x "$SELF" ] || fail "first run did not install the golden-gre command"
systemctl is-active -q "$U" || { cat "$tmp/menu.out"; journalctl -u "$U" -n 20 --no-pager; fail "$U is not running after setup"; }
systemctl is-enabled -q "$U" || fail "$U is not enabled at boot"
ok "first run installs, sets up a tunnel, and systemd runs it"

# manage -> tunnel 1 -> FEC on -> back, back, exit
printf '%s\n' 2 1 8 0 '' 0 | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "menu failed"; }
grep -qx 'FEC=10:5' "$CONF" || { cat "$tmp/menu.out"; fail "FEC on did not reach the config"; }
systemctl is-active -q "$U" || fail "$U is not running after the FEC restart"
ok "FEC toggle writes the config and restarts the tunnel"

# manage -> tunnel 1 -> disguise (dns -> icmp) -> back, back, exit
rules() { iptables -S INPUT | grep -F "golden-gre:192.0.2.1" || true; }
[[ $(rules) == *"--dport 53"* ]] || fail "no UDP 53 accept for the dns disguise before the switch"
printf '%s\n' 2 1 7 0 '' 0 | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "menu failed"; }
grep -qx 'FACADE=icmp' "$CONF" || { cat "$tmp/menu.out"; fail "disguise switch did not write FACADE=icmp"; }
systemctl is-active -q "$U" || fail "$U is not running after the disguise switch"
[[ $(rules) == *"-p icmp"* ]] || fail "no ICMP accept after switching to icmp: $(rules)"
[[ $(rules) != *"--dport 53"* ]] || fail "the dns disguise's UDP 53 accept was left behind: $(rules)"
# and back to dns
printf '%s\n' 2 1 7 0 '' 0 | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "menu failed"; }
grep -qx 'FACADE=dns' "$CONF" || fail "switching back did not write FACADE=dns"
[[ $(rules) == *"--dport 53"* && $(rules) != *"-p icmp"* ]] || fail "wrong accept rules after switching back to dns: $(rules)"
ok "disguise switch moves the tunnel between dns and icmp and swaps the firewall rule"

# manage -> tunnel 1 -> port forwarding: add, refuse 22, remove one, clear
fwd_rules() { iptables -t nat -S PREROUTING | grep -cF -- "golden-gre-fwd:192.0.2.1" || true; }
printf '%s\n' 2 1 9 1 '8443 2053:2096' 1 22 0 0 '' 0 | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "menu failed"; }
grep -qx 'FORWARD="8443 2053:2096"' "$CONF" || { cat "$tmp/menu.out"; fail "adding ports did not write FORWARD=\"8443 2053:2096\""; }
grep -q 'SSH' "$tmp/menu.out" || { cat "$tmp/menu.out"; fail "refusing port 22 does not say why"; }
systemctl is-active -q "$U" || fail "$U is not running after adding ports"
[ "$(fwd_rules)" = 4 ] || fail "want 4 DNAT rules (2 entries x tcp/udp), got $(fwd_rules)"
printf '%s\n' 2 1 9 2 8443 0 0 '' 0 | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "menu failed"; }
grep -qx 'FORWARD="2053:2096"' "$CONF" || { cat "$tmp/menu.out"; fail "removing 8443 did not leave FORWARD=\"2053:2096\""; }
[ "$(fwd_rules)" = 2 ] || fail "want 2 DNAT rules after removing one entry, got $(fwd_rules)"
printf '%s\n' 2 1 9 3 0 0 '' 0 | "$SELF" >"$tmp/menu.out" 2>&1 || { cat "$tmp/menu.out"; fail "menu failed"; }
if grep -q '^FORWARD=' "$CONF"; then fail "remove all left a FORWARD line"; fi
[ "$(fwd_rules)" = 0 ] || fail "remove all left $(fwd_rules) DNAT rules"
ok "port forwarding menu adds, refuses 22, removes and clears ports, and the rules follow"

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
