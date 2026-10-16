#!/usr/bin/env bash
# Golden GRE — bring up one tunnel from /etc/golden-gre/<instance>.conf.
#
# The tunnel is GRE-in-FOU on loopback. golden-gre-relay (started by golden-gre-relay.sh, or by the
# systemd unit) carries its packets between the two servers inside a DNS-shaped UDP/53 disguise (or
# ICMP), because a filtered IPv4 path cuts every ordinary tunnel flow after a few packets. This script
# builds the device and the firewall state; it does not run the relay.
# Usage: golden-gre-up.sh <instance>
set -euo pipefail

NAME="${1:?usage: golden-gre-up.sh <instance>}"
CONF="/etc/golden-gre/${NAME}.conf"
[ -r "$CONF" ] || { echo "golden-gre: missing config $CONF" >&2; exit 1; }
# shellcheck source=/dev/null
. "$CONF"

: "${DEV:?DEV not set in $CONF}"
: "${LOCAL_PUB:?LOCAL_PUB not set in $CONF}"
: "${REMOTE_PUB:?REMOTE_PUB not set in $CONF}"
: "${TUN_ADDR:?TUN_ADDR not set in $CONF}"
MTU="${MTU:-1380}"
FACADE="${FACADE:-dns}"
DNS_PORT="${DNS_PORT:-53}"
RELAY_PORT="${RELAY_PORT:-5601}"
FOU_PORT="${FOU_PORT:-5599}"
GRE_KEY="${GRE_KEY:-41}"

case "${LOCAL_PUB}${REMOTE_PUB}" in
  *:*) echo "golden-gre: LOCAL_PUB and REMOTE_PUB must be IPv4 addresses ($CONF)" >&2; exit 1 ;;
esac
case "${FACADE}" in
  dns | icmp) ;;
  *) echo "golden-gre: FACADE must be dns or icmp ($CONF)" >&2; exit 1 ;;
esac
ICMP_TYPE="${ICMP_TYPE:-0}"
case "${ICMP_TYPE}" in
  0 | 8) ;;
  *) echo "golden-gre: ICMP_TYPE must be 0 (echo reply) or 8 (echo request) ($CONF)" >&2; exit 1 ;;
esac
# icmp tunnels between the same two addresses must agree on ICMP_TYPE: a type-8 tunnel drops every echo
# reply to the peer, which is all a type-0 tunnel sends.
if [ "${FACADE}" = icmp ]; then
  me="${LOCAL_PUB} ${REMOTE_PUB}"
  for f in "$(dirname "$CONF")"/*.conf; do
    [ -r "$f" ] && [ "$f" != "$CONF" ] || continue
    # shellcheck source=/dev/null
    other=$(unset FACADE LOCAL_PUB REMOTE_PUB ICMP_TYPE; . "$f" >/dev/null 2>&1
      [ "${FACADE:-dns} ${LOCAL_PUB:-} ${REMOTE_PUB:-}" = "icmp $me" ] && echo "${ICMP_TYPE:-0}") || true
    if [ -n "$other" ] && [ "$other" != "${ICMP_TYPE}" ]; then
      echo "golden-gre: tunnel $(basename "$f" .conf) uses ICMP_TYPE=$other between the same addresses; set the same ICMP_TYPE on both ($CONF)" >&2
      exit 1
    fi
  done
fi

# Port forwarding: FORWARD="443 2053:2096 8080=80" sends this host's public ports (TCP and UDP) through the
# tunnel to the peer's overlay address: P to port P, A:B to the same ports, P=Q to port Q. Checked here,
# before anything is touched, so a bad entry never takes down a live tunnel.
FWD_PORTS=() FWD_DEST=()
if [ -n "${FORWARD:-}" ]; then
  fwd_bad() { echo "golden-gre: FORWARD entry '$1' $2 ($CONF)" >&2; exit 1; }
  if [ -n "${PEER_ADDR:-}" ]; then
    [[ $PEER_ADDR =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "golden-gre: PEER_ADDR must be an IPv4 address ($CONF)" >&2; exit 1; }
    fwd_peer=$PEER_ADDR
  else
    ip4="${TUN_ADDR%/*}" last="${TUN_ADDR%/*}"; last="${last##*.}"
    case "${TUN_ADDR#*/}" in
      30) fwd_peer="${ip4%.*}.$(( (last & ~3) + 3 - (last & 3) ))" ;;
      31) fwd_peer="${ip4%.*}.$(( last ^ 1 ))" ;;
      *) echo "golden-gre: set PEER_ADDR in $CONF to use FORWARD (TUN_ADDR is not a /30 or /31)" >&2; exit 1 ;;
    esac
  fi
  read -ra _fwd <<<"${FORWARD//,/ }"   # commas or spaces separate entries
  for e in ${_fwd[@]+"${_fwd[@]}"}; do
    if [[ $e =~ ^([0-9]{1,5})(:([0-9]{1,5}))?$ ]]; then
      lo=$(( 10#${BASH_REMATCH[1]} )) hi=$(( 10#${BASH_REMATCH[3]:-${BASH_REMATCH[1]}} )) to=''
    elif [[ $e =~ ^([0-9]{1,5})=([0-9]{1,5})$ ]]; then
      lo=$(( 10#${BASH_REMATCH[1]} )) hi=$lo to=$(( 10#${BASH_REMATCH[2]} ))
    else
      fwd_bad "$e" "is not PORT, FIRST:LAST or PORT=PEER_PORT"
    fi
    for p in "$lo" "$hi" ${to:+"$to"}; do (( p >= 1 && p <= 65535 )) || fwd_bad "$e" "has a port outside 1-65535"; done
    (( lo <= hi )) || fwd_bad "$e" "is a range that ends before it starts"
    (( lo > 22 || hi < 22 )) || fwd_bad "$e" "includes port 22: forwarding SSH would lock you out of this server"
    if [ "$lo" = "$hi" ]; then FWD_PORTS+=("$lo"); else FWD_PORTS+=("$lo:$hi"); fi
    FWD_DEST+=("${fwd_peer}${to:+:$to}")
  done
fi

# The relay binds LOCAL_PUB and needs a route to the peer. At early boot either may be missing:
# fail before touching anything and let systemd's Restart= retry.
# grep reads through < <(...), not a pipe: grep -q stops at the first match, and on a host whose address
# list is longer than a pipe buffer that kills ip, which pipefail would read as "not configured".
grep -qw "${LOCAL_PUB}" < <(ip -4 -o addr show 2>/dev/null) \
  || { echo "golden-gre: ${LOCAL_PUB} is not configured on this host yet" >&2; exit 1; }
ip route get "${REMOTE_PUB}" >/dev/null 2>&1 \
  || { echo "golden-gre: no route to ${REMOTE_PUB} yet" >&2; exit 1; }

# A listener that already exists on a fresh bringup (no device yet) belongs to another tunnel on this
# host: sharing it would let this tunnel's rollback or teardown remove the other one's listener. A
# stale one from a crashed run is removed by the unit's ExecStopPost; by hand, run golden-gre-down.sh.
if ! ip link show "${DEV}" >/dev/null 2>&1 && grep -q "port ${FOU_PORT} " < <(ip fou show 2>/dev/null); then
  echo "golden-gre: FOU port ${FOU_PORT} is already in use; give each tunnel on this host its own FOU_PORT ($CONF)" >&2
  exit 1
fi

# On a fresh bringup, roll back on any failure: systemd never runs ExecStop for a
# start that failed, so a half-built tunnel (listener, rules, device) would stay
# behind. Only when the device does not exist yet: a failing re-run by hand on a
# live tunnel must not tear it down while systemd still reports it active.
rollback() {
  local rc=$?
  [ "$rc" -eq 0 ] && return
  echo "golden-gre: ${NAME} bringup failed (exit ${rc}), rolling back" >&2
  "$(dirname "$0")/golden-gre-down.sh" "${NAME}" >/dev/null 2>&1
}
if ! ip link show "${DEV}" >/dev/null 2>&1; then
  trap rollback EXIT
  # A stop during bringup (SIGTERM from systemd) must roll back too, but the EXIT
  # trap would see $? of the last finished command, usually 0. Exit non-zero.
  trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM
fi

# fou has no module alias, so `ip fou add` cannot autoload it. ip_gre does
# autoload (rtnl-link-gre) at `ip link add type gre`.
modprobe fou

# FOU decapsulation listener, loopback only: the relay hands the peer's packets to it (idempotent)
grep -q "port ${FOU_PORT} " < <(ip fou show 2>/dev/null) \
  || ip fou add port "${FOU_PORT}" ipproto 47 local 127.0.0.1

# The relay's wire traffic takes packets from the peer only. Deleted and re-inserted so the rule sits
# at the top of INPUT and opens the port on hosts whose INPUT policy is DROP (ufw). No DROP rule for
# other sources: a local resolver may share the DNS port. The rule carries the instance name, so
# tunnels sharing a peer each own (and later remove) their own.
if [ "${FACADE}" = dns ]; then
  WIRE=(-p udp --dport "${DNS_PORT}")
else
  WIRE=(-p icmp)
fi
drop_tagged() { # this tunnel's INPUT/OUTPUT rules, found by their tag, so a changed address leaves none behind
  local rule args
  while read -r rule; do
    rule=${rule//\"/}   # iptables -S quotes the comment; the tag has no spaces
    [[ " $rule " == *" --comment golden-gre:${NAME} "* ]] || continue
    read -ra args <<<"${rule/#-A /-D }"
    iptables "${args[@]}" 2>/dev/null || true
  done < <(iptables -S 2>/dev/null)
}
drop_tagged
iptables -I INPUT "${WIRE[@]}" -s "${REMOTE_PUB}" -m comment --comment "golden-gre:${NAME}" -j ACCEPT
# With echo requests on the wire (ICMP_TYPE=8) the kernel would answer each one with an echo reply,
# doubling the traffic to the peer. The relay then sends only requests, so drop every echo reply to the peer.
if [ "${FACADE}" = icmp ] && [ "${ICMP_TYPE}" = 8 ]; then
  iptables -I OUTPUT -s "${LOCAL_PUB}" -d "${REMOTE_PUB}" -p icmp --icmp-type 0 -m comment --comment "golden-gre:${NAME}" -j DROP
fi

# (re)create the tunnel device (idempotent). Both ends must use the same GRE_KEY; tunnels on one host
# need different keys, FOU_PORT, RELAY_PORT and LOCAL_PUB.
ip link del "${DEV}" 2>/dev/null || true
ip link add "${DEV}" type gre local 127.0.0.1 remote 127.0.0.1 ttl 255 key "${GRE_KEY}" \
  encap fou encap-sport "${FOU_PORT}" encap-dport "${RELAY_PORT}"
ip addr add "${TUN_ADDR}" dev "${DEV}"
ip link set "${DEV}" mtu "${MTU}" up

# One packet per datagram. With GSO the kernel would hand the relay datagrams of up to 64 KB, and the
# loopback path does not segment them.
ethtool -K "${DEV}" tso off gso off gro off >/dev/null 2>&1 || true

# Accept forwarded traffic in/out of the tunnel. Deleted and re-inserted so it is
# always at the top, ahead of any DROP that Docker/ufw added since the last run.
# TCP MSS clamp on the forward path (both directions) — prevents PMTUD black holes
for DIR in "-o" "-i"; do
  iptables -D FORWARD "${DIR}" "${DEV}" -j ACCEPT 2>/dev/null || true
  iptables -I FORWARD "${DIR}" "${DEV}" -j ACCEPT
  iptables -t mangle -C FORWARD "${DIR}" "${DEV}" -p tcp --tcp-flags SYN,RST SYN \
      -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
    || iptables -t mangle -A FORWARD "${DIR}" "${DEV}" -p tcp --tcp-flags SYN,RST SYN \
      -j TCPMSS --clamp-mss-to-pmtu
done

# Optional static routes through the tunnel (space-separated CIDRs)
if [ -n "${ROUTES:-}" ]; then
  read -ra _routes <<<"${ROUTES}"
  for net in "${_routes[@]}"; do
    ip route replace "${net}" dev "${DEV}"
  done
fi

# Optional MASQUERADE for traffic exiting via this node. Without NAT_OUT, match
# anything leaving by an interface other than the tunnel (no NIC-name guessing).
if [ -n "${NAT_SRC:-}" ]; then
  if [ -n "${NAT_OUT:-}" ]; then OUT=(-o "${NAT_OUT}"); else OUT=(! -o "${DEV}"); fi
  iptables -t nat -C POSTROUTING -s "${NAT_SRC}" "${OUT[@]}" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "${NAT_SRC}" "${OUT[@]}" -j MASQUERADE
fi

# Port forwarding (FORWARD, checked above). This tunnel's old rules go first, so a changed FORWARD leaves
# nothing behind. Traffic from the peer's own address is never forwarded: that is the relay's own traffic,
# and the peer's SSH. MASQUERADE makes the peer answer through the tunnel instead of its own default route.
while read -r rule; do
  rule=${rule//\"/}   # iptables -S quotes the comment; the tag has no spaces
  [[ " $rule " == *" --comment golden-gre-fwd:${NAME} "* ]] || continue
  read -ra args <<<"${rule/#-A /-D }"
  iptables -t nat "${args[@]}"
done < <(iptables -t nat -S)
if [ "${#FWD_PORTS[@]}" -gt 0 ]; then
  sysctl -qw net.ipv4.ip_forward=1
  for i in "${!FWD_PORTS[@]}"; do
    for proto in tcp udp; do
      iptables -t nat -A PREROUTING -d "${LOCAL_PUB}" ! -s "${REMOTE_PUB}" -p "$proto" --dport "${FWD_PORTS[i]}" \
        -m comment --comment "golden-gre-fwd:${NAME}" -j DNAT --to-destination "${FWD_DEST[i]}"
    done
  done
  # Inserted, not appended: an earlier catch-all SNAT/ACCEPT in POSTROUTING would otherwise win, and the
  # peer would answer by its own default route. The match is narrow enough to go first.
  iptables -t nat -I POSTROUTING -o "${DEV}" -m conntrack --ctstate DNAT \
    -m comment --comment "golden-gre-fwd:${NAME}" -j MASQUERADE
fi

echo "golden-gre: ${DEV} up — ${TUN_ADDR} -> ${REMOTE_PUB} (relay ${FACADE}, mtu ${MTU}); run the relay: golden-gre-relay.sh ${NAME}"
