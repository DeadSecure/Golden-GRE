#!/usr/bin/env bash
# Golden GRE — tear down one tunnel: device, loopback FOU listener and firewall state.
# It does not stop the relay (systemd stops it as the unit's main process).
# Usage: golden-gre-down.sh <instance>
set -uo pipefail

NAME="${1:?usage: golden-gre-down.sh <instance>}"
CONF="/etc/golden-gre/${NAME}.conf"
# shellcheck source=/dev/null
[ -r "$CONF" ] && . "$CONF"

if [ -n "${DEV:-}" ]; then
  for DIR in "-o" "-i"; do
    iptables -D FORWARD "${DIR}" "${DEV}" -j ACCEPT 2>/dev/null || true
    iptables -t mangle -D FORWARD "${DIR}" "${DEV}" -p tcp --tcp-flags SYN,RST SYN \
      -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  done
  if [ -n "${NAT_SRC:-}" ]; then
    if [ -n "${NAT_OUT:-}" ]; then OUT=(-o "${NAT_OUT}"); else OUT=(! -o "${DEV}"); fi
    iptables -t nat -D POSTROUTING -s "${NAT_SRC}" "${OUT[@]}" -j MASQUERADE 2>/dev/null || true
  fi
  ip link del "${DEV}" 2>/dev/null || true
fi

# The loopback FOU listener (each tunnel on a host uses its own port) and this tunnel's INPUT accept
# and ICMP_TYPE=8 echo-reply drop, by tag: they go even when the disguise or addresses changed since up.
FOU_PORT="${FOU_PORT:-5599}"
ip fou del port "${FOU_PORT}" local 127.0.0.1 2>/dev/null || ip fou del port "${FOU_PORT}" 2>/dev/null || true
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

# Port forwarding rules, found by their tag, so they go even when FORWARD changed since up.
while read -r rule; do
  rule=${rule//\"/}   # iptables -S quotes the comment; the tag has no spaces
  [[ " $rule " == *" --comment golden-gre-fwd:${NAME} "* ]] || continue
  read -ra args <<<"${rule/#-A /-D }"
  iptables -t nat "${args[@]}" 2>/dev/null || true
done < <(iptables -t nat -S 2>/dev/null)

echo "golden-gre: ${NAME} down"
exit 0
