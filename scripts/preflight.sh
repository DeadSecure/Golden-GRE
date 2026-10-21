#!/usr/bin/env bash
# Golden GRE preflight — check a host (and optionally a tunnel config) is ready.
# Usage: preflight.sh [instance]
set -uo pipefail

g(){ printf '  \033[32m✓\033[0m %s\n' "$1"; }
b(){ printf '  \033[31m✗\033[0m %s\n' "$1"; FAIL=1; }
w(){ printf '  \033[33m!\033[0m %s\n' "$1"; }
FAIL=0

echo "== kernel modules =="
for m in fou ip_gre; do
  if modprobe "$m" 2>/dev/null; then g "$m loadable"; else b "$m not loadable"; fi
done

echo "== tools =="
for t in ip iptables; do
  if command -v "$t" >/dev/null 2>&1; then g "$t present"; else b "$t missing"; fi
done
if command -v ethtool >/dev/null 2>&1; then g "ethtool present"; else w "ethtool missing (turns off GSO on the tunnel device; install it)"; fi
RELAY="${GOLDEN_GRE_RELAY:-/usr/local/sbin/golden-gre-relay}"
if [ -x "$RELAY" ]; then g "relay binary $RELAY"; else b "relay binary $RELAY missing (run install.sh; it needs gcc)"; fi

echo "== sysctl =="
cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')"
if [ "$cc" = bbr ]; then g "tcp_congestion_control = bbr"; else w "tcp_congestion_control = $cc (run install.sh for bbr)"; fi
fwd="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"
if [ "$fwd" = 1 ]; then g "ip_forward = 1"; else w "ip_forward = $fwd (needed only when routing through the tunnel)"; fi

NAME="${1:-}"
if [ -n "$NAME" ]; then
  CONF="/etc/golden-gre/${NAME}.conf"
  echo "== config: $CONF =="
  if [ -r "$CONF" ]; then
    # shellcheck source=/dev/null
    . "$CONF"
    for v in DEV LOCAL_PUB REMOTE_PUB TUN_ADDR; do
      if [ -n "${!v:-}" ]; then g "$v=${!v}"; else b "$v not set"; fi
    done
    case "${LOCAL_PUB:-}${REMOTE_PUB:-}" in *:*) b "LOCAL_PUB and REMOTE_PUB must be IPv4 addresses" ;; esac
    if [ -n "${LOCAL_PUB:-}" ]; then
      # Not a pipe: grep -q would kill a long `ip` listing and pipefail would read "not here" (see golden-gre-up.sh).
      if grep -qw "${LOCAL_PUB}" < <(ip -4 -o addr show); then g "${LOCAL_PUB} is configured on this host"; else b "${LOCAL_PUB} is not an address of this host (the relay binds it)"; fi
    fi
    FACADE="${FACADE:-dns}"
    case "$FACADE" in
      dns)
        read -ra ports <<<"${DNS_PORTS:-${DNS_PORT:-53}}"; read -ra ports <<<"${ports[*]//,/ }"
        for port in "${ports[@]}"; do
          if [ -n "$(ss -Hlun "sport = :${port}" "src ${LOCAL_PUB:-0.0.0.0}" 2>/dev/null)" ]; then
            b "UDP ${LOCAL_PUB:-*}:${port} is already in use (another relay or a DNS server); use a different LOCAL_PUB or DNS_PORT(S)"
          else
            g "UDP ${LOCAL_PUB:-*}:${port} is free for the relay"
          fi
        done
        w "verify the path end-to-end with: tcpdump -ni any udp port ${ports[0]}  (run on the peer while this side sends)"
        ;;
      icmp)
        case "${ICMP_TYPE:-0}" in 0 | 8) ;; *) b "ICMP_TYPE must be 0 (echo reply) or 8 (echo request)" ;; esac
        w "verify the path end-to-end with: tcpdump -ni any icmp  (run on the peer while this side sends)" ;;
      none) w "verify the path end-to-end with: tcpdump -ni any proto gre  (run on the peer while this side sends)" ;;
      *) b "FACADE must be dns, icmp or none" ;;
    esac
    if [ -n "${KEYFILE:-}" ]; then
      if [ ! -r "$KEYFILE" ]; then b "KEYFILE $KEYFILE is not readable (needs the same 32-byte key as the peer)"
      elif [ "$(wc -c <"$KEYFILE")" -ne 32 ]; then b "KEYFILE $KEYFILE must be exactly 32 bytes"
      else g "KEYFILE present (payload encryption on); the peer must hold the same key"; fi
    fi
  else
    b "config not found — create it from examples/"
  fi
fi

echo
if [ "$FAIL" = 0 ]; then echo "preflight: OK"; else echo "preflight: problems found"; exit 1; fi
