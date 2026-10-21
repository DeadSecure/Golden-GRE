#!/usr/bin/env bash
# Golden GRE — run the relay for one tunnel, in the foreground (it is the systemd unit's main process).
# Without systemd: golden-gre-up.sh <instance>, then this script in the background.
# Usage: golden-gre-relay.sh <instance>
set -euo pipefail

NAME="${1:?usage: golden-gre-relay.sh <instance>}"
CONF="/etc/golden-gre/${NAME}.conf"
[ -r "$CONF" ] || { echo "golden-gre: missing config $CONF" >&2; exit 1; }
# shellcheck source=/dev/null
. "$CONF"
: "${LOCAL_PUB:?LOCAL_PUB not set in $CONF}"
: "${REMOTE_PUB:?REMOTE_PUB not set in $CONF}"

# FACADE=none: plain GRE between the public addresses, nothing to relay. Stay in the foreground anyway:
# this is the unit's main process, and Restart=always would rebuild the tunnel every time it exits.
[ "${FACADE:-dns}" != none ] || exec sleep infinity

RELAY="${GOLDEN_GRE_RELAY:-/usr/local/sbin/golden-gre-relay}"
[ -x "$RELAY" ] || { echo "golden-gre: relay binary $RELAY not found (run install.sh)" >&2; exit 1; }

# FEC=K:M adds M parity packets per K on what this end sends; the peer decodes without any setting.
# ICMP_TYPE (icmp only): 0 sends echo replies, 8 echo requests; both ends must use the same.
# SPORT_ROTATE (dns only): reopen the sending socket every N frames, so each source port carries at
# most N; a fresh source port is a fresh flow on paths that allow only the first few packets per flow.
# The icmp facade shares one raw socket for both directions and has no source port: rotation is off there.
# RATE (dns only): cap on frames per second the relay puts on the wire; keeps sustained churn under
# what the path accepts instead of getting clamped. Unset = no cap.
# KEYFILE: path to a 32-byte pre-shared key. Set (to the same key) on both ends to encrypt the payload
# with XChaCha20-Poly1305 and randomize the facade markers; unset = plaintext, fixed markers (legacy).
[ "${FACADE:-dns}" = dns ] || SPORT_ROTATE=
exec "$RELAY" --facade "${FACADE:-dns}" --bind "${LOCAL_PUB}" --peer "${REMOTE_PUB}" \
  --local "127.0.0.1:${RELAY_PORT:-5601}" --reply "127.0.0.1:${FOU_PORT:-5599}" --port "${DNS_PORTS:-${DNS_PORT:-53}}" \
  --itype "${ICMP_TYPE:-0}" ${FEC:+--fec "$FEC"} ${SPORT_ROTATE:+--rotate "$SPORT_ROTATE"} ${RATE:+--rate "$RATE"} \
  ${KEYFILE:+--keyfile "$KEYFILE"}
