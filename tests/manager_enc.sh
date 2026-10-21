#!/usr/bin/env bash
# Unit test for the manager's encryption helpers (derive_key_file, toggle_enc, enc_status), driven by
# sourcing golden-gre.sh with a throwaway CONF_DIR so no systemd or network state is touched.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
# Build our own relay and point the manager at it (derive_key_file honours GOLDEN_GRE_RELAY), so this
# test never depends on or overwrites an installed binary.
gcc -O2 -Wall -pthread -o "$tmp/relay" relay/golden-gre-relay.c relay/monocypher.c
export GOLDEN_GRE_RELAY="$tmp/relay"
export CONF_DIR="$tmp/conf"; mkdir -p "$CONF_DIR"
fail(){ echo "FAIL: $*" >&2; exit 1; }

# Source only the functions (golden-gre.sh runs main only when executed directly, not when sourced).
# shellcheck source=/dev/null
source ./golden-gre.sh

# a conf like setup writes, icmp disguise, no key yet
cat >"$CONF_DIR/peerA.conf" <<EOF
DEV=gt9
LOCAL_PUB=203.0.113.1
REMOTE_PUB=198.51.100.2
TUN_ADDR=10.99.103.1/30
GRE_KEY=43
FACADE=icmp
ICMP_TYPE=0
EOF

[ "$(enc_status peerA)" = off ] || fail "enc_status should be off before keying"

# derive_key_file reads the passphrase on fd 0 via ask_secret; feed it twice (passphrase + confirm).
printf 'swordfish\nswordfish\n' | derive_key_file peerA 203.0.113.1 198.51.100.2 >/dev/null 2>&1 \
  || fail "derive_key_file failed"
[ "$(wc -c <"$CONF_DIR/peerA.key")" = 32 ] || fail "key is not 32 bytes"

# same passphrase + swapped IP order must reproduce the identical key (both-ends property)
printf 'swordfish\nswordfish\n' | derive_key_file peerB 198.51.100.2 203.0.113.1 >/dev/null 2>&1 \
  || fail "second derive failed"
cmp -s "$CONF_DIR/peerA.key" "$CONF_DIR/peerB.key" || fail "same passphrase+pair gave different keys"

# a different passphrase must give a different key
printf 'other\nother\n' | derive_key_file peerC 203.0.113.1 198.51.100.2 >/dev/null 2>&1 || fail "third derive failed"
cmp -s "$CONF_DIR/peerA.key" "$CONF_DIR/peerC.key" && fail "different passphrase gave the same key"

echo "ok: derive_key_file is deterministic, order-independent and passphrase-sensitive"

# toggle_enc off removes the line and the key file (stub systemctl: nothing is running here)
systemctl() { return 1; }
echo "KEYFILE=$CONF_DIR/peerA.key" >>"$CONF_DIR/peerA.conf"
[ "$(enc_status peerA)" = on ] || fail "enc_status should be on with KEYFILE set"
toggle_enc peerA >/dev/null 2>&1 || true
grep -q '^KEYFILE=' "$CONF_DIR/peerA.conf" && fail "toggle_enc did not remove KEYFILE"
[ -e "$CONF_DIR/peerA.key" ] && fail "toggle_enc did not remove the key file"
echo "ok: toggle_enc off clears the KEYFILE line and the key file"

echo "manager_enc: PASS"
