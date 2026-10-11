#!/usr/bin/env bash
# Loopback test of the relay: two relays on 127.0.0.2/127.0.0.3 and two stand-in tunnel endpoints.
# Checks both directions, bulk delivery and sizes, and (dns) that frames from a non-peer address are
# ignored. The icmp facade needs root (raw socket) and is skipped otherwise. Builds the relay itself.
# Ports are per run and checked free first: on a host that already runs a tunnel (whose relay holds
# 127.0.0.1:5601 by default) fixed ports would send this test's datagrams into the live relay.
# To be safe on such a host, run it in its own network namespace: unshare -n sh -c 'ip link set lo up; tests/relay.sh'
set -euo pipefail

cd "$(dirname "$0")/.."
fail(){ echo "FAIL: $*" >&2; exit 1; }
ok(){ echo "ok: $*"; }

base=$(( 20000 + $$ % 20000 ))
RELAY_A=$base RELAY_B=$(( base + 1 )) END_A=$(( base + 2 )) END_B=$(( base + 3 )) DNSP=$(( base + 4 ))
for p in "$RELAY_A" "$RELAY_B" "$END_A" "$END_B" "$DNSP"; do
  [ -z "$(ss -Hlun "sport = :${p}")" ] || fail "UDP port $p is already in use"
done

tmp="$(mktemp -d)"
pids=()
nets=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  for n in "${nets[@]}"; do ip netns del "$n" 2>/dev/null || true; done
  rm -rf "$tmp"
}
trap cleanup EXIT

gcc -O2 -Wall -Wextra -Werror -pthread -o "$tmp/relay" relay/golden-gre-relay.c
ok "relay builds without warnings"

run_facade() {
  local facade="$1"
  "$tmp/relay" --facade "$facade" --bind 127.0.0.2 --peer 127.0.0.3 --local "127.0.0.1:$RELAY_A" --port "$DNSP" >"$tmp/a.log" 2>&1 &
  pids+=("$!")
  "$tmp/relay" --facade "$facade" --bind 127.0.0.3 --peer 127.0.0.2 --local "127.0.0.1:$RELAY_B" --reply "127.0.0.1:$END_B" --port "$DNSP" >"$tmp/b.log" 2>&1 &
  pids+=("$!")
  sleep 0.5
  for p in "${pids[@]}"; do
    kill -0 "$p" 2>/dev/null || fail "a relay did not start: $(cat "$tmp/a.log" "$tmp/b.log")"
  done
  python3 - "$facade" "$RELAY_A" "$RELAY_B" "$END_A" "$END_B" "$DNSP" <<'PY'
import socket, struct, sys, threading, time

facade = sys.argv[1]
relay_a, relay_b, end_a, end_b, dnsp = (int(x) for x in sys.argv[2:7])

def udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(2)
    return s

a, b = udp(end_a), udp(end_b)
# relay B was started with --reply, so b never has to send first; relay A learns its endpoint from the
# first local packet, so a registers itself
a.sendto(b"reg-a", ("127.0.0.1", relay_a))
time.sleep(0.3)
for s in (a, b):
    s.settimeout(0.3)
    try:
        while True:
            s.recvfrom(2048)
    except socket.timeout:
        pass
    s.settimeout(2)

a.sendto(b"from-a", ("127.0.0.1", relay_a))
assert b.recvfrom(2048)[0] == b"from-a", "a -> b"
b.sendto(b"from-b", ("127.0.0.1", relay_b))
assert a.recvfrom(2048)[0] == b"from-b", "b -> a"

N, size = 3000, 1300
got = [0]

def drain():
    b.settimeout(0.7)
    try:
        while True:
            d = b.recvfrom(2048)[0]
            assert len(d) == size, "payload size changed: %d" % len(d)
            got[0] += 1
    except socket.timeout:
        pass

t = threading.Thread(target=drain)
t.start()
for i in range(N):
    a.sendto(i.to_bytes(4, "big") + b"x" * (size - 4), ("127.0.0.1", relay_a))
    if i % 100 == 99:
        time.sleep(0.002)
t.join()
assert got[0] >= 0.9 * N, "bulk delivered only %d of %d" % (got[0], N)

if facade == "dns":
    # a well-formed frame from an address that is not the peer must not reach the endpoint
    question = b"\x05probe\x04test\x00" + struct.pack("!HH", 16, 1)
    payload = b"intruder"
    frame = (struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 1) + question
             + b"\x00" + struct.pack("!HHIH", 41, 4096, 0, len(payload)) + payload)
    x = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    x.bind(("127.0.0.4", 0))
    x.sendto(frame, ("127.0.0.2", dnsp))
    a.settimeout(0.5)
    try:
        a.recvfrom(2048)
        raise AssertionError("frame from a non-peer address was delivered")
    except socket.timeout:
        pass
print("delivered %d of %d" % (got[0], N))
PY
  kill "${pids[@]}" 2>/dev/null || true   # SIGTERM: each relay prints its counters and exits
  wait 2>/dev/null || true
  pids=()
  if [ "$facade" = dns ]; then
    grep -qE 'gso=[1-9]' "$tmp/a.log" || fail "dns facade: bulk frames never went out as one UDP GSO send: $(tail -2 "$tmp/a.log")"
  fi
}

run_facade dns
ok "dns facade: both directions (one end --reply, one learned), bulk delivery in UDP GSO batches, sizes intact, non-peer frame ignored"

if [ "$(id -u)" -eq 0 ]; then
  run_facade icmp
  ok "icmp facade: both directions, bulk delivery, sizes intact"
else
  echo "skip: icmp facade needs root"
fi

# FEC under loss: two network namespaces joined by a veth pair that drops 20% of packets each way.
# The sender's relay runs with or without --fec; the receiver's relay never has --fec (decoding needs
# no flag). Every packet carries its sequence number and a size and content derived from it, so the
# receiver catches loss, corruption (a wrong reconstruction) and duplicates. Halfway through, the
# sender's relay restarts (its block numbers start over) while the receiver's keeps running.
fec_under_loss() {  # <expected-min-delivered> <expected-max-delivered> [K:M]
  local min="$1" max="$2" fec="${3:-}" na="ggf-a-$$" nb="ggf-b-$$"
  ip netns add "$na"
  ip netns add "$nb"
  nets+=("$na" "$nb")
  ip link add va netns "$na" type veth peer name vb netns "$nb"
  ip -n "$na" addr add 192.0.2.1/24 dev va
  ip -n "$nb" addr add 192.0.2.2/24 dev vb
  for ns in "$na" "$nb"; do ip -n "$ns" link set lo up; done
  ip -n "$na" link set va up
  ip -n "$nb" link set vb up
  # pinned neighbours: netem drops ARP too, and a few seconds of failed resolution would read as tunnel loss
  ip -n "$na" neigh add 192.0.2.2 lladdr "$(ip -n "$nb" -br link show dev vb | awk '{print $3}')" dev va nud permanent
  ip -n "$nb" neigh add 192.0.2.1 lladdr "$(ip -n "$na" -br link show dev va | awk '{print $3}')" dev vb nud permanent
  tc -n "$na" qdisc add dev va root netem loss 20%
  tc -n "$nb" qdisc add dev vb root netem loss 20%
  # --gso off: netem would drop a whole UDP GSO send (up to 32 frames) as one packet, which is not the
  # per-packet loss this test models; on a real NIC the frames leave, and get lost, one by one
  start_sender() {
    ip netns exec "$na" "$tmp/relay" --facade dns --bind 192.0.2.1 --peer 192.0.2.2 --local 127.0.0.1:5601 \
      --gso off ${fec:+--fec "$fec"} >>"$tmp/fa.log" 2>&1 &
    apid=$!
    pids+=("$apid")
  }
  start_sender
  ip netns exec "$nb" "$tmp/relay" --facade dns --bind 192.0.2.2 --peer 192.0.2.1 --local 127.0.0.1:5601 \
    --reply 127.0.0.1:5599 >"$tmp/fb.log" 2>&1 &
  pids+=("$!")
  sleep 0.5
  ip netns exec "$nb" python3 - "$min" "$max" >"$tmp/recv.out" 2>&1 <<'PY' &
import socket, sys
lo, hi = float(sys.argv[1]), float(sys.argv[2])
N = 4000
def expect(seq):
    size = 40 + (seq * 7919) % 1340          # 40..1379 bytes, so blocks mix sizes
    return seq.to_bytes(4, "big") + bytes((seq * 31 + j) & 255 for j in range(size - 4))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 5599))
s.settimeout(3)
seen, bad, dup = set(), 0, 0
try:
    while True:
        d = s.recvfrom(4096)[0]
        seq = int.from_bytes(d[:4], "big")
        if seq >= N or d != expect(seq):
            bad += 1
        elif seq in seen:
            dup += 1
        else:
            seen.add(seq)
except socket.timeout:
    pass
frac = len(seen) / N
print("delivered %d of %d (%.2f%%), corrupt %d, duplicate %d" % (len(seen), N, 100 * frac, bad, dup))
assert bad == 0 and dup == 0, "corrupt or duplicate packets reached the tunnel"
assert lo <= frac <= hi, "delivered fraction %.4f outside [%s, %s]" % (frac, lo, hi)
PY
  local rp=$!
  sleep 0.3
  send_range() {  # <first> <end>
    ip netns exec "$na" python3 - "$1" "$2" <<'PY'
import socket, sys, time
def expect(seq):
    size = 40 + (seq * 7919) % 1340
    return seq.to_bytes(4, "big") + bytes((seq * 31 + j) & 255 for j in range(size - 4))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 5599))
for seq in range(int(sys.argv[1]), int(sys.argv[2])):
    s.sendto(expect(seq), ("127.0.0.1", 5601))
    if seq % 40 == 39:
        time.sleep(0.01)    # about 4000 packets/s
    if seq % 500 == 499:
        time.sleep(0.05)    # idle gaps, so partly filled blocks must be flushed by the timer
PY
  }
  send_range 0 2000
  kill "$apid"
  wait "$apid" 2>/dev/null || true
  start_sender
  sleep 0.5
  send_range 2000 4000
  local rc=0
  wait "$rp" || rc=$?
  cat "$tmp/recv.out"
  [ "$rc" -eq 0 ] || fail "fec ${fec:-off}: $(tail -1 "$tmp/recv.out"); sender relay: $(cat "$tmp/fa.log")"
  kill "${pids[@]}" 2>/dev/null || true
  wait 2>/dev/null || true
  pids=()
  ip netns del "$na"
  ip netns del "$nb"
  nets=()
}

if [ "$(id -u)" -eq 0 ] && modprobe sch_netem 2>/dev/null; then
  fec_under_loss 0.70 0.88
  ok "20% wire loss without FEC loses about a fifth (the loss is real)"
  fec_under_loss 0.995 1.0 10:10
  ok "20% wire loss with --fec 10:10: >= 99.5% delivered, mixed sizes and partly filled blocks intact"
else
  echo "skip: FEC loss test needs root and sch_netem"
fi

echo "relay: PASS"
