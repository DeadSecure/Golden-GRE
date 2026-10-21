#!/usr/bin/env python3
"""Behaviour tests for the relay's optional payload encryption (--keyfile).

Runs two real relay processes over loopback (A -> peer -> B) and injects known
"tunnel" packets into A's --local, reading what B delivers to its --reply. For the
dns facade a middle UDP process records and forwards the wire datagrams so the test
can assert on them; for icmp a raw sniffer captures copies off lo.

  crypto_test.py <relay-binary> <dns|icmp> <case>

cases:
  deliver    keyed A and B carry every injected packet through intact
  encrypted  the bytes on the wire after the facade header are not the plaintext
  markers    the per-frame facade markers vary across datagrams (not a constant)
  wrongkey   B with a different key delivers nothing
  legacy     no key on either end: delivery works and the markers are constant

Loopback addresses: A=127.0.0.1, B=127.0.0.2, middle=127.0.0.3 (dns only).
Exit 0 on pass, 1 on fail. Needs root for the icmp facade (raw sockets).
"""
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

A_IP, B_IP, MID_IP = "127.0.0.1", "127.0.0.2", "127.0.0.3"
PORT = 5353
A_LOCAL = (A_IP, 7001)      # relay A reads injected tunnel packets here
B_REPLY = (B_IP, 7008)      # relay B delivers decrypted packets here
DNS_HDR, ICMP_HDR = 39, 8
QUESTION = b"\x05probe\x04test\x00\x00\x10\x00\x01"  # legacy constant question
N = 40                      # packets per run
procs = []


def start(binary, facade, bind, peer, local, reply, keyfile):
    cmd = [binary, "--facade", facade, "--bind", bind, "--peer", peer,
           "--local", "%s:%d" % local, "--reply", "%s:%d" % reply]
    if facade == "dns":
        cmd += ["--port", str(PORT)]
    else:
        cmd += ["--itype", "0"]
    if keyfile:
        cmd += ["--keyfile", keyfile]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    procs.append(p)
    return p


def mkkey(d, name, byte):
    path = os.path.join(d, name)
    with open(path, "wb") as f:
        f.write(bytes([byte]) * 32)
    return path


def payload(i):  # a GRE-ish packet (never starts with 0xF5 = FEC_MAGIC), carries index i
    return struct.pack("!HHI", 0x0000, 0x0800, i) + b"golden-gre payload %04d" % i + b"\xab" * 40


def facade_strip(facade, d):
    if facade == "dns":
        return d[DNS_HDR:] if len(d) > DNS_HDR else b""
    ihl = (d[0] & 15) * 4
    return d[ihl + ICMP_HDR:] if len(d) > ihl + ICMP_HDR else b""


def facade_marker(facade, d):  # the bytes a DPI rule would key on
    if facade == "dns":
        return d[12:28]            # the question (qname + type/class)
    ihl = (d[0] & 15) * 4
    return d[ihl + 4:ihl + 6]      # the ICMP identifier


class DnsMiddle(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((MID_IP, PORT))
        self.s.settimeout(0.3)
        self.out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.out.bind((MID_IP, 0))  # so B sees the middle (its configured peer) as the source
        self.wire = []
        self.run_flag = True

    def run(self):
        while self.run_flag:
            try:
                d, _ = self.s.recvfrom(65535)
            except socket.timeout:
                continue
            self.wire.append(d)
            self.out.sendto(d, (B_IP, PORT))


class IcmpSniffer(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.s.settimeout(0.3)
        self.wire = []
        self.run_flag = True

    def run(self):
        while self.run_flag:
            try:
                d, addr = self.s.recvfrom(65535)
            except socket.timeout:
                continue
            if addr[0] == A_IP:  # the A -> B datagrams (B's own copy is filtered separately)
                self.wire.append(d)


def run_case(binary, facade, case):
    d = tempfile.mkdtemp()
    k1 = mkkey(d, "k1", 0x11)
    keyed = case != "legacy"
    a_key = k1 if keyed else None
    b_key = (mkkey(d, "k2", 0x22) if case == "wrongkey" else k1) if keyed else None

    recorder = None
    if facade == "dns":
        recorder = DnsMiddle()
        recorder.start()
        a_peer = MID_IP
    else:
        recorder = IcmpSniffer()
        recorder.start()
        a_peer = B_IP

    start(binary, facade, B_IP, (MID_IP if facade == "dns" else A_IP), (B_IP, 7002), B_REPLY, b_key)
    start(binary, facade, A_IP, a_peer, A_LOCAL, (A_IP, 7009), a_key)
    time.sleep(0.8)

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind(B_REPLY)
    rx.settimeout(0.3)

    inj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    inj.bind((A_IP, 7009))  # source = A's reply addr, so A also learns its reverse path
    sent = [payload(i) for i in range(N)]
    for pk in sent:
        inj.sendto(pk, A_LOCAL)
        time.sleep(0.01)

    got = []
    end = time.time() + 2
    while time.time() < end:
        try:
            got.append(rx.recv(65535))
        except socket.timeout:
            pass

    recorder.run_flag = False
    for p in procs:
        p.terminate()
    time.sleep(0.2)
    wire = recorder.wire
    logs = "".join("\n  [relay] " + (p.stdout.read() or b"").decode(errors="replace").replace("\n", "\n  ")
                   for p in procs)

    def fail(msg):
        print("FAIL [%s/%s]: %s%s" % (facade, case, msg, logs))
        sys.exit(1)

    legacy_marker = QUESTION if facade == "dns" else b"\x74\x62"  # probe.test / 0x7462

    if case in ("deliver", "legacy"):
        if set(got) != set(sent):
            fail("delivered %d/%d distinct packets" % (len(set(got) & set(sent)), N))
    elif case == "wrongkey":
        if got:
            fail("B with the wrong key delivered %d packets (want 0)" % len(got))
        if "decrypt failed" not in logs:
            fail("B dropped every frame but never said the keys differ")
    elif case == "encrypted":
        if not wire:
            fail("captured no wire datagrams")
        bodies = [facade_strip(facade, w) for w in wire]
        plain = set(sent)
        if any(any(b.find(p) >= 0 for p in plain) for b in bodies):
            fail("plaintext payload found on the wire")
    elif case == "markers":
        if len(wire) < 5:
            fail("too few wire datagrams to judge (%d)" % len(wire))
        if any(facade_marker(facade, w) == legacy_marker for w in wire):
            fail("the legacy constant marker is still on the wire")
        if facade == "dns":  # the txid must also not be a predictable constant/sequence
            txids = {w[:2] for w in wire}
            if len(txids) < 2:
                fail("dns txid is constant across %d datagrams" % len(wire))

    print("PASS [%s/%s]" % (facade, case))
    sys.exit(0)


def derive(binary, salt, passphrase):
    p = subprocess.run([binary, "--derive-key", salt], input=passphrase.encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.stdout


def run_kdf(binary):
    def fail(msg):
        print("FAIL [kdf]: %s" % msg)
        sys.exit(1)
    salt = "203.0.113.1,198.51.100.2"
    k1 = derive(binary, salt, "correct horse battery staple")
    if len(k1) != 32:
        fail("key is %d bytes, want 32" % len(k1))
    if derive(binary, salt, "correct horse battery staple") != k1:
        fail("same passphrase + salt gave a different key (not deterministic)")
    if derive(binary, "198.51.100.2,203.0.113.1", "correct horse battery staple") != k1:
        fail("swapped IP pair gave a different key (salt not order-independent)")
    if derive(binary, salt, "wrong passphrase") == k1:
        fail("a different passphrase gave the same key")
    if derive(binary, "203.0.113.9,198.51.100.2", "correct horse battery staple") == k1:
        fail("a different IP pair gave the same key")
    print("PASS [kdf]")
    sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[2] == "kdf":
        run_kdf(sys.argv[1])
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    run_case(sys.argv[1], sys.argv[2], sys.argv[3])
