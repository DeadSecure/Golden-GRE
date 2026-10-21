// golden-gre-relay: carry a tunnel's UDP packets between two servers inside a disguise that a filtered
// IPv4 path lets through. The tunnel (GRE-in-FOU on loopback) sends its packets to --local; each one is
// wrapped and sent to the peer's relay, which unwraps it and hands it to its own tunnel: to --reply if
// given (the tunnel's FOU address), else to the sender of the last local packet, which means nothing
// reaches the tunnel until the tunnel has sent something. Batches with recvmmsg/sendmmsg. Each
// direction runs in its own thread, so a two-core server spreads the relay over both cores.
//
// FEC: with --fec K:M the relay follows every K tunnel packets with M Reed-Solomon parity packets (a
// block that is still short FLUSH_MS after its first packet gets proportionally fewer), so the peer can
// rebuild up to M lost packets of the block without waiting a round trip for TCP to resend them. Data
// packets are never held back. Only the sending side needs the flag: every relay decodes FEC frames and
// still accepts plain ones, so turn it on for the direction that loses packets.
//
// With the dns facade, runs of equal-size frames go out as one UDP GSO send (see wire_flush); --gso off
// sends every frame on its own (it is also switched off by itself where the kernel cannot do it).
// SIGTERM/SIGINT print the counters and exit.
//
//   gcc -O2 -Wall -pthread -o golden-gre-relay golden-gre-relay.c
//   golden-gre-relay --facade dns|icmp --bind <public_ip> --peer <peer_ip> --local <ip:port>
//                    [--reply <ip:port>] [--port 53] [--itype 0] [--fec K:M] [--gso on|off]
//
// dns:  UDP from an ephemeral port to <peer>:53, framed as a DNS query (one question, EDNS0 OPT record
//       whose RDATA is the payload); listens on <bind>:53 (--port).
// icmp: ICMP messages of --itype: 0 = unsolicited echo reply, so no kernel answers it; 8 = echo request, for
// paths that drop echo replies without a request (golden-gre-up.sh then drops the kernel's answers); needs root.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "monocypher.h"

#define BATCH 64
#define OUTQ 128
#define BUF 2048
#define DNS_HDR 39  // 12 header + 16 question + 11 OPT record header
#define ICMP_HDR 8
#define HEAD 64     // room in front of the payload for the facade header
#define IDENT 0x7462

#define FEC_MAGIC 0xF5  // first payload byte of an FEC frame; no GRE or WireGuard packet starts with it
#define FEC_HDR 7       // magic, block id (4 bytes), index (data: i, parity: 0x80 | j), k (parity only)
#define KMAX 32
#define MMAX 32
#define NSLOT 64        // blocks the receiver keeps open
#define FLUSH_MS 5
#define MAXPAY (BUF - HEAD - FEC_HDR - 2 - CRYPTO_OH)  // largest tunnel packet; room for FEC len + AEAD nonce/tag
#define GSO_MAX 32       // frames per UDP GSO send (the kernel allows 64 on older versions)
#define GSO_BYTES 60000  // and bytes per send (one UDP datagram before segmentation)
#define GSO_FRAME 1472   // frames above this would not fit a 1500-byte MTU unfragmented: sent alone
#define NONCE 24         // XChaCha20-Poly1305 nonce, prepended to the frame payload when keyed
#define TAG 16           // Poly1305 authentication tag, appended after the ciphertext when keyed
#define CRYPTO_OH (NONCE + TAG)

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

static const uint8_t QUESTION[16] = {5, 'p', 'r', 'o', 'b', 'e', 4, 't', 'e', 's', 't', 0, 0, 16, 0, 1};

// --- optional payload encryption (--keyfile): XChaCha20-Poly1305 over the frame payload. When keyed,
// the receiver identifies our frames by a verifying tag instead of a constant marker, so the dns
// question and the icmp identifier can be random and carry no fixed signature. ---
static uint64_t now_ms(void);
static int keyed;
static uint8_t key[32];
static uint8_t nonce_base[16];     // random per process; with the per-frame counter the nonce never repeats
static uint64_t nonce_ctr;         // only local_to_wire sends on the wire, so one unlocked counter is safe
static uint8_t cur_question[16];   // the dns question actually sent: QUESTION, or random labels when keyed
static unsigned cur_ident = IDENT; // the icmp identifier actually sent: IDENT, or random when keyed
static uint64_t rngs;              // xorshift64 for the cosmetic per-frame txid / per-flow markers

static uint64_t xrng(void) {
  rngs ^= rngs << 13;
  rngs ^= rngs >> 7;
  rngs ^= rngs << 17;
  return rngs;
}

static void rng_seed(void) {
  if (getrandom(&rngs, sizeof rngs, 0) != sizeof rngs || !rngs) rngs = now_ms() | 1;
}

// A well-formed 5+4-label question with random a-z0-9 content; the lengths, root and type/class keep the
// 16-byte shape so the fixed header offset still holds, but the name is no longer a constant to match on.
static void randomize_question(void) {
  static const char cs[] = "abcdefghijklmnopqrstuvwxyz0123456789";
  memcpy(cur_question, QUESTION, sizeof cur_question);
  for (int i = 1; i <= 10; i++) {
    if (i == 6) continue;  // the second label's length byte
    cur_question[i] = (uint8_t)cs[xrng() % 35];
  }
}

static void gen_nonce(uint8_t *n) {
  memcpy(n, nonce_base, 16);
  uint64_t c = nonce_ctr++;
  for (int i = 0; i < 8; i++) n[16 + i] = (uint8_t)(c >> (56 - 8 * i));
}

// receive batches, one per direction: each direction runs in its own thread
struct batch {
  uint8_t bufs[BATCH][BUF];
  struct sockaddr_in names[BATCH];
  struct iovec iov[BATCH];
  struct mmsghdr msgs[BATCH];
};
static struct batch from_local, from_wire;

#define MAX_PORTS 8  // dns facade: the receiver may listen on several ports; see the --port list
static int is_dns, itype, tx, loc;
static int rxs[MAX_PORTS], nports = 1;       // the receive sockets (the dns facade may have several)
static int peer_i;                           // which of peers[] the current tx socket sends to
static struct sockaddr_in peers[MAX_PORTS];  // the peer addresses, one per port in the list
static int rotate;                // dns only: reopen the sending socket every this many frames (0 = never)
static unsigned long sockframes;  // frames sent on the current tx socket
static struct sockaddr_in tx_bind;
static int rate;                  // cap on wire frames per second (0 = unlimited)
static double tokens;             // token bucket behind --rate
static uint64_t token_ts;
static struct sockaddr_in peer;  // the dns facade's tx thread rotates its port; the address never changes
static in_addr_t peer_addr;       // the peer's address, for the rx thread's source check
static struct sockaddr_in reply;  // where tunnel packets go; the wire -> local thread's own copy
static unsigned seq;
static unsigned long ntx, nrx, nbad, nrebuilt;
#define ADD(v, n) __atomic_add_fetch(&(v), (n), __ATOMIC_RELAXED)  // counters: both threads, the stats line
#define GET(v) __atomic_load_n(&(v), __ATOMIC_RELAXED)

static void die(const char *what) {
  perror(what);
  exit(1);
}

static struct sockaddr_in mkaddr(const char *ip, int port) {
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
  if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
    fprintf(stderr, "bad address %s\n", ip);
    exit(1);
  }
  return a;
}

static int udp_socket(struct sockaddr_in a) {
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  int big = 4 << 20;
  if (s < 0) die("socket");
  setsockopt(s, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
  setsockopt(s, SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
  if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) die("bind");
  return s;
}

// Reopen the sending socket with a fresh source port. Some paths allow only the first few packets of
// each flow, and a source port is most of what tells the path one flow from the next; the receiver
// keeps listening on its one port and accepts any source port. With several ports in the list, the
// destination port rotates too, which multiplies the number of distinct flows by the list length.
static void rotate_tx(void) {
  close(tx);
  tx = udp_socket(tx_bind);
  sockframes = 0;
  if (keyed) randomize_question();  // a fresh flow gets a fresh name, so flows do not share a signature
  if (nports > 1) {
    peer_i = (peer_i + 1) % nports;
    peer = peers[peer_i];
  }
}

static uint64_t now_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static uint16_t csum(const uint8_t *p, size_t n) {
  uint32_t t = 0;
  for (; n > 1; p += 2, n -= 2) t += (p[0] << 8) | p[1];
  if (n) t += p[0] << 8;
  while (t >> 16) t = (t & 0xFFFF) + (t >> 16);
  return (uint16_t)~t;
}

static void put16(uint8_t *p, unsigned v) {
  p[0] = v >> 8;
  p[1] = v & 0xFF;
}

static void dns_head(uint8_t *h, unsigned id, size_t payload) {
  static const uint8_t flags[10] = {0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  put16(h, id);
  memcpy(h + 2, flags, sizeof flags);
  memcpy(h + 12, cur_question, sizeof cur_question);
  h[28] = 0;                // OPT owner name: root
  put16(h + 29, 41);        // type OPT
  put16(h + 31, 4096);      // UDP payload size
  memset(h + 33, 0, 4);     // extended rcode / flags
  put16(h + 37, payload);   // RDATA length
}

static void icmp_head(uint8_t *h, int type, unsigned seq, size_t payload) {
  h[0] = type;
  h[1] = 0;
  put16(h + 2, 0);
  put16(h + 4, cur_ident);
  put16(h + 6, seq);
  put16(h + 2, csum(h, ICMP_HDR + payload));
}

// --- outgoing queues: frames to the peer (wire) and packets to the local tunnel endpoint ---

static uint8_t wbuf[OUTQ][BUF], lbuf[OUTQ][BUF];
static struct iovec wiov[OUTQ], liov[OUTQ];
static struct mmsghdr wmsg[OUTQ], lmsg[OUTQ];
static int nw, nl;

// UDP GSO (dns facade): a run of equal-size frames, optionally ending in one shorter frame, goes to the
// kernel as one send with UDP_SEGMENT. The kernel builds one packet for the whole run and the NIC (or the
// kernel, late) cuts it into the frames: one route lookup, one allocation and one virtio doorbell per run
// instead of per frame, which is most of what a relay on a small virtual machine spends its CPU on.
static int use_gso;
static unsigned long ngso;
static int stopping;  // set by the signal handler, read by every thread

static void on_stop(int sig) {
  (void)sig;
  __atomic_store_n(&stopping, 1, __ATOMIC_RELAXED);
}

static void wire_flush(void) {
  static struct mmsghdr g[OUTQ];
  static union { char buf[CMSG_SPACE(sizeof(uint16_t))]; struct cmsghdr align; } cm[OUTQ];
  static int first[OUTQ], nseg[OUTQ];
  if (!nw) return;
  if (!use_gso) {
    int sent = sendmmsg(tx, wmsg, nw, 0);
    if (sent > 0) {
      ADD(ntx, sent);
      sockframes += sent;
      if (rate) tokens -= sent;
    }
    nw = 0;
    if (rotate && sockframes >= (unsigned long)rotate) rotate_tx();
    return;
  }
  int ng = 0;
  for (int i = 0; i < nw;) {
    size_t sz = wiov[i].iov_len;
    int n = 1, cap = sz <= GSO_FRAME ? (int)(GSO_BYTES / sz) : 1;
    if (cap > GSO_MAX) cap = GSO_MAX;
    while (i + n < nw && n < cap && wiov[i + n].iov_len <= sz)
      if (wiov[i + n++].iov_len < sz) break;  // a shorter frame may only end a run
    g[ng].msg_hdr = (struct msghdr){.msg_name = &peer, .msg_namelen = sizeof peer, .msg_iov = &wiov[i], .msg_iovlen = n};
    if (n > 1) {
      uint16_t s16 = sz;
      g[ng].msg_hdr.msg_control = cm[ng].buf;
      g[ng].msg_hdr.msg_controllen = sizeof cm[ng].buf;
      struct cmsghdr *c = CMSG_FIRSTHDR(&g[ng].msg_hdr);
      c->cmsg_level = SOL_UDP;
      c->cmsg_type = UDP_SEGMENT;
      c->cmsg_len = CMSG_LEN(sizeof s16);
      memcpy(CMSG_DATA(c), &s16, sizeof s16);
    }
    first[ng] = i;
    nseg[ng++] = n;
    i += n;
  }
  for (int j = 0; j < ng;) {
    int sent = sendmmsg(tx, g + j, ng - j, 0);
    if (sent > 0) {
      for (int k = j; k < j + sent; k++) {
        ADD(ntx, nseg[k]);
        sockframes += nseg[k];
        if (rate) tokens -= nseg[k];
        if (nseg[k] > 1) ADD(ngso, 1);
      }
      j += sent;
      continue;
    }
    if (nseg[j] > 1 && (errno == EIO || errno == EINVAL)) {  // no UDP GSO on this path: plain sends from now on
      printf("udp gso unavailable (%s); sending frames one by one\n", strerror(errno));
      fflush(stdout);
      use_gso = 0;
      int rest = sendmmsg(tx, wmsg + first[j], nw - first[j], 0);
      if (rest > 0) {
        ADD(ntx, rest);
        sockframes += rest;
        if (rate) tokens -= rest;
      }
    }
    break;  // anything else (a full socket buffer): drop the rest, as a plain send would
  }
  nw = 0;
  if (rotate && sockframes >= (unsigned long)rotate) rotate_tx();
}

// queue the frame a || b, wrapped in the facade
static void wire_emit(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) {
  uint8_t *p = wbuf[nw] + HEAD;
  size_t len = alen + blen, hdr = is_dns ? DNS_HDR : ICMP_HDR, paylen;
  if (keyed) {
    uint8_t *pt = p + NONCE;  // payload = nonce || AEAD(frame) || tag; encrypt in place over pt
    if (alen) memcpy(pt, a, alen);
    memcpy(pt + alen, b, blen);
    gen_nonce(p);
    crypto_aead_lock(pt, pt + len, key, p, NULL, 0, pt, len);
    paylen = NONCE + len + TAG;
  } else {
    if (alen) memcpy(p, a, alen);
    memcpy(p + alen, b, blen);
    paylen = len;
  }
  seq++;
  if (is_dns) dns_head(p - hdr, keyed ? (unsigned)(xrng() & 0xFFFF) : seq, paylen);
  else icmp_head(p - hdr, itype, seq, paylen);
  wiov[nw] = (struct iovec){p - hdr, hdr + paylen};
  wmsg[nw].msg_hdr = (struct msghdr){.msg_name = &peer, .msg_namelen = sizeof peer, .msg_iov = &wiov[nw], .msg_iovlen = 1};
  // Also flush at a rotation boundary, so one source port never carries more than --rotate frames.
  if (++nw == OUTQ || (rotate && sockframes + (unsigned long)nw >= (unsigned long)rotate)) wire_flush();
}

// Deliver decrypted packets to the local tunnel endpoint. Like wire_flush, coalesce a run of equal-size
// packets into one UDP GSO send (they all go to the one reply address), so the kernel builds and
// segments a single skb instead of running udp_sendmsg per packet — the relay's top cost under load.
static int local_gso = 1;  // loopback UDP GSO; turned off for good if the kernel ever refuses it
static void local_flush(void) {
  static struct mmsghdr g[OUTQ];
  static union { char buf[CMSG_SPACE(sizeof(uint16_t))]; struct cmsghdr align; } cm[OUTQ];
  static int first[OUTQ], nseg[OUTQ];
  if (!nl) return;
  if (!local_gso) {
    int sent = sendmmsg(loc, lmsg, nl, 0);
    if (sent > 0) ADD(nrx, sent);
    nl = 0;
    return;
  }
  int ng = 0;
  for (int i = 0; i < nl;) {
    size_t sz = liov[i].iov_len;
    int n = 1, cap = sz <= GSO_FRAME ? (int)(GSO_BYTES / sz) : 1;
    if (cap > GSO_MAX) cap = GSO_MAX;
    while (i + n < nl && n < cap && liov[i + n].iov_len <= sz)
      if (liov[i + n++].iov_len < sz) break;  // a shorter packet may only end a run
    g[ng].msg_hdr = (struct msghdr){.msg_name = &reply, .msg_namelen = sizeof reply, .msg_iov = &liov[i], .msg_iovlen = n};
    if (n > 1) {
      uint16_t s16 = sz;
      g[ng].msg_hdr.msg_control = cm[ng].buf;
      g[ng].msg_hdr.msg_controllen = sizeof cm[ng].buf;
      struct cmsghdr *c = CMSG_FIRSTHDR(&g[ng].msg_hdr);
      c->cmsg_level = SOL_UDP;
      c->cmsg_type = UDP_SEGMENT;
      c->cmsg_len = CMSG_LEN(sizeof s16);
      memcpy(CMSG_DATA(c), &s16, sizeof s16);
    }
    first[ng] = i;
    nseg[ng++] = n;
    i += n;
  }
  for (int j = 0; j < ng;) {
    int sent = sendmmsg(loc, g + j, ng - j, 0);
    if (sent > 0) {
      for (int k = j; k < j + sent; k++) ADD(nrx, nseg[k]);
      j += sent;
      continue;
    }
    if (nseg[j] > 1 && (errno == EIO || errno == EINVAL)) {  // no UDP GSO to the tunnel here: plain sends from now on
      printf("local udp gso unavailable (%s); sending packets one by one\n", strerror(errno));
      fflush(stdout);
      local_gso = 0;
      int rest = sendmmsg(loc, lmsg + first[j], nl - first[j], 0);
      if (rest > 0) ADD(nrx, rest);
    }
    break;  // a full socket buffer: drop the rest, as a plain send would
  }
  nl = 0;
}

static void local_emit(const uint8_t *p, size_t len) {
  memcpy(lbuf[nl], p, len);
  liov[nl] = (struct iovec){lbuf[nl], len};
  lmsg[nl].msg_hdr = (struct msghdr){.msg_name = &reply, .msg_namelen = sizeof reply, .msg_iov = &liov[nl], .msg_iovlen = 1};
  if (++nl == OUTQ) local_flush();
}

// --- Reed-Solomon over GF(256): systematic, parity row j = sum over i of C[j][i] * data_i with the
// Cauchy matrix C[j][i] = 1 / ((128 + j) xor i). Every square submatrix of a Cauchy matrix is invertible,
// so any K of the K + M packets of a block rebuild it. Packets of a block differ in size: each counts as
// the vector (2-byte length, payload, zero padding) and parity is as long as the longest.

static uint8_t gexp[512], glog[256], gmul[256][256], cauchy[MMAX][KMAX];
// split-nibble tables: c * b = nib[c][0][b & 15] ^ nib[c][1][b >> 4], 16 bytes each, so a SIMD byte
// shuffle multiplies 16 or 32 bytes by c at once
static uint8_t nib[256][2][16];

static uint8_t ginv(uint8_t a) { return gexp[255 - glog[a]]; }

static void gf_init(void) {
  unsigned x = 1;
  for (int i = 0; i < 255; i++) {
    gexp[i] = gexp[i + 255] = (uint8_t)x;
    glog[x] = (uint8_t)i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (int a = 1; a < 256; a++)
    for (int b = 1; b < 256; b++) gmul[a][b] = gexp[glog[a] + glog[b]];
  for (int c = 0; c < 256; c++)
    for (int n = 0; n < 16; n++) {
      nib[c][0][n] = gmul[c][n];
      nib[c][1][n] = gmul[c][n << 4];
    }
  for (int j = 0; j < MMAX; j++)
    for (int i = 0; i < KMAX; i++) cauchy[j][i] = ginv((uint8_t)((0x80 | j) ^ i));
}

static uint8_t coef(int j, int i) { return cauchy[j][i]; }

// dst += c * src, three ways; gf_pick chooses one at startup
static void muladd_table(uint8_t *dst, const uint8_t *src, uint8_t c, size_t n) {
  const uint8_t *row = gmul[c];
  for (size_t x = 0; x < n; x++) dst[x] ^= row[src[x]];
}

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#define GF_X86 1

__attribute__((target("avx2"))) static void muladd_avx2(uint8_t *dst, const uint8_t *src, uint8_t c, size_t n) {
  const __m256i lo = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *)nib[c][0]));
  const __m256i hi = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *)nib[c][1]));
  const __m256i mask = _mm256_set1_epi8(0x0F);
  size_t x = 0;
  for (; x + 32 <= n; x += 32) {
    __m256i s = _mm256_loadu_si256((const __m256i *)(src + x));
    __m256i p = _mm256_xor_si256(_mm256_shuffle_epi8(lo, _mm256_and_si256(s, mask)),
                                 _mm256_shuffle_epi8(hi, _mm256_and_si256(_mm256_srli_epi64(s, 4), mask)));
    _mm256_storeu_si256((__m256i *)(dst + x), _mm256_xor_si256(_mm256_loadu_si256((const __m256i *)(dst + x)), p));
  }
  muladd_table(dst + x, src + x, c, n - x);
}

__attribute__((target("ssse3"))) static void muladd_ssse3(uint8_t *dst, const uint8_t *src, uint8_t c, size_t n) {
  const __m128i lo = _mm_loadu_si128((const __m128i *)nib[c][0]);
  const __m128i hi = _mm_loadu_si128((const __m128i *)nib[c][1]);
  const __m128i mask = _mm_set1_epi8(0x0F);
  size_t x = 0;
  for (; x + 16 <= n; x += 16) {
    __m128i s = _mm_loadu_si128((const __m128i *)(src + x));
    __m128i p = _mm_xor_si128(_mm_shuffle_epi8(lo, _mm_and_si128(s, mask)),
                              _mm_shuffle_epi8(hi, _mm_and_si128(_mm_srli_epi64(s, 4), mask)));
    _mm_storeu_si128((__m128i *)(dst + x), _mm_xor_si128(_mm_loadu_si128((const __m128i *)(dst + x)), p));
  }
  muladd_table(dst + x, src + x, c, n - x);
}
#endif

static void (*muladd)(uint8_t *dst, const uint8_t *src, uint8_t c, size_t n) = muladd_table;
static const char *gf_impl = "table";

// The fastest multiply this CPU has, used only after it matched the table for every coefficient and a
// spread of lengths (vector loop and tail): parity must be byte-identical to what any relay computes.
static void gf_pick(void) {
#ifdef GF_X86
  __builtin_cpu_init();
  if (__builtin_cpu_supports("avx2")) {
    muladd = muladd_avx2;
    gf_impl = "avx2";
  } else if (__builtin_cpu_supports("ssse3")) {
    muladd = muladd_ssse3;
    gf_impl = "ssse3";
  }
#endif
  uint8_t src[100], a[100], b[100];
  for (int c = 0; c < 256; c++) {
    size_t n = 1 + (size_t)(c * 37) % 100;
    for (size_t x = 0; x < n; x++) {
      src[x] = (uint8_t)(x * 151 + c * 7 + 13);
      a[x] = b[x] = (uint8_t)(x * 29 + c);
    }
    muladd_table(a, src, (uint8_t)c, n);
    muladd(b, src, (uint8_t)c, n);
    if (memcmp(a, b, n)) {
      muladd = muladd_table;
      gf_impl = "table (the fast path did not match)";
      return;
    }
  }
}

static void muladd_vec(uint8_t *dst, const uint8_t *p, size_t len, uint8_t c) {  // dst += c * (len, p)
  uint8_t pre[2] = {(uint8_t)(len >> 8), (uint8_t)len};
  muladd(dst, pre, c, 2);
  muladd(dst + 2, p, c, len);
}

static void fec_head(uint8_t *h, uint32_t id, int idx, int k) {
  h[0] = FEC_MAGIC;
  h[1] = id >> 24;
  h[2] = id >> 16;
  h[3] = id >> 8;
  h[4] = id;
  h[5] = idx;
  h[6] = k;
}

// sender: every parity row grows as each packet of the block goes out (the packet is still in cache and
// need not be kept), and goes out itself when the block is full or FLUSH_MS old
static int fec_k, fec_m;
static struct {
  uint32_t id;
  int k;
  size_t maxlen;
  uint8_t par[MMAX][2 + MAXPAY];
  uint64_t start;
} enc;

static void fec_flush(void) {  // send the current block's parity and start the next block
  uint8_t h[FEC_HDR];
  int k = enc.k, m = (fec_m * k + fec_k - 1) / fec_k;
  size_t L = 2 + enc.maxlen;
  for (int j = 0; j < m; j++) {
    fec_head(h, enc.id, 0x80 | j, k);
    wire_emit(h, FEC_HDR, enc.par[j], L);
  }
  for (int j = 0; j < fec_m; j++) memset(enc.par[j], 0, L);
  enc.id++;
  enc.k = 0;
  enc.maxlen = 0;
}

static void send_tunnel_packet(const uint8_t *p, size_t len) {
  if (!fec_k) {
    wire_emit(NULL, 0, p, len);
    return;
  }
  uint8_t h[FEC_HDR];
  if (!enc.k) enc.start = now_ms();
  fec_head(h, enc.id, enc.k, 0);
  wire_emit(h, FEC_HDR, p, len);
  for (int j = 0; j < fec_m; j++) muladd_vec(enc.par[j], p, len, coef(j, enc.k));
  if (len > enc.maxlen) enc.maxlen = len;
  if (++enc.k == fec_k) fec_flush();
}

// receiver: data packets go to the tunnel as they arrive; once a block has as many packets as it has
// data packets, the missing ones are rebuilt and sent after them
static struct slot {
  uint32_t id;
  int used, done, k, nd, np;
  size_t L;
  uint8_t have[KMAX + MMAX];
  size_t len[KMAX + MMAX];
  uint8_t buf[KMAX + MMAX][2 + MAXPAY];
} slots[NSLOT];

static void fec_rebuild(struct slot *s) {
  static uint8_t S[MMAX][2 + MAXPAY];
  uint8_t a[MMAX][2 * MMAX];
  int miss[KMAX], prow[MMAX], e = 0, r = 0;
  for (int i = 0; i < s->k; i++)
    if (!s->have[i]) miss[e++] = i;
  for (int j = 0; j < MMAX && r < e; j++)
    if (s->have[KMAX + j]) prow[r++] = j;
  if (r < e) return;
  // S_r = parity row prow[r] minus the received data's share = sum over missing c of C[prow[r]][c] * D_c
  for (r = 0; r < e; r++) {
    memcpy(S[r], s->buf[KMAX + prow[r]], s->L);
    for (int i = 0; i < s->k; i++)
      if (s->have[i]) muladd_vec(S[r], s->buf[i], s->len[i], coef(prow[r], i));
    for (int c = 0; c < e; c++) {
      a[r][c] = coef(prow[r], miss[c]);
      a[r][e + c] = r == c;
    }
  }
  for (int c = 0; c < e; c++) {  // Gauss-Jordan: a = [A | I] becomes [I | A^-1]
    int p = c;
    while (p < e && !a[p][c]) p++;
    if (p == e) { ADD(nbad, 1); return; }
    for (int x = 0; p != c && x < 2 * e; x++) {
      uint8_t t = a[p][x];
      a[p][x] = a[c][x];
      a[c][x] = t;
    }
    uint8_t inv = ginv(a[c][c]);
    for (int x = 0; x < 2 * e; x++) a[c][x] = gmul[inv][a[c][x]];
    for (int q = 0; q < e; q++) {
      uint8_t f = a[q][c];
      if (q == c || !f) continue;
      for (int x = 0; x < 2 * e; x++) a[q][x] ^= gmul[f][a[c][x]];
    }
  }
  for (int c = 0; c < e; c++) {
    uint8_t *d = s->buf[miss[c]];
    memset(d, 0, s->L);
    for (r = 0; r < e; r++) muladd(d, S[r], a[c][e + r], s->L);
    size_t n = (size_t)d[0] << 8 | d[1];
    s->have[miss[c]] = 1;
    if (n > s->L - 2) { ADD(nbad, 1); continue; }
    local_emit(d + 2, n);
    ADD(nrebuilt, 1);
  }
  s->done = 1;
}

static void fec_input(const uint8_t *p, size_t len) {
  if (len < FEC_HDR) { ADD(nbad, 1); return; }
  uint32_t id = (uint32_t)p[1] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 8 | p[4];
  int idx = p[5], k = p[6], par = idx & 0x80, j = idx & 0x7F;
  const uint8_t *body = p + FEC_HDR;
  size_t blen = len - FEC_HDR;
  if (par ? j >= MMAX || k < 1 || k > KMAX || blen < 2 || blen > 2 + MAXPAY : idx >= KMAX || blen > MAXPAY) {
    ADD(nbad, 1);
    return;
  }
  struct slot *s = &slots[id % NSLOT];
  if (!s->used || s->id != id) {
    // a late packet of a block whose slot is already reused; anything further back is a sender that
    // restarted (it numbers its blocks from a new random start), so the slot starts over
    uint32_t behind = s->id - id;
    if (s->used && behind <= 4 * NSLOT) {
      if (!par) local_emit(body, blen);
      return;
    }
    memset(s->have, 0, sizeof s->have);
    s->id = id;
    s->used = 1;
    s->done = s->k = s->nd = s->np = 0;
    s->L = 0;
  }
  int at = par ? KMAX + j : idx;
  if (s->have[at]) return;  // a duplicate, or a packet already rebuilt
  if (par) {
    if (s->k && (s->k != k || s->L != blen)) { ADD(nbad, 1); return; }
    s->k = k;
    s->L = blen;
    s->np++;
  } else {
    s->nd++;
    if (!s->done) local_emit(body, blen);
  }
  s->have[at] = 1;
  memcpy(s->buf[at], body, blen);
  s->len[at] = blen;
  if (s->k && !s->done) {
    if (s->nd >= s->k) s->done = 1;
    else if (s->nd + s->np >= s->k) fec_rebuild(s);
  }
}

// --- the two directions, one thread each. They share only where tunnel packets go (learned from the
// tunnel's own packets unless --reply fixed it) and the counters, so they run on two cores in parallel.

static pthread_mutex_t reply_mu = PTHREAD_MUTEX_INITIALIZER;
static struct sockaddr_in reply_shared;
static int reply_known;

static void set_reply(const struct sockaddr_in *a) {
  pthread_mutex_lock(&reply_mu);
  reply_shared = *a;
  reply_known = 1;
  pthread_mutex_unlock(&reply_mu);
}

static int get_reply(struct sockaddr_in *a) {
  pthread_mutex_lock(&reply_mu);
  int known = reply_known;
  if (known) *a = reply_shared;
  pthread_mutex_unlock(&reply_mu);
  return known;
}

static void recv_setup(struct batch *b, size_t room) {
  for (int i = 0; i < BATCH; i++) {
    b->iov[i] = (struct iovec){b->bufs[i], room};
    b->msgs[i].msg_hdr = (struct msghdr){.msg_name = &b->names[i], .msg_namelen = sizeof b->names[i], .msg_iov = &b->iov[i], .msg_iovlen = 1};
  }
}

static void *local_to_wire(void *arg) {  // tunnel packets -> FEC -> facade -> peer
  struct batch *b = &from_local;
  struct sockaddr_in last = {0};
  struct pollfd pf = {loc, POLLIN, 0};
  (void)arg;
  while (!GET(stopping)) {
    int wait = 1000;
    if (enc.k) {
      uint64_t age = now_ms() - enc.start;
      wait = age >= FLUSH_MS ? 0 : (int)(FLUSH_MS - age);
    }
    if (rate) {  // token bucket: a short burst is fine, the sustained rate is what trips the path
      uint64_t now = now_ms();
      tokens += (double)(now - token_ts) * rate / 1000.0;
      token_ts = now;
      double cap = rate / 4.0;
      if (tokens > cap) tokens = cap;
      if (tokens < 1) {  // out of budget: sleep out the deficit instead of pulling more frames
        struct timespec ts = {0, (long)(1000000.0 * (1 - tokens) / rate) + 100000};
        nanosleep(&ts, NULL);
        continue;
      }
    }
    if (poll(&pf, 1, wait) > 0 && (pf.revents & POLLIN)) {
      recv_setup(b, MAXPAY);
      int n = recvmmsg(loc, b->msgs, BATCH, MSG_DONTWAIT, NULL);
      for (int i = 0; i < n; i++) {
        if (memcmp(&b->names[i], &last, sizeof last)) {  // the tunnel's address: tell the other direction
          last = b->names[i];
          set_reply(&last);
        }
        if (b->msgs[i].msg_hdr.msg_flags & MSG_TRUNC) { ADD(nbad, 1); continue; }
        send_tunnel_packet(b->bufs[i], b->msgs[i].msg_len);
      }
      wire_flush();
    }
    if (enc.k && now_ms() - enc.start >= FLUSH_MS) {
      fec_flush();
      wire_flush();
    }
  }
  return NULL;
}

static void *wire_to_local(void *arg) {  // peer -> facade -> FEC -> tunnel
  struct batch *b = &from_wire;
  struct pollfd pf[MAX_PORTS];
  (void)arg;
  for (int i = 0; i < nports; i++) pf[i] = (struct pollfd){rxs[i], POLLIN, 0};
  while (!GET(stopping)) {
    if (poll(pf, nports, 1000) <= 0) continue;
    int got = 0;
    for (int k = 0; k < nports; k++) {
      if (!(pf[k].revents & POLLIN)) continue;
      recv_setup(b, BUF);
      int n = recvmmsg(rxs[k], b->msgs, BATCH, MSG_DONTWAIT, NULL);
      // Read even before the tunnel's address is known, and drop: unread data would keep poll returning.
      if (n <= 0 || !get_reply(&reply)) continue;
      got = 1;
      for (int i = 0; i < n; i++) {
        uint8_t *p = b->bufs[i];
        size_t len = b->msgs[i].msg_len;
        if (b->names[i].sin_addr.s_addr != peer_addr) continue;
        if (is_dns) {
          // keyed: the tag decides, so no constant question to match on; legacy: match the fixed question
          if (len <= DNS_HDR || (!keyed && memcmp(p + 12, QUESTION, sizeof QUESTION))) { ADD(nbad, 1); continue; }
          p += DNS_HDR;
          len -= DNS_HDR;
        } else {
          size_t ihl = (p[0] & 15) * 4;
          if (len <= ihl + ICMP_HDR || (!keyed && ((p[ihl + 4] << 8) | p[ihl + 5]) != IDENT)) { ADD(nbad, 1); continue; }
          if (p[ihl] != itype) {  // the peer's relay with the other ICMP_TYPE: say so once instead of going quiet
            static int warned;
            if (!warned++)
              fprintf(stderr, "golden-gre-relay: got ICMP type %d, ICMP_TYPE here is %d: set the same ICMP_TYPE on both ends\n",
                      p[ihl], itype);
            ADD(nbad, 1);
            continue;
          }
          p += ihl + ICMP_HDR;
          len -= ihl + ICMP_HDR;
        }
        uint8_t pt[BUF];
        if (keyed) {  // nonce || ciphertext || tag; a verifying tag is what marks the frame as ours
          if (len < NONCE + TAG) { ADD(nbad, 1); continue; }
          size_t ctlen = len - NONCE - TAG;
          if (crypto_aead_unlock(pt, p + NONCE + ctlen, key, p, NULL, 0, p + NONCE, ctlen)) {
            static int warned;  // a key mismatch drops every frame: say why once instead of going quiet
            if (!warned++) fprintf(stderr, "golden-gre-relay: payload decrypt failed: both ends must use the same KEYFILE\n");
            ADD(nbad, 1);
            continue;
          }
          p = pt;
          len = ctlen;
        }
        if (p[0] == FEC_MAGIC) fec_input(p, len);
        else local_emit(p, len);
      }
    }
    if (got) local_flush();
  }
  return NULL;
}

static void print_counters(void) {
  printf("tx=%lu rx=%lu bad=%lu rebuilt=%lu gso=%lu\n", GET(ntx), GET(nrx), GET(nbad), GET(nrebuilt), GET(ngso));
  fflush(stdout);
}

// --derive-key "<a>,<b>": read a passphrase from stdin and write a 32-byte key to stdout. The salt is
// BLAKE2b of the two comma-separated tokens sorted, so both ends derive the same key from the same
// passphrase and the same IP pair in either order, with nothing transferred between them.
static int derive_key(const char *salt_arg) {
  char buf[256];
  snprintf(buf, sizeof buf, "%s", salt_arg);
  char *comma = strchr(buf, ','), salt_str[600];
  if (comma) {  // sort the two tokens so "a,b" and "b,a" hash the same
    *comma = 0;
    const char *x = buf, *y = comma + 1;
    if (strcmp(x, y) > 0) { const char *t = x; x = y; y = t; }
    snprintf(salt_str, sizeof salt_str, "%s,%s", x, y);
  } else {
    snprintf(salt_str, sizeof salt_str, "%s", salt_arg);
  }
  uint8_t pass[1024];
  size_t plen = 0;
  ssize_t r;
  while (plen < sizeof pass && (r = read(0, pass + plen, sizeof pass - plen)) > 0) plen += r;
  while (plen && (pass[plen - 1] == '\n' || pass[plen - 1] == '\r')) plen--;  // drop a trailing newline
  if (!plen) { fprintf(stderr, "golden-gre-relay: empty passphrase on stdin\n"); return 1; }
  uint8_t salt[16];
  crypto_blake2b(salt, sizeof salt, (const uint8_t *)salt_str, strlen(salt_str));
  uint32_t blocks = 65536;  // 64 MiB, 3 passes: one-time at setup, cheap to verify, costly to brute-force
  void *work = malloc((size_t)blocks * 1024);
  if (!work) die("malloc");
  uint8_t out[32];
  crypto_argon2(out, sizeof out, work,
                (crypto_argon2_config){CRYPTO_ARGON2_I, blocks, 3, 1},
                (crypto_argon2_inputs){pass, salt, (uint32_t)plen, sizeof salt},
                crypto_argon2_no_extras);
  crypto_wipe(pass, sizeof pass);
  free(work);
  if (write(1, out, sizeof out) != (ssize_t)sizeof out) { crypto_wipe(out, sizeof out); return 1; }
  crypto_wipe(out, sizeof out);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 3 && !strcmp(argv[1], "--derive-key")) return derive_key(argv[2]);
  const char *facade = NULL, *bind_ip = NULL, *peer_ip = NULL, *local = NULL, *reply_arg = NULL, *fec_arg = NULL;
  const char *gso_arg = "on", *rotate_arg = NULL, *port_arg = "53", *rate_arg = NULL, *keyfile = NULL;
  for (int i = 1; i + 1 < argc; i += 2) {
    if (!strcmp(argv[i], "--facade")) facade = argv[i + 1];
    else if (!strcmp(argv[i], "--keyfile")) keyfile = argv[i + 1];
    else if (!strcmp(argv[i], "--bind")) bind_ip = argv[i + 1];
    else if (!strcmp(argv[i], "--peer")) peer_ip = argv[i + 1];
    else if (!strcmp(argv[i], "--local")) local = argv[i + 1];
    else if (!strcmp(argv[i], "--reply")) reply_arg = argv[i + 1];
    else if (!strcmp(argv[i], "--port")) port_arg = argv[i + 1];
    else if (!strcmp(argv[i], "--itype")) itype = atoi(argv[i + 1]);
    else if (!strcmp(argv[i], "--fec")) fec_arg = argv[i + 1];
    else if (!strcmp(argv[i], "--gso")) gso_arg = argv[i + 1];
    else if (!strcmp(argv[i], "--rotate")) rotate_arg = argv[i + 1];
    else if (!strcmp(argv[i], "--rate")) rate_arg = argv[i + 1];
  }
  if (!facade || !bind_ip || !peer_ip || !local || (strcmp(facade, "dns") && strcmp(facade, "icmp")) ||
      (strcmp(gso_arg, "on") && strcmp(gso_arg, "off"))) {
    fprintf(stderr, "usage: %s --facade dns|icmp --bind IP --peer IP --local IP:PORT [--reply IP:PORT] [--port 53,853,...] [--itype 0] [--fec K:M] [--gso on|off] [--rotate N] [--rate N] [--keyfile PATH]\n", argv[0]);
    return 1;
  }
  if (rotate_arg) {
    rotate = atoi(rotate_arg);
    if (rotate < 0 || rotate > 64) {
      fprintf(stderr, "--rotate needs 0..64 frames per source port (0 keeps a single port)\n");
      return 1;
    }
  }
  if (rate_arg) {
    rate = atoi(rate_arg);
    if (rate < 0 || rate > 200000) {
      fprintf(stderr, "--rate needs 0..200000 frames per second (0 keeps it unlimited)\n");
      return 1;
    }
  }
  token_ts = now_ms();
  if (fec_arg && (sscanf(fec_arg, "%d:%d", &fec_k, &fec_m) != 2 || fec_k < 1 || fec_k > KMAX || fec_m < 1 || fec_m > MMAX)) {
    fprintf(stderr, "--fec needs K:M with 1 <= K, M <= %d\n", KMAX);
    return 1;
  }
  gf_init();
  gf_pick();
  memcpy(cur_question, QUESTION, sizeof cur_question);
  if (keyfile) {
    int fd = open(keyfile, O_RDONLY);
    if (fd < 0) die("open keyfile");
    uint8_t extra;
    if (read(fd, key, sizeof key) != (ssize_t)sizeof key || read(fd, &extra, 1) != 0) {
      fprintf(stderr, "golden-gre-relay: keyfile %s must be exactly 32 bytes\n", keyfile);
      return 1;
    }
    close(fd);
    keyed = 1;
    rng_seed();
    if (getrandom(nonce_base, sizeof nonce_base, 0) != (ssize_t)sizeof nonce_base) die("getrandom");
    uint8_t p0[8] = "goldengr", c0[8], t0[TAG], o0[8], z0[NONCE] = {0};  // KAT: a miscompiled AEAD must not ship
    crypto_aead_lock(c0, t0, key, z0, NULL, 0, p0, sizeof p0);
    if (crypto_aead_unlock(o0, t0, key, z0, NULL, 0, c0, sizeof c0) || memcmp(p0, o0, sizeof p0))
      die("AEAD self-test failed");
    randomize_question();
    cur_ident = (unsigned)(xrng() & 0xFFFF);
    if (cur_ident == IDENT) cur_ident ^= 1;  // never emit the legacy constant id by chance
  }
  // a random first block number, so the peer cannot mistake a restarted sender's blocks for old ones
  if (getrandom(&enc.id, sizeof enc.id, 0) != sizeof enc.id) enc.id = (uint32_t)now_ms();
  is_dns = !strcmp(facade, "dns");
  if (rotate && !is_dns) die("--rotate is only for the dns facade");
  if (!is_dns && itype != 0 && itype != 8) die("--itype must be 0 (echo reply) or 8 (echo request)");
  use_gso = is_dns && !strcmp(gso_arg, "on");
  // stop on SIGTERM/SIGINT after printing the counters (without SA_RESTART, so poll returns at once)
  struct sigaction sa = {.sa_handler = on_stop};
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  char lip[64];
  snprintf(lip, sizeof lip, "%s", local);
  char *colon = strrchr(lip, ':');
  if (!colon) die("--local needs ip:port");
  *colon = 0;

  loc = udp_socket(mkaddr(lip, atoi(colon + 1)));
  if (is_dns) {
    char plist[256];
    snprintf(plist, sizeof plist, "%s", port_arg);
    nports = 0;
    for (char *tok = strtok(plist, ", \t"); tok; tok = strtok(NULL, ", \t")) {
      char *end;
      long p = strtol(tok, &end, 10);
      if (*end || p < 1 || p > 65535 || nports == MAX_PORTS)
        die("--port wants 1..65535, comma or space separated, at most 8 ports");
      rxs[nports] = udp_socket(mkaddr(bind_ip, (int)p));
      peers[nports] = mkaddr(peer_ip, (int)p);
      nports++;
    }
    if (!nports) die("--port wants at least one port");
    tx_bind = mkaddr(bind_ip, 0);
    tx = udp_socket(tx_bind);
    peer_i = 0;
    peer = peers[0];
  } else {
    rxs[0] = tx = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (rxs[0] < 0) die("raw socket (root needed)");
    struct sockaddr_in b = mkaddr(bind_ip, 0);
    if (bind(rxs[0], (struct sockaddr *)&b, sizeof b) < 0) die("bind");
    int big = 4 << 20;
    setsockopt(rxs[0], SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    setsockopt(rxs[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    peer = mkaddr(peer_ip, 0);
    // A raw socket gets a copy of every ICMP packet to its address, so with several tunnels on one public
    // address every relay would also wake for the others' traffic. Let the kernel keep only the peer's.
    struct sock_filter only_peer[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 12),  // IPv4 source address
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ntohl(peer.sin_addr.s_addr), 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 0xffffffff),
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    struct sock_fprog prog = {(unsigned short)(sizeof only_peer / sizeof only_peer[0]), only_peer};
    if (setsockopt(rxs[0], SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof prog) < 0) die("SO_ATTACH_FILTER");
  }

  peer_addr = peer.sin_addr.s_addr;
  if (reply_arg) {
    char rip[64];
    snprintf(rip, sizeof rip, "%s", reply_arg);
    char *rcolon = strrchr(rip, ':');
    if (!rcolon) die("--reply needs ip:port");
    *rcolon = 0;
    struct sockaddr_in r = mkaddr(rip, atoi(rcolon + 1));
    set_reply(&r);
  }
  char rot[64] = "";
  if (rotate) snprintf(rot, sizeof rot, ", rotate %d", rotate);
  if (nports > 1) snprintf(rot + strlen(rot), sizeof rot - strlen(rot), ", %d ports", nports);
  if (rate) snprintf(rot + strlen(rot), sizeof rot - strlen(rot), ", rate %d", rate);
  printf("golden-gre-relay up: %s %s <-> %s, local %s, fec %s, gso %s, gf %s, enc %s%s%s\n", facade, bind_ip, peer_ip, local,
         fec_arg ? fec_arg : "off", use_gso ? "on" : "off", gf_impl, keyed ? "xchacha20-poly1305" : "off",
         is_dns ? "" : itype ? ", itype 8" : ", itype 0", rot);
  fflush(stdout);

  pthread_t out_thread, in_thread;
  if ((errno = pthread_create(&out_thread, NULL, local_to_wire, NULL)) ||
      (errno = pthread_create(&in_thread, NULL, wire_to_local, NULL)))
    die("pthread_create");
  pthread_setname_np(out_thread, "relay-out");
  pthread_setname_np(in_thread, "relay-in");
  for (time_t next = time(NULL) + 60; !GET(stopping);) {
    sleep(1);
    if (time(NULL) >= next) {
      print_counters();
      next += 60;
    }
  }
  pthread_join(out_thread, NULL);
  pthread_join(in_thread, NULL);
  print_counters();
  return 0;
}
