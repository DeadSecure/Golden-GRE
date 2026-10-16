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
// icmp: ICMP messages of --itype (0 = unsolicited echo reply, so no kernel answers it); needs root.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
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
#define MAXPAY (BUF - HEAD - FEC_HDR - 2)  // largest tunnel packet; parity carries a 2-byte length too
#define GSO_MAX 32       // frames per UDP GSO send (the kernel allows 64 on older versions)
#define GSO_BYTES 60000  // and bytes per send (one UDP datagram before segmentation)
#define GSO_FRAME 1472   // frames above this would not fit a 1500-byte MTU unfragmented: sent alone

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

static const uint8_t QUESTION[16] = {5, 'p', 'r', 'o', 'b', 'e', 4, 't', 'e', 's', 't', 0, 0, 16, 0, 1};

// receive batches, one per direction: each direction runs in its own thread
struct batch {
  uint8_t bufs[BATCH][BUF];
  struct sockaddr_in names[BATCH];
  struct iovec iov[BATCH];
  struct mmsghdr msgs[BATCH];
};
static struct batch from_local, from_wire;

static int is_dns, itype, tx, rx, loc;
static struct sockaddr_in peer;
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
  memcpy(h + 12, QUESTION, sizeof QUESTION);
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
  put16(h + 4, IDENT);
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
    if (sent > 0) ADD(ntx, sent);
    nw = 0;
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
      if (rest > 0) ADD(ntx, rest);
    }
    break;  // anything else (a full socket buffer): drop the rest, as a plain send would
  }
  nw = 0;
}

// queue the frame a || b, wrapped in the facade
static void wire_emit(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) {
  uint8_t *p = wbuf[nw] + HEAD;
  size_t len = alen + blen, hdr = is_dns ? DNS_HDR : ICMP_HDR;
  if (alen) memcpy(p, a, alen);
  memcpy(p + alen, b, blen);
  seq++;
  if (is_dns) dns_head(p - hdr, seq, len);
  else icmp_head(p - hdr, itype, seq, len);
  wiov[nw] = (struct iovec){p - hdr, hdr + len};
  wmsg[nw].msg_hdr = (struct msghdr){.msg_name = &peer, .msg_namelen = sizeof peer, .msg_iov = &wiov[nw], .msg_iovlen = 1};
  if (++nw == OUTQ) wire_flush();
}

static void local_flush(void) {
  if (!nl) return;
  int sent = sendmmsg(loc, lmsg, nl, 0);
  if (sent > 0) ADD(nrx, sent);
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
  struct pollfd pf = {rx, POLLIN, 0};
  (void)arg;
  while (!GET(stopping)) {
    if (poll(&pf, 1, 1000) <= 0 || !(pf.revents & POLLIN)) continue;
    recv_setup(b, BUF);
    int n = recvmmsg(rx, b->msgs, BATCH, MSG_DONTWAIT, NULL);
    if (n <= 0 || !get_reply(&reply)) continue;  // nothing reaches the tunnel before its address is known
    for (int i = 0; i < n; i++) {
      uint8_t *p = b->bufs[i];
      size_t len = b->msgs[i].msg_len;
      if (b->names[i].sin_addr.s_addr != peer.sin_addr.s_addr) continue;
      if (is_dns) {
        if (len <= DNS_HDR || memcmp(p + 12, QUESTION, sizeof QUESTION)) { ADD(nbad, 1); continue; }
        p += DNS_HDR;
        len -= DNS_HDR;
      } else {
        size_t ihl = (p[0] & 15) * 4;
        if (len <= ihl + ICMP_HDR || p[ihl] != itype || ((p[ihl + 4] << 8) | p[ihl + 5]) != IDENT) { ADD(nbad, 1); continue; }
        p += ihl + ICMP_HDR;
        len -= ihl + ICMP_HDR;
      }
      if (p[0] == FEC_MAGIC) fec_input(p, len);
      else local_emit(p, len);
    }
    local_flush();
  }
  return NULL;
}

static void print_counters(void) {
  printf("tx=%lu rx=%lu bad=%lu rebuilt=%lu gso=%lu\n", GET(ntx), GET(nrx), GET(nbad), GET(nrebuilt), GET(ngso));
  fflush(stdout);
}

int main(int argc, char **argv) {
  const char *facade = NULL, *bind_ip = NULL, *peer_ip = NULL, *local = NULL, *reply_arg = NULL, *fec_arg = NULL;
  const char *gso_arg = "on";
  int port = 53;
  for (int i = 1; i + 1 < argc; i += 2) {
    if (!strcmp(argv[i], "--facade")) facade = argv[i + 1];
    else if (!strcmp(argv[i], "--bind")) bind_ip = argv[i + 1];
    else if (!strcmp(argv[i], "--peer")) peer_ip = argv[i + 1];
    else if (!strcmp(argv[i], "--local")) local = argv[i + 1];
    else if (!strcmp(argv[i], "--reply")) reply_arg = argv[i + 1];
    else if (!strcmp(argv[i], "--port")) port = atoi(argv[i + 1]);
    else if (!strcmp(argv[i], "--itype")) itype = atoi(argv[i + 1]);
    else if (!strcmp(argv[i], "--fec")) fec_arg = argv[i + 1];
    else if (!strcmp(argv[i], "--gso")) gso_arg = argv[i + 1];
  }
  if (!facade || !bind_ip || !peer_ip || !local || (strcmp(facade, "dns") && strcmp(facade, "icmp")) ||
      (strcmp(gso_arg, "on") && strcmp(gso_arg, "off"))) {
    fprintf(stderr, "usage: %s --facade dns|icmp --bind IP --peer IP --local IP:PORT [--reply IP:PORT] [--port 53] [--itype 0] [--fec K:M] [--gso on|off]\n", argv[0]);
    return 1;
  }
  if (fec_arg && (sscanf(fec_arg, "%d:%d", &fec_k, &fec_m) != 2 || fec_k < 1 || fec_k > KMAX || fec_m < 1 || fec_m > MMAX)) {
    fprintf(stderr, "--fec needs K:M with 1 <= K, M <= %d\n", KMAX);
    return 1;
  }
  gf_init();
  gf_pick();
  // a random first block number, so the peer cannot mistake a restarted sender's blocks for old ones
  if (getrandom(&enc.id, sizeof enc.id, 0) != sizeof enc.id) enc.id = (uint32_t)now_ms();
  is_dns = !strcmp(facade, "dns");
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
    rx = udp_socket(mkaddr(bind_ip, port));
    tx = udp_socket(mkaddr(bind_ip, 0));
    peer = mkaddr(peer_ip, port);
  } else {
    rx = tx = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (rx < 0) die("raw socket (root needed)");
    struct sockaddr_in b = mkaddr(bind_ip, 0);
    if (bind(rx, (struct sockaddr *)&b, sizeof b) < 0) die("bind");
    int big = 4 << 20;
    setsockopt(rx, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    setsockopt(rx, SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
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
    if (setsockopt(rx, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof prog) < 0) die("SO_ATTACH_FILTER");
  }

  if (reply_arg) {
    char rip[64];
    snprintf(rip, sizeof rip, "%s", reply_arg);
    char *rcolon = strrchr(rip, ':');
    if (!rcolon) die("--reply needs ip:port");
    *rcolon = 0;
    struct sockaddr_in r = mkaddr(rip, atoi(rcolon + 1));
    set_reply(&r);
  }
  printf("golden-gre-relay up: %s %s <-> %s, local %s, fec %s, gso %s, gf %s\n", facade, bind_ip, peer_ip, local,
         fec_arg ? fec_arg : "off", use_gso ? "on" : "off", gf_impl);
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
