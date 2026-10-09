// golden-gre-relay: carry a tunnel's UDP packets between two servers inside a disguise that a filtered
// IPv4 path lets through. The tunnel (GRE-in-FOU on loopback) sends its packets to --local; each one is
// wrapped and sent to the peer's relay, which unwraps it and hands it to its own tunnel: to --reply if
// given (the tunnel's FOU address), else to the sender of the last local packet, which means nothing
// reaches the tunnel until the tunnel has sent something. Batches with recvmmsg/sendmmsg.
//
// FEC: with --fec K:M the relay follows every K tunnel packets with M Reed-Solomon parity packets (a
// block that is still short FLUSH_MS after its first packet gets proportionally fewer), so the peer can
// rebuild up to M lost packets of the block without waiting a round trip for TCP to resend them. Data
// packets are never held back. Only the sending side needs the flag: every relay decodes FEC frames and
// still accepts plain ones, so turn it on for the direction that loses packets.
//
//   gcc -O2 -Wall -o golden-gre-relay golden-gre-relay.c
//   golden-gre-relay --facade dns|icmp --bind <public_ip> --peer <peer_ip> --local <ip:port>
//                    [--reply <ip:port>] [--port 53] [--itype 0] [--fec K:M]
//
// dns:  UDP from an ephemeral port to <peer>:53, framed as a DNS query (one question, EDNS0 OPT record
//       whose RDATA is the payload); listens on <bind>:53 (--port).
// icmp: ICMP messages of --itype (0 = unsolicited echo reply, so no kernel answers it); needs root.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static const uint8_t QUESTION[16] = {5, 'p', 'r', 'o', 'b', 'e', 4, 't', 'e', 's', 't', 0, 0, 16, 0, 1};

static uint8_t bufs[BATCH][BUF];
static struct sockaddr_in names[BATCH];
static struct iovec iov[BATCH];
static struct mmsghdr msgs[BATCH];

static int is_dns, itype, tx, loc;
static struct sockaddr_in peer, reply;
static unsigned seq;
static unsigned long ntx, nrx, nbad, nrebuilt;

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

static void wire_flush(void) {
  if (!nw) return;
  int sent = sendmmsg(tx, wmsg, nw, 0);
  if (sent > 0) ntx += sent;
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
  if (sent > 0) nrx += sent;
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

static uint8_t gexp[512], glog[256], gmul[256][256];

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
}

static uint8_t ginv(uint8_t a) { return gexp[255 - glog[a]]; }

static uint8_t coef(int j, int i) { return ginv((uint8_t)((0x80 | j) ^ i)); }

static void muladd(uint8_t *dst, const uint8_t *src, uint8_t c, size_t n) {  // dst += c * src
  const uint8_t *row = gmul[c];
  for (size_t x = 0; x < n; x++) dst[x] ^= row[src[x]];
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

// sender
static int fec_k, fec_m;
static struct {
  uint32_t id;
  int k;
  size_t len[KMAX], maxlen;
  uint8_t data[KMAX][MAXPAY];
  uint64_t start;
} enc;

static void fec_flush(void) {  // send the current block's parity and start the next block
  static uint8_t par[2 + MAXPAY];
  uint8_t h[FEC_HDR];
  int k = enc.k, m = (fec_m * k + fec_k - 1) / fec_k;
  size_t L = 2 + enc.maxlen;
  for (int j = 0; j < m; j++) {
    memset(par, 0, L);
    for (int i = 0; i < k; i++) muladd_vec(par, enc.data[i], enc.len[i], coef(j, i));
    fec_head(h, enc.id, 0x80 | j, k);
    wire_emit(h, FEC_HDR, par, L);
  }
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
  memcpy(enc.data[enc.k], p, len);
  enc.len[enc.k] = len;
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
    if (p == e) { nbad++; return; }
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
    if (n > s->L - 2) { nbad++; continue; }
    local_emit(d + 2, n);
    nrebuilt++;
  }
  s->done = 1;
}

static void fec_input(const uint8_t *p, size_t len) {
  if (len < FEC_HDR) { nbad++; return; }
  uint32_t id = (uint32_t)p[1] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 8 | p[4];
  int idx = p[5], k = p[6], par = idx & 0x80, j = idx & 0x7F;
  const uint8_t *body = p + FEC_HDR;
  size_t blen = len - FEC_HDR;
  if (par ? j >= MMAX || k < 1 || k > KMAX || blen < 2 || blen > 2 + MAXPAY : idx >= KMAX || blen > MAXPAY) {
    nbad++;
    return;
  }
  struct slot *s = &slots[id % NSLOT];
  if (!s->used || s->id != id) {
    if (s->used && (int32_t)(id - s->id) < 0) {  // late packet of a block whose slot is reused
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
    if (s->k && (s->k != k || s->L != blen)) { nbad++; return; }
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

int main(int argc, char **argv) {
  const char *facade = NULL, *bind_ip = NULL, *peer_ip = NULL, *local = NULL, *reply_arg = NULL, *fec_arg = NULL;
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
  }
  if (!facade || !bind_ip || !peer_ip || !local || (strcmp(facade, "dns") && strcmp(facade, "icmp"))) {
    fprintf(stderr, "usage: %s --facade dns|icmp --bind IP --peer IP --local IP:PORT [--reply IP:PORT] [--port 53] [--itype 0] [--fec K:M]\n", argv[0]);
    return 1;
  }
  if (fec_arg && (sscanf(fec_arg, "%d:%d", &fec_k, &fec_m) != 2 || fec_k < 1 || fec_k > KMAX || fec_m < 1 || fec_m > MMAX)) {
    fprintf(stderr, "--fec needs K:M with 1 <= K, M <= %d\n", KMAX);
    return 1;
  }
  gf_init();
  is_dns = !strcmp(facade, "dns");
  char lip[64];
  snprintf(lip, sizeof lip, "%s", local);
  char *colon = strrchr(lip, ':');
  if (!colon) die("--local needs ip:port");
  *colon = 0;

  loc = udp_socket(mkaddr(lip, atoi(colon + 1)));
  int rx;
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
  }

  int have_reply = 0;
  if (reply_arg) {
    char rip[64];
    snprintf(rip, sizeof rip, "%s", reply_arg);
    char *rcolon = strrchr(rip, ':');
    if (!rcolon) die("--reply needs ip:port");
    *rcolon = 0;
    reply = mkaddr(rip, atoi(rcolon + 1));
    have_reply = 1;
  }
  time_t next = time(NULL) + 60;
  struct pollfd pf[2] = {{loc, POLLIN, 0}, {rx, POLLIN, 0}};
  printf("golden-gre-relay up: %s %s <-> %s, local %s, fec %s\n", facade, bind_ip, peer_ip, local, fec_arg ? fec_arg : "off");
  fflush(stdout);

  for (;;) {
    int wait = 1000;
    if (enc.k) {
      uint64_t age = now_ms() - enc.start;
      wait = age >= FLUSH_MS ? 0 : (int)(FLUSH_MS - age);
    }
    poll(pf, 2, wait);
    if (pf[0].revents & POLLIN) {  // local tunnel endpoint -> wire
      for (int i = 0; i < BATCH; i++) {
        iov[i] = (struct iovec){bufs[i], MAXPAY};
        msgs[i].msg_hdr = (struct msghdr){.msg_name = &names[i], .msg_namelen = sizeof names[i], .msg_iov = &iov[i], .msg_iovlen = 1};
      }
      int n = recvmmsg(loc, msgs, BATCH, MSG_DONTWAIT, NULL);
      for (int i = 0; i < n; i++) {
        reply = names[i];
        have_reply = 1;
        if (msgs[i].msg_hdr.msg_flags & MSG_TRUNC) { nbad++; continue; }
        send_tunnel_packet(bufs[i], msgs[i].msg_len);
      }
      wire_flush();
    }
    if (enc.k && now_ms() - enc.start >= FLUSH_MS) {
      fec_flush();
      wire_flush();
    }
    if (pf[1].revents & POLLIN) {  // wire -> local tunnel endpoint
      for (int i = 0; i < BATCH; i++) {
        iov[i] = (struct iovec){bufs[i], BUF};
        msgs[i].msg_hdr = (struct msghdr){.msg_name = &names[i], .msg_namelen = sizeof names[i], .msg_iov = &iov[i], .msg_iovlen = 1};
      }
      int n = recvmmsg(rx, msgs, BATCH, MSG_DONTWAIT, NULL);
      for (int i = 0; i < n && have_reply; i++) {
        uint8_t *p = bufs[i];
        size_t len = msgs[i].msg_len;
        if (names[i].sin_addr.s_addr != peer.sin_addr.s_addr) continue;
        if (is_dns) {
          if (len <= DNS_HDR || memcmp(p + 12, QUESTION, sizeof QUESTION)) { nbad++; continue; }
          p += DNS_HDR;
          len -= DNS_HDR;
        } else {
          size_t ihl = (p[0] & 15) * 4;
          if (len <= ihl + ICMP_HDR || p[ihl] != itype || ((p[ihl + 4] << 8) | p[ihl + 5]) != IDENT) { nbad++; continue; }
          p += ihl + ICMP_HDR;
          len -= ihl + ICMP_HDR;
        }
        if (p[0] == FEC_MAGIC) fec_input(p, len);
        else local_emit(p, len);
      }
      local_flush();
    }
    if (time(NULL) >= next) {
      printf("tx=%lu rx=%lu bad=%lu rebuilt=%lu\n", ntx, nrx, nbad, nrebuilt);
      fflush(stdout);
      next += 60;
    }
  }
}
