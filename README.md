<p align="center">
  <img src="docs/banner.svg" alt="Golden GRE" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/License-Apache_2.0-FFD700?style=for-the-badge&labelColor=1a1a1a" alt="Apache 2.0 License">
  <img src="https://img.shields.io/badge/Bash-Linux-DAA520?style=for-the-badge&logo=gnubash&logoColor=black&labelColor=1a1a1a" alt="Bash">
  <img src="https://img.shields.io/badge/systemd-managed-B8860B?style=for-the-badge&labelColor=1a1a1a" alt="systemd">
  <img src="https://img.shields.io/badge/TCP-BBR-FFC72C?style=for-the-badge&labelColor=1a1a1a" alt="BBR">
  <img src="https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-D4AF37?style=for-the-badge&logo=ubuntu&logoColor=black&labelColor=1a1a1a" alt="Ubuntu">
</p>

<p align="center">
  <a href="https://github.com/LivingG0D/Golden-GRE/actions/workflows/ci.yml"><img src="https://github.com/LivingG0D/Golden-GRE/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

<h3 align="center">🥇 GRE tunnels for IPv4 paths that cut every other tunnel. GRE rides inside a relay that makes it look like ping replies or DNS queries.</h3>

<p align="center"><i>A real <code>greN</code> interface between two Linux servers, managed by systemd, set up with one command. Measured at 500–690 Mbit/s Iran–Kharej.</i></p>

## 💛 Donate

If Golden GRE helps you, you can support it:

| Network | Address |
|---------|---------|
| TRON (TRX) | `TR3pJMPvNdACK2oNNgjyyDTPrzCvkoGg4L` |
| USDT (BEP20) | `0xd360aEb1A32adcc3d5E1dFc043d68650C136D6D5` |
| GRAM | `UQCeLZhcJUwY-7ymm1ZESdj1so91LGJNVcAG_KzGvZUnBOgR` |

---

## ✨ Why

Some IPv4 paths between countries **cut every flow after the first few packets**: GRE, FOU, WireGuard, VXLAN, QUIC and plain TCP tunnels all come up and then go silent. One measured path let through only ICMP and UDP/53 carrying a valid DNS message ([docs/FILTER.md](docs/FILTER.md)).

Golden GRE keeps GRE as the tunnel and carries it through a small relay that disguises each packet as an **ICMP echo request**, an **ICMP echo reply** or a **DNS query**. To the path it is ping or DNS; to your routing table it is a point-to-point link. Around that it adds BBR tuning, forwarding and MSS clamping, optional FEC, port forwarding, a health check, and a menu.

| Path | `dns` disguise | `icmp` disguise |
|------|----------------|-----------------|
| Iran–Kharej 1 | passes, 140–160 Mbit/s | passes, slower (heavy reordering at high rates) |
| Iran–Kharej 2 | **cut after 6 packets per flow** | passes, 500–690 Mbit/s |
| Iran–Kharej 3 | **cut after a few packets** | echo replies from Iran **dropped** (requests pass): use ICMP requests |

---

## ⚡ Install (one line)

On **both** servers, as root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/LivingG0D/Golden-GRE/main/golden-gre.sh)
```

It installs missing packages, builds Golden GRE, and asks:

1. **Server 1's IP and server 2's IP.** Type the same two on both servers, in any order. The script works out which end it is on and gives both ends the same GRE key and /30.
2. **Disguise:** Enter for ICMP requests (the default), 2 for DNS, 3 for ICMP replies (what tunnels made before ICMP requests use), 4 for none (plain GRE, no relay: fastest, but only where the path does not cut GRE). Same on both servers.

FEC starts off; turn it on later in **Manage tunnels → FEC** if the path loses packets ([FEC](#-fec-for-lossy-paths)).

Both servers print a **pair check** (key, subnet, disguise) that must match. When the second server finishes, it pings the first through the tunnel. Later, `golden-gre` opens the menu: new tunnel, manage tunnels (status with live ping, start/stop/restart, disguise, FEC, port forwarding, delete), live logs, update, uninstall.

- Not root? Run `sudo -i` first: `sudo bash <(…)` does not work. Use `bash <(…)`, not `curl … | bash`.
- Behind 1:1 NAT (AWS, GCP, Oracle)? Type the **public** IPs; the script asks which server it is on.
- The provider firewall must let in ICMP (UDP 53 for DNS, GRE for none) from the other server.
- Ping answers a few times, then stops? The path cuts that disguise: switch **both** servers in **Manage tunnels → Disguise**.
- No GitHub access on the server? Copy a clone over and run `sudo ./golden-gre.sh` inside it.

Each tunnel is named after its peer: `golden-gre@<peer IP>`, config `/etc/golden-gre/<peer IP>.conf`.

**Several destinations from one server:** run **New tunnel** again with the other peer's IP. Any number of ICMP tunnels can share this server's public IP; each relay gets only its own peer's packets from the kernel. A DNS tunnel needs the IP's UDP port 53 to itself, so there can be one DNS tunnel per IP next to the ICMP ones.

---

## 🛠 How it works

```text
your packet ─► gre1 (GRE + key) ─► FOU on loopback ─► relay ─► wire: ICMP echo reply or DNS query to :53 ─► peer relay ─► FOU ─► gre1
```

`golden-gre-up.sh` builds a `greN` device whose peer is loopback (GRE in FOU, sent to the local relay). `golden-gre-relay`, the systemd unit's main process, wraps each datagram in the disguise and sends it to the peer's relay, which checks the source address and shape, unwraps it and hands it back to the kernel. Overhead is 36 bytes with `icmp` and 75 with `dns`.

With `FACADE=none` (no disguise) there is no relay and no FOU: `greN` is plain GRE between the two public IPs, 28 bytes of overhead, and the unit's main process only waits.

---

## 🚀 Manual setup

```bash
# on both servers
git clone https://github.com/LivingG0D/Golden-GRE.git && cd Golden-GRE && sudo ./install.sh

# server 1 (server 2: swap the addresses and use 10.99.99.2/30)
sudo tee /etc/golden-gre/link.conf >/dev/null <<'EOF'
DEV=gre1
LOCAL_PUB=203.0.113.10
REMOTE_PUB=198.51.100.20
TUN_ADDR=10.99.99.1/30
FACADE=icmp
ICMP_TYPE=8
EOF
sudo systemctl enable --now golden-gre@link
ping 10.99.99.2
```

`install.sh` is idempotent. It needs `gcc` (to build the relay), `iproute2`, `iptables`, `ethtool` and the `fou` and `ip_gre` modules. It installs the scripts to `/usr/local/sbin`, the `golden-gre@` and `golden-gre-check@` units, and BBR/`fq`/buffer/`ip_forward` tuning in `/etc/sysctl.d/99-golden-gre.conf`. It starts no tunnel by itself.

### Configuration

One file per tunnel, `/etc/golden-gre/<name>.conf`:

| Key | Default | Meaning |
|-----|---------|---------|
| `DEV` | required | Tunnel device, unique per host. |
| `LOCAL_PUB` | required | This server's IPv4 address (the relay binds it). Shared by any number of icmp tunnels; one dns tunnel per address. |
| `REMOTE_PUB` | required | Peer's public IPv4 address. |
| `TUN_ADDR` | required | This end's overlay address, e.g. `10.99.99.1/30`. |
| `FACADE` | `dns` | `icmp`, `dns`, or `none` (plain GRE, no relay; `FEC`, `SPORT_ROTATE` and `RATE` do not apply). Same on both ends. The one-line setup writes `icmp`. |
| `ICMP_TYPE` | `0` | icmp only: `8` sends echo requests, `0` echo replies. Same on both ends. The one-line setup writes `8`. With `8`, this server stops answering pings from the peer's public IP (the kernel's replies would double the traffic). |
| `SPORT_ROTATE` | off | dns only: reopen the sending socket every N frames, so each source port carries at most N; a fresh source port is a fresh flow on a path that allows only the first few packets of each. Set it on the sending end. |
| `RATE` | off | dns only: cap on frames per second put on the wire (a token bucket with a short burst allowed). Keeps sustained churn under what a filtering path accepts, so the tunnel stays smooth where an uncapped one gets clamped. Set it on the sending end. |
| `MTU` | `1380` | If the path carries 1500-byte packets (`ping -M do -s 1472 <peer>` answers), use `1464` for icmp, `1425` for dns or `1472` for none. |
| `GRE_KEY` | `41` | Same on both ends; different per tunnel on a host. |
| `FEC` | off | `K:M`: M parity packets per K on what this end sends. |
| `KEYFILE` | off | Path to a 32-byte pre-shared key. The **same** key on both ends encrypts the payload with XChaCha20-Poly1305 and replaces the fixed `dns`/`icmp` markers with random ones, so the wire carries no constant signature. `golden-gre` setup offers this and derives the key from a passphrase you type on both servers (no key copied between them); or make one by hand with `head -c32 /dev/urandom > KEYFILE && chmod 600 KEYFILE` and copy it to the peer. Unset = plaintext with fixed markers. |
| `FORWARD` | none | Ports to forward to the peer, comma- or space-separated: `"443,1080,2053:2096,8080=80"`. |
| `ROUTES` | none | CIDRs to route via the tunnel. |
| `NAT_SRC` / `NAT_OUT` | none | MASQUERADE this source out an interface (use the node as an exit). |
| `FOU_PORT` / `RELAY_PORT` | `5599` / `5601` | Loopback ports, unique per tunnel on a host. |
| `DNS_PORT` / `DNS_PORTS` | `53` | UDP port(s) for the `dns` disguise. `DNS_PORTS` takes a comma- or space-separated list (up to 8); several ports multiply the flows a rotating sender gets before it has to reuse one. Same list on both ends. |
| `PEER_ADDR` | derived | Peer's overlay address, if `TUN_ADDR` is not a /30 or /31. |

### Managing

```bash
systemctl enable --now golden-gre@link     # start, and on every boot
systemctl restart golden-gre@link
systemctl disable --now golden-gre@link    # stop for good
journalctl -u golden-gre@link -f           # relay logs tx/rx/bad/rebuilt once a minute
golden-gre-preflight link                  # check host and config before starting
systemctl enable golden-gre-check@link.timer   # ping the peer every minute; a dead tunnel shows in systemctl --failed
```

---

## 🔀 Port forwarding

Clients connect to the Iran server's public IP; the service runs on the Kharej server. On the Iran server: **Manage tunnels → tunnel → Port forwarding → Add ports**, or in its config:

```bash
FORWARD="443,1080,2087,2053:2096,8080=80"   # same ports on the peer, a range, 8080 -> peer 80; TCP and UDP
```

It is kernel NAT (a DNAT per entry plus a MASQUERADE on the tunnel), so it adds no CPU beyond the tunnel. The rules follow the tunnel and are removed on stop.

- Port 22 is refused; the menu also refuses the real SSH port and warns before taking a port a local program uses.
- Traffic from the peer's own address is never forwarded.
- The service on the peer must listen on `0.0.0.0` or its tunnel address, and sees clients as this end's tunnel address. With ufw on the peer: `ufw allow in on gre1`.
- Running UDP flows keep their old path until idle. Earlier `nat` PREROUTING rules (Docker, port hopping) win over these.

---

## 🧯 FEC for lossy paths

`FEC=K:M` sends M Reed-Solomon parity packets after every K, so the peer rebuilds up to M lost packets per block without a retransmit. Set it on the end that **sends into** the lossy direction; the peer decodes without any setting. It costs M/K extra bandwidth.

On a path losing 7–22% into Iran, single TCP downloads went from 7 Mbit/s to 250–288 with `10:5`. Too little parity (`10:3`) did nothing. On a path with ~1% loss, `20:2` rebuilt packets but did not raise throughput: FEC fixes loss, not every slow path.

---

## 📊 Performance

| Iran–Kharej 2 (79 ms, icmp, 1-vCPU server abroad) | Result |
|------|--------|
| TCP upload / download, 1 flow | 512–558 / 520–691 Mbit/s |
| TCP download, 60 s | ~606 Mbit/s average |
| UDP at 100 Mbit/s | 0–0.08% loss |

On Iran–Kharej 1 (DNS disguise): 138 Mbit/s down, 153 up, 144 over a 5-minute soak. Test your own path with `iperf3 -s -B <peer tunnel IP>` on one end and `iperf3 -c <peer tunnel IP> [-R]` on the other. [`bench/`](bench) tests every tunnel method over two of your servers; [docs/FILTER.md](docs/FILTER.md) has the full tables.

---

## 🩺 Troubleshooting

| Symptom | Fix |
|---------|-----|
| Ping answers a few times (often 6), then stops | The path cuts the disguise. Switch both ends to another one. |
| Plain ping between the servers works, the tunnel does not (icmp replies) | The path drops echo replies sent without a request. Switch both ends to ICMP requests. |
| Ping never answers | Same pair check on both servers? Provider firewall lets in ICMP / UDP 53 from the peer? |
| `… is not configured on this host` | `LOCAL_PUB` is not an address of this host (systemd retries every 5 s at boot). |
| `bind: Address already in use` | Something holds `LOCAL_PUB:53` (dns disguise): another dns tunnel or a DNS server. Use icmp or another `LOCAL_PUB`. |
| `FOU port … is already in use` / `File exists` | Give each tunnel on a host its own `FOU_PORT`, `RELAY_PORT` and `GRE_KEY`. |
| Bulk traffic slow in one direction | Measure loss per direction (`iperf3 -u -b 20M`, with and without `-R`); try `FEC` on the sending end. |
| Forwarded TCP connects, then stalls | Lower `MTU`. |

Logs: `journalctl -u golden-gre@<name>`.

---

## 🔐 Security

- **Unencrypted by default**, like GRE. For confidentiality set `KEYFILE` (XChaCha20-Poly1305 over the payload, same key both ends), run WireGuard through the relay ([docs/WireGuard.md](docs/WireGuard.md)), or carry already-encrypted traffic (TLS, VLESS+Reality). With `KEYFILE` the facade markers are also randomized, so no constant byte pattern identifies the tunnel. No anti-replay window: the tag stops forgery, but a captured frame can be replayed (a duplicate the inner transport already tolerates).
- The relay accepts frames only from `REMOTE_PUB` with the right shape and never replies to anything else. A spoofer who forges both can still inject; the GRE key (sent in cleartext) stops blind injection.
- Everything routed through `greN` is forwarded. Filter inside the overlay if the peer shouldn't reach everything this host can.
- Keep real addresses out of git: configs live in `/etc/golden-gre/`.

---

## 🧹 Uninstall

`golden-gre` → **Uninstall** stops every tunnel, removes everything the install added, and asks before deleting `/etc/golden-gre/`. Kernel tuning (BBR, `ip_forward`) stays until reboot.

---

## 🧪 Development

CI runs ShellCheck, a `-Werror` build of the relay, and real tunnels in network namespaces ([`tests/relay.sh`](tests/relay.sh), [`tests/e2e.sh`](tests/e2e.sh)), under systemd ([`tests/systemd.sh`](tests/systemd.sh)), and through the menu ([`tests/manager.sh`](tests/manager.sh)):

```bash
shellcheck -x golden-gre.sh scripts/*.sh tests/*.sh install.sh
sudo tests/relay.sh && sudo tests/e2e.sh && sudo tests/manager.sh
```

`tests/systemd.sh` and `GOLDEN_GRE_TEST_UNINSTALL=1 tests/manager.sh` install and remove real units: run them on a throwaway machine.

[`tools/xui-set-outbound-address.sh`](tools/xui-set-outbound-address.sh) points an x-ui outbound at a tunnel address, with a backup and a rollback script.

---

## 📄 License

[Apache 2.0](LICENSE) © [LivingG0D](https://github.com/LivingG0D)
