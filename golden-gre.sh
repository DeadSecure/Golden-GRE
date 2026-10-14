#!/usr/bin/env bash
# Golden GRE — easy installer and tunnel manager (interactive menu).
#
# Run the same line on both servers, as root:
#   bash <(curl -fsSL https://raw.githubusercontent.com/LivingG0D/Golden-GRE/main/golden-gre.sh)
# The first run installs Golden GRE and the `golden-gre` command, then sets up a tunnel from just the
# two servers' public IPs. Later, `golden-gre` opens this menu.
set -uo pipefail

REPO=LivingG0D/Golden-GRE
BRANCH="${GOLDEN_GRE_BRANCH:-main}"
CONF_DIR=/etc/golden-gre
SBIN=/usr/local/sbin
SELF=/usr/local/bin/golden-gre
FEC_DEFAULT=10:5

if [ -t 1 ]; then Y=$'\e[1;33m' G=$'\e[32m' R=$'\e[31m' D=$'\e[2m' N=$'\e[0m'; else Y='' G='' R='' D='' N=''; fi

say()  { printf '%s\n' "$*"; }
good() { printf '%s✓%s %s\n' "$G" "$N" "$*"; }
bad()  { printf '%s✗%s %s\n' "$R" "$N" "$*"; }

# Read one answer into REPLY (default when empty). End of input quits.
ask() { # prompt [default]
  read -r -p "$1" REPLY || { echo; exit 0; }
  REPLY="${REPLY:-${2:-}}"
}
yes_no() { # prompt default(y|n)
  ask "$1" "$2"
  [[ $REPLY == [yY]* ]]
}

valid_ip() { # dotted IPv4 without leading zeros: both ends must type the very same string
  local o='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
  [[ $1 =~ ^$o\.$o\.$o\.$o$ ]]
}
is_private() { # RFC 1918, CGNAT, link-local
  [[ $1 =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|169\.254\.) ]]
}
ask_ip() { # prompt -> REPLY
  while ask "$1"; ! valid_ip "$REPLY"; do bad "'$REPLY' is not an IPv4 address like 203.0.113.10"; done
}
ip2int() {
  local a b c d
  IFS=. read -r a b c d <<<"$1"
  echo $(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))
}

# What both ends must agree on, from the two public IPs alone, in either order: the GRE key and a /30
# in 10.99.0.0/16 come from a hash of the pair, and the lower IP takes the first address of the /30.
pair_params() { # ip1 ip2 this_server_ip -> PAIR_KEY, PAIR_ADDR (this end, /30), PAIR_PEER
  local lo=$1 hi=$2 id idx base me=1 peer=2
  if (( $(ip2int "$1") > $(ip2int "$2") )); then lo=$2 hi=$1; fi
  id=$(printf '%s-%s' "$lo" "$hi" | cksum | cut -d' ' -f1)
  idx=$(( id % 16384 ))
  base=$(( idx % 64 * 4 ))
  [ "$3" = "$lo" ] || { me=2 peer=1; }
  PAIR_KEY=$(( 1000 + id % 64000 ))
  PAIR_ADDR="10.99.$(( idx / 64 )).$(( base + me ))/30"
  PAIR_PEER="10.99.$(( idx / 64 )).$(( base + peer ))"
}
peer_of() { # a.b.c.d/30 -> the other host of the /30
  local ip=${1%/*} last
  last=${ip##*.}
  echo "${ip%.*}.$(( (last & ~3) + 3 - (last & 3) ))"
}
net_of() { # a.b.c.d/30 -> network address
  local ip=${1%/*} last
  last=${ip##*.}
  echo "${ip%.*}.$(( last & ~3 ))"
}

# A check that stops reading early (grep -q) kills a writer still printing, and pipefail turns that into
# "not found": feed such checks through < <(...) instead of a pipe.
has_addr() { grep -qxF "$1" < <(ip -4 -o addr show 2>/dev/null | awk '{ split($4, a, "/"); print a[1] }'); }
src_for() { ip -4 route get "$1" 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p'; }

tunnel_names() {
  local f
  for f in "$CONF_DIR"/*.conf; do
    [ -e "$f" ] || continue
    f=${f##*/}
    echo "${f%.conf}"
  done
}
conf_get() { # name KEY [default]
  (
    # shellcheck source=/dev/null
    . "$CONF_DIR/$1.conf"
    printf '%s\n' "${!2:-${3:-}}"
  )
}
used() { # KEY default -> the value of KEY in every tunnel on this host
  local n
  while read -r n; do conf_get "$n" "$1" "$2"; done < <(tunnel_names)
}
owner_of() { # KEY value [default] -> the first tunnel on this host whose KEY is value
  local n
  while read -r n; do
    if [ "$(conf_get "$n" "$1" "${3:-}")" = "$2" ]; then echo "$n"; return 0; fi
  done < <(tunnel_names)
  return 1
}
next_dev() {
  local i=1 taken
  taken=" $(used DEV '' | tr '\n' ' ') "
  while [[ $taken == *" gre$i "* ]] || ip link show "gre$i" >/dev/null 2>&1; do i=$(( i + 1 )); done
  echo "gre$i"
}
next_port() { # first [taken...] -> first free UDP port from `first`
  local p=$1 taken=" ${*:2} "
  while [[ $taken == *" $p "* ]] || [ -n "$(ss -Hlun "sport = :$p" 2>/dev/null)" ]; do p=$(( p + 1 )); done
  echo "$p"
}

start_tunnel() { # name
  local out
  if ! out=$(golden-gre-preflight "$1" 2>&1); then
    printf '%s\n' "$out" | grep -v '✓'
    return 1
  fi
  systemctl enable --now "golden-gre@$1" >/dev/null 2>&1
  sleep 2
  if ! systemctl is-active -q "golden-gre@$1"; then
    journalctl -u "golden-gre@$1" -n 15 --no-pager
    # Restart=always would rebuild it every 5 s: keep it off until the problem is fixed.
    systemctl disable --now "golden-gre@$1" >/dev/null 2>&1
    return 1
  fi
}
remove_tunnel() { # name — stop first: the unit's teardown reads the config
  systemctl disable --now "golden-gre-check@$1.timer" >/dev/null 2>&1
  systemctl disable --now "golden-gre@$1" >/dev/null 2>&1
  systemctl reset-failed "golden-gre@$1" "golden-gre-check@$1.service" >/dev/null 2>&1
  rm -f "$CONF_DIR/$1.conf"
}

setup_tunnel() {
  local s1 s2 me peer lp name conf fec='' dev fou relay hint other
  local -a taken
  say ""
  say "${Y}New tunnel${N}: run this same setup on both servers, with the same two IPs."
  hint=$(src_for 1.1.1.1)
  if [ -z "$hint" ]; then :
  elif is_private "$hint"; then
    say "${D}This server's own address is private ($hint), so it is behind NAT: type its public IP from your provider's panel.${N}"
  else
    say "${D}This server's IP looks like $hint${N}"
  fi
  ask_ip "Server 1 public IP: "; s1=$REPLY
  ask_ip "Server 2 public IP: "; s2=$REPLY
  [ "$s1" != "$s2" ] || { bad "The two IPs must be different."; return 1; }

  if has_addr "$s1"; then me=$s1 peer=$s2 lp=$s1
  elif has_addr "$s2"; then me=$s2 peer=$s1 lp=$s2
  else
    # Behind 1:1 NAT (some clouds) the public IP is not on the host: the relay binds the address that
    # reaches the peer.
    ask "Neither IP is on this server (NAT?). Is this server 1 or 2? "
    case $REPLY in
      1) me=$s1 peer=$s2 ;;
      2) me=$s2 peer=$s1 ;;
      *) bad "Answer 1 or 2."; return 1 ;;
    esac
    lp=$(src_for "$peer")
    [ -n "$lp" ] || { bad "This server has no route to $peer."; return 1; }
  fi
  good "This server is $me, the other one is $peer."

  name=$peer conf="$CONF_DIR/$peer.conf"
  if [ -e "$conf" ]; then
    yes_no "A tunnel to $peer already exists. Replace it? [y/N] " n || return 1
    remove_tunnel "$name"
  fi
  if other=$(owner_of LOCAL_PUB "$lp"); then
    bad "This server already has a tunnel on $lp (tunnel $other). Each tunnel needs its own public IP on this server: the relay takes UDP port 53 on it. If you no longer need that tunnel, delete it in 'Manage tunnels' first."
    return 1
  fi
  pair_params "$s1" "$s2" "$me"
  if owner_of GRE_KEY "$PAIR_KEY" 41 >/dev/null \
    || grep -qxF "$(net_of "$PAIR_ADDR")" < <(used TUN_ADDR '' | while read -r a; do net_of "$a"; done); then
    bad "Rare clash with another tunnel on this server (same GRE key or tunnel subnet). Write $conf by hand; see the README."
    return 1
  fi

  say ""
  say "FEC repairs lost packets. It adds 50% to the traffic this server sends."
  say "Turn it on for the server that sends INTO the lossy side: usually the foreign server, when downloads in Iran are slow."
  if yes_no "Enable FEC on this server? [y/N] " n; then fec=$FEC_DEFAULT; fi

  dev=$(next_dev)
  mapfile -t taken < <(used FOU_PORT 5599; used RELAY_PORT 5601)
  fou=$(next_port 5599 ${taken[@]+"${taken[@]}"})
  relay=$(next_port 5601 ${taken[@]+"${taken[@]}"} "$fou")
  install -d -m 0750 "$CONF_DIR"
  {
    echo "# Made by golden-gre setup. $peer has the matching file: same GRE_KEY, the other address of the /30."
    echo "DEV=$dev"
    echo "LOCAL_PUB=$lp"
    echo "REMOTE_PUB=$peer"
    echo "TUN_ADDR=$PAIR_ADDR"
    echo "GRE_KEY=$PAIR_KEY"
    echo "FOU_PORT=$fou"
    echo "RELAY_PORT=$relay"
    if [ -n "$fec" ]; then echo "FEC=$fec"; fi
  } >"$conf"
  good "Saved $conf"

  if ! start_tunnel "$name"; then
    bad "The tunnel did not start. Fix the problem above, then start it from 'Manage tunnels'."
    return 1
  fi
  say ""
  good "Tunnel to $peer is running on this server."
  say "  This server: $me, tunnel IP ${PAIR_ADDR%/*}"
  say "  Peer:        $peer, tunnel IP $PAIR_PEER  (use this address to reach the peer through the tunnel)"
  say "  Pair check:  key $PAIR_KEY, subnet $(net_of "$PAIR_ADDR")/30  (both servers must show the same)"
  if ping -c 2 -W 2 -q "$PAIR_PEER" >/dev/null 2>&1; then
    good "The peer answers through the tunnel. Done!"
  else
    say "The peer does not answer yet. That is normal until you run the same setup on $peer."
    say "If $peer is already set up: check that both servers show the same pair check, and that the"
    say "provider's firewall on each server lets in UDP port 53 from the other one."
  fi
}

ping_ms() { # dev addr
  local t
  t=$(ping -c 1 -W 1 -I "$1" "$2" 2>/dev/null | sed -n 's/.*time=\([0-9.]*\).*/\1/p')
  if [ -n "$t" ]; then echo "$t ms"; else echo "no reply"; fi
}
choose_tunnel() { # -> PICKED; status 1 for none or back
  local -a names
  local i n addr peer
  mapfile -t names < <(tunnel_names)
  if [ ${#names[@]} -eq 0 ]; then say "No tunnels yet. Choose 'New tunnel' first."; return 1; fi
  say ""
  printf '  %-3s %-16s %-32s %-10s %-6s %s\n' '#' TUNNEL 'TUNNEL IPs (this -> peer)' STATE FEC PING
  for i in "${!names[@]}"; do
    n=${names[i]}
    addr=$(conf_get "$n" TUN_ADDR)
    peer=$(conf_get "$n" PEER_ADDR "$(peer_of "$addr")")
    printf '  %-3s %-16s %-32s %-10s %-6s %s\n' "$(( i + 1 ))" "$n" "${addr%/*} -> $peer" \
      "$(systemctl is-active "golden-gre@$n" 2>/dev/null)" "$(conf_get "$n" FEC off)" \
      "$(ping_ms "$(conf_get "$n" DEV)" "$peer")"
  done
  ask "Tunnel number (Enter = back): "
  [[ $REPLY =~ ^[0-9]+$ ]] && (( REPLY >= 1 && REPLY <= ${#names[@]} )) || return 1
  PICKED=${names[REPLY - 1]}
}

interruptible() { # command... — Ctrl+C stops the command, not this menu
  # A handler, not ignore: an ignored SIGINT would be inherited by the command too.
  trap ':' INT
  "$@"
  trap - INT
}
follow_logs() { # name
  say "${D}Live logs. Press Ctrl+C to go back.${N}"
  interruptible journalctl -u "golden-gre@$1" -n 20 -f
}
toggle_fec() { # name
  local conf="$CONF_DIR/$1.conf"
  if grep -q '^FEC=' "$conf"; then
    sed -i '/^FEC=/d' "$conf"
    good "FEC off"
  else
    echo "FEC=$FEC_DEFAULT" >>"$conf"
    good "FEC on ($FEC_DEFAULT)"
  fi
  if systemctl is-active -q "golden-gre@$1"; then systemctl restart "golden-gre@$1" && good "Restarted"; fi
}

tunnel_menu() { # name
  local n=$1 peer
  while :; do
    peer=$(conf_get "$n" PEER_ADDR "$(peer_of "$(conf_get "$n" TUN_ADDR)")")
    say ""
    say "${Y}Tunnel $n${N}: $(systemctl is-active "golden-gre@$n" 2>/dev/null), FEC $(conf_get "$n" FEC off)"
    say "  1) Restart  2) Stop  3) Start  4) Ping test  5) Recent logs  6) Live logs"
    say "  7) FEC on/off  8) Show settings  9) Delete  0) Back"
    ask "> "
    case $REPLY in
      1) systemctl restart "golden-gre@$n" && good "Restarted" ;;
      2) systemctl disable --now "golden-gre@$n" >/dev/null 2>&1 && good "Stopped (it stays off after reboot too)" ;;
      3) if systemctl is-active -q "golden-gre@$n"; then good "Already running"
         else start_tunnel "$n" && good "Started (and starts on every boot)"; fi ;;
      4) interruptible ping -c 5 -W 2 "$peer" ;;
      5) journalctl -u "golden-gre@$n" -n 50 --no-pager ;;
      6) follow_logs "$n" ;;
      7) toggle_fec "$n" ;;
      8) cat "$CONF_DIR/$n.conf" ;;
      9) if yes_no "Delete tunnel $n? It stops now and its settings are removed. [y/N] " n; then
           remove_tunnel "$n"
           good "Deleted"
           return
         fi ;;
      0 | '') return ;;
    esac
  done
}

source_tree() { # -> SRC: this clone, or a fresh download of the repo (then SRC_TMP=1)
  local here
  here=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)
  SRC_TMP=0
  if [ -f "$here/install.sh" ] && [ -d "$here/relay" ]; then SRC=$here; return; fi
  SRC=$(mktemp -d) SRC_TMP=1
  say "Downloading Golden GRE ($BRANCH)..."
  curl -fsSL --connect-timeout 15 "https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz" \
    | tar -xz -C "$SRC" --strip-components=1 \
    || { bad "Download from GitHub failed. Or: git clone https://github.com/$REPO && cd Golden-GRE && ./golden-gre.sh"; return 1; }
}
install_packages() {
  local t missing=()
  for t in gcc ip iptables ethtool ping curl tar ss; do command -v "$t" >/dev/null 2>&1 || missing+=("$t"); done
  [ -e /usr/include/stdio.h ] || missing+=(libc-headers)
  [ ${#missing[@]} -eq 0 ] && return 0
  say "Installing packages for: ${missing[*]} (this can take a few minutes)"
  if command -v apt-get >/dev/null 2>&1; then
    # A broken third-party repo fails `update` but not the install. On a fresh VPS, unattended-upgrades
    # often holds the dpkg lock for a while: wait for it.
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o DPkg::Lock::Timeout=300 \
      gcc libc6-dev iproute2 iptables ethtool iputils-ping curl tar
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q gcc glibc-devel iproute iptables ethtool iputils curl tar
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q gcc glibc-devel iproute iptables ethtool iputils curl tar
  else
    bad "Install these yourself, then run again: ${missing[*]}"
    return 1
  fi
}
install_or_update() {
  local out running
  install_packages || { bad "Package install failed."; return 1; }
  source_tree || { [ "$SRC_TMP" = 1 ] && rm -rf "$SRC"; return 1; }
  local rc=0
  if ! out=$(cd "$SRC" && ./install.sh 2>&1) || ! install -m 0755 "$SRC/golden-gre.sh" "$SELF"; then rc=1; fi
  [ "$SRC_TMP" = 1 ] && rm -rf "$SRC"
  if [ "$rc" -ne 0 ]; then
    printf '%s\n' "$out"
    bad "Install failed."
    return 1
  fi
  good "Golden GRE installed. Open this menu any time with: golden-gre"
  if ! out=$(golden-gre-preflight 2>&1); then
    printf '%s\n' "$out" | grep -v '✓'
    bad "This server cannot run the tunnel (see above). VPSes on OpenVZ/LXC usually lack the fou/ip_gre modules."
    return 1
  fi
  running=$(systemctl list-units --plain --no-legend --state=active 'golden-gre@*' 2>/dev/null | awk '{print $1}')
  if [ -n "$running" ] && yes_no "Restart running tunnels now to use the new version? [Y/n] " y; then
    # shellcheck disable=SC2086 # one unit per word
    systemctl restart $running && good "Restarted"
  fi
}

uninstall() {
  local n
  yes_no "Uninstall Golden GRE? Every tunnel stops. [y/N] " n || return 0
  while read -r n; do
    systemctl disable --now "golden-gre-check@$n.timer" "golden-gre@$n" >/dev/null 2>&1
  done < <(tunnel_names)
  systemctl stop 'golden-gre@*' 'golden-gre-check@*' >/dev/null 2>&1
  # Enable links of tunnels whose config is already gone (the templates are files, not links).
  find /etc/systemd/system -type l -name 'golden-gre*@?*' -delete 2>/dev/null
  find /etc/systemd/system -type d -name 'golden-gre@*.wants' -empty -delete 2>/dev/null
  rm -f "$SBIN"/golden-gre-{relay,up.sh,down.sh,relay.sh,preflight,check} \
    /etc/systemd/system/golden-gre@.service /etc/systemd/system/golden-gre-check@.{service,timer} \
    /etc/sysctl.d/99-golden-gre.conf
  systemctl daemon-reload
  systemctl reset-failed 'golden-gre@*' 'golden-gre-check@*' >/dev/null 2>&1
  if yes_no "Also delete the tunnel settings in $CONF_DIR? [y/N] " n; then rm -rf "$CONF_DIR"; fi
  rm -f "$SELF"
  good "Golden GRE removed. Its kernel tuning (BBR, ip_forward) stays until the next reboot."
  exit 0
}

main() {
  [ "$(id -u)" -eq 0 ] || { bad "Run as root: sudo -i, then the same command again."; exit 1; }
  if [ ! -x "$SBIN/golden-gre-relay" ] || [ ! -x "$SELF" ]; then
    say "${Y}Golden GRE${N} is not installed yet. Installing..."
    install_or_update || exit 1
    if [ -z "$(tunnel_names)" ] && yes_no "Set up a tunnel now? [Y/n] " y; then setup_tunnel; fi
  fi
  while :; do
    say ""
    say "${Y}=== Golden GRE ===${N}  tunnels: $(tunnel_names | wc -l), running: $(systemctl list-units --plain --no-legend --state=active 'golden-gre@*' 2>/dev/null | wc -l)"
    say "  1) New tunnel (asks for the two server IPs)"
    say "  2) Manage tunnels (status, start/stop, FEC, delete)"
    say "  3) Live logs"
    say "  4) Update Golden GRE"
    say "  5) Uninstall"
    say "  0) Exit"
    ask "> "
    case $REPLY in
      1) setup_tunnel ;;
      2) while choose_tunnel; do tunnel_menu "$PICKED"; done ;;
      3) choose_tunnel && follow_logs "$PICKED" ;;
      4) install_or_update ;;
      5) uninstall ;;
      0 | q) exit 0 ;;
    esac
  done
}

# `curl … | bash` feeds the script on stdin, where the menu needs the keyboard.
if [ -z "${BASH_SOURCE[0]:-}" ]; then
  bad "Run it as: bash <(curl -fsSL https://raw.githubusercontent.com/$REPO/main/golden-gre.sh)   (not curl | bash)"
  exit 1
elif [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
