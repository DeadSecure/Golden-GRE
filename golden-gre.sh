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
  local s1 s2 me peer lp name conf fec='' facade dev fou relay hint other
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
    bad "This server already has a tunnel on $lp (tunnel $other). Each tunnel needs its own public IP on this server: its relay owns that address. If you no longer need that tunnel, delete it in 'Manage tunnels' first."
    return 1
  fi
  pair_params "$s1" "$s2" "$me"
  if owner_of GRE_KEY "$PAIR_KEY" 41 >/dev/null \
    || grep -qxF "$(net_of "$PAIR_ADDR")" < <(used TUN_ADDR '' | while read -r a; do net_of "$a"; done); then
    bad "Rare clash with another tunnel on this server (same GRE key or tunnel subnet). Write $conf by hand; see the README."
    return 1
  fi

  say ""
  say "Disguise: what the tunnel's traffic looks like on the wire. Both servers must pick the same one."
  say "  1) ICMP: ping replies. Passed on every path measured so far."
  say "  2) DNS:  queries to UDP port 53. Some paths cut it after a few packets."
  ask "Disguise? [1/2] (Enter = 1, ICMP) " 1
  case $REPLY in
    2 | [dD]*) facade=dns ;;
    *) facade=icmp ;;
  esac

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
    echo "FACADE=$facade"
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
  say "  Pair check:  key $PAIR_KEY, subnet $(net_of "$PAIR_ADDR")/30, disguise $facade  (both servers must show the same)"
  if ping -c 2 -W 2 -q "$PAIR_PEER" >/dev/null 2>&1; then
    good "The peer answers through the tunnel. Done!"
  else
    say "The peer does not answer yet. That is normal until you run the same setup on $peer."
    say "If $peer is already set up: both servers must show the same pair check, and each"
    if [ "$facade" = dns ]; then
      say "provider's firewall must let in UDP port 53 from the other server."
    else
      say "provider's firewall must let in ICMP (ping) from the other server."
    fi
    say "If the ping works for a few packets and then stops, or never works, the path cuts this"
    say "disguise: switch both servers to the other one in 'Manage tunnels' (Disguise)."
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
  printf '  %-3s %-16s %-32s %-10s %-9s %-6s %s\n' '#' TUNNEL 'TUNNEL IPs (this -> peer)' STATE DISGUISE FEC PING
  for i in "${!names[@]}"; do
    n=${names[i]}
    addr=$(conf_get "$n" TUN_ADDR)
    peer=$(conf_get "$n" PEER_ADDR "$(peer_of "$addr")")
    printf '  %-3s %-16s %-32s %-10s %-9s %-6s %s\n' "$(( i + 1 ))" "$n" "${addr%/*} -> $peer" \
      "$(systemctl is-active "golden-gre@$n" 2>/dev/null)" "$(conf_get "$n" FACADE dns)" \
      "$(conf_get "$n" FEC off)" "$(ping_ms "$(conf_get "$n" DEV)" "$peer")"
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
toggle_disguise() { # name — what the wire traffic looks like: DNS queries to UDP 53, or ICMP echo replies
  local conf="$CONF_DIR/$1.conf" new=icmp running=0
  [ "$(conf_get "$1" FACADE dns)" = icmp ] && new=dns
  # Stop before editing: the teardown removes the firewall rule of the disguise the tunnel started with.
  if systemctl is-active -q "golden-gre@$1"; then running=1; systemctl stop "golden-gre@$1"; fi
  sed -i '/^FACADE=/d' "$conf"
  echo "FACADE=$new" >>"$conf"
  good "Disguise is now $new. Switch the other server to $new too: both ends must use the same one."
  if [ "$running" = 1 ]; then systemctl start "golden-gre@$1" && good "Restarted"; fi
}

# Port forwarding: FORWARD in the config, applied by golden-gre-up.sh (TCP and UDP, through the tunnel to the
# peer). Entries: PORT, FIRST:LAST, or PORT=PEER_PORT.
fwd_range() { # entry -> FWD_LO FWD_HI; status 1 when it is not a valid entry
  local to=''
  if [[ $1 =~ ^([0-9]{1,5})(:([0-9]{1,5}))?$ ]]; then
    FWD_LO=$(( 10#${BASH_REMATCH[1]} )) FWD_HI=$(( 10#${BASH_REMATCH[3]:-${BASH_REMATCH[1]}} ))
  elif [[ $1 =~ ^([0-9]{1,5})=([0-9]{1,5})$ ]]; then
    FWD_LO=$(( 10#${BASH_REMATCH[1]} )) FWD_HI=$FWD_LO to=$(( 10#${BASH_REMATCH[2]} ))
  else
    return 1
  fi
  (( FWD_LO >= 1 && FWD_HI <= 65535 && FWD_LO <= FWD_HI )) && (( ${to:-1} >= 1 && ${to:-1} <= 65535 ))
}
valid_forward() { # entry: well formed and not over port 22 (golden-gre-up.sh refuses that too)
  fwd_range "$1" && (( FWD_LO > 22 || FWD_HI < 22 ))
}
set_forward() { # name "entries" — write FORWARD; restart a running tunnel so the rules follow
  local conf="$CONF_DIR/$1.conf" v cur
  v=$(tr -s ' ' <<<" $2 "); v=${v# }; v=${v% }
  cur=$(conf_get "$1" FORWARD)
  if [ "$v" = "$cur" ]; then say "No change."; return 0; fi
  if [ -n "$v" ] && [ -z "$(conf_get "$1" PEER_ADDR)" ]; then
    case "$(conf_get "$1" TUN_ADDR)" in
      */30 | */31) ;;
      *) bad "Forwarding needs PEER_ADDR in $conf: its TUN_ADDR is not a /30 or /31."; return 1 ;;
    esac
  fi
  sed -i '/^FORWARD=/d' "$conf"
  if [ -n "$v" ]; then echo "FORWARD=\"$v\"" >>"$conf"; fi
  if systemctl is-active -q "golden-gre@$1"; then
    systemctl restart "golden-gre@$1" && good "Restarted. Forwarded ports: ${v:-none}"
  else
    good "Saved. Forwarded ports: ${v:-none} (applied when the tunnel starts)"
  fi
}
fwd_overlap() { # entry "entries" -> the first listed entry whose ports on this server overlap entry's
  local lo hi x
  local -a list
  fwd_range "$1" || return 1
  lo=$FWD_LO hi=$FWD_HI
  read -ra list <<<"$2"
  for x in ${list[@]+"${list[@]}"}; do
    fwd_range "$x" || continue
    if (( FWD_LO <= hi && lo <= FWD_HI )); then echo "$x"; return 0; fi
  done
  return 1
}
add_forwards() { # name
  local n=$1 cur e p ok dev lp relay='' add='' other
  local -a in=() ssh_ports=() listening=()
  cur=$(conf_get "$n" FORWARD) lp=$(conf_get "$n" LOCAL_PUB)
  # The dns facade's own relay listens on LOCAL_PUB:DNS_PORT; the peer's traffic is never forwarded, so it stays.
  [ "$(conf_get "$n" FACADE dns)" = icmp ] || relay=$(conf_get "$n" DNS_PORT 53)
  say "Examples: 443   2053:2096 (a range)   8080=80 (this server's 8080 to the peer's 80). Each is TCP and UDP."
  ask "Ports to add: "
  read -ra in <<<"$REPLY"
  mapfile -t ssh_ports < <({ echo 22; sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }'; } | sort -un)
  # Only listeners the forwarding takes over: on LOCAL_PUB or on every address.
  mapfile -t listening < <(ss -Hltun 2>/dev/null | awk -v lp="$lp" -v relay="$relay" '{
      n = split($5, a, ":"); port = a[n]; addr = substr($5, 1, length($5) - length(port) - 1); sub(/%.*/, "", addr)
      if ((addr == lp || addr == "0.0.0.0" || addr == "*" || addr == "[::]") && port != relay) print port }' | sort -un)
  for e in ${in[@]+"${in[@]}"}; do
    if ! fwd_range "$e"; then bad "'$e' is not a port, a FIRST:LAST range, or PORT=PEER_PORT"; continue; fi
    ok=1
    for p in "${ssh_ports[@]}"; do
      if (( FWD_LO <= p && p <= FWD_HI )); then
        bad "'$e' includes port $p, this server's SSH: forwarding it would lock you out. Skipped."
        ok=0
      fi
    done
    [ "$ok" = 1 ] || continue
    if other=$(fwd_overlap "$e" "$cur $add"); then
      bad "'$e' overlaps '$other', which is already forwarded. Remove that one first to change it. Skipped."
      continue
    fi
    fwd_range "$e"
    for p in ${listening[@]+"${listening[@]}"}; do
      if (( FWD_LO <= p && p <= FWD_HI )); then
        yes_no "A program on this server listens on port $p; forwarding '$e' takes that port away from it. Forward anyway? [y/N] " n || ok=0
        break
      fi
    done
    [ "$ok" = 1 ] || continue
    add+=" $e"
  done
  [ -n "$add" ] || return 0
  set_forward "$n" "$cur$add" || return
  dev=$(conf_get "$n" DEV)
  say "On $(conf_get "$n" REMOTE_PUB), the service must listen on those ports (on 0.0.0.0 or its tunnel IP)."
  say "If that server runs ufw, also run there: ufw allow in on $dev"
}
remove_forwards() { # name
  local n=$1 cur e keep=''
  local -a list=()
  cur=$(conf_get "$n" FORWARD)
  [ -n "$cur" ] || { say "No forwarded ports."; return 0; }
  ask "Ports to remove, exactly as listed ($cur): "
  read -ra list <<<"$cur"
  for e in ${list[@]+"${list[@]}"}; do [[ " $REPLY " == *" $e "* ]] || keep+=" $e"; done
  if [ "${keep# }" = "$cur" ]; then say "Nothing matched: type entries exactly as listed."; return 0; fi
  set_forward "$n" "$keep"
}
forward_menu() { # name
  local n=$1
  while :; do
    say ""
    say "${Y}Port forwarding${N}: connections to this server's public IP on these ports go through the tunnel to the peer."
    say "  Forwarded now: $(conf_get "$n" FORWARD none)"
    say "   1) Add ports"
    say "   2) Remove ports"
    say "   3) Remove all"
    say "   0) Back"
    ask "> "
    case $REPLY in
      1) add_forwards "$n" ;;
      2) remove_forwards "$n" ;;
      3) if [ -z "$(conf_get "$n" FORWARD)" ]; then say "No forwarded ports."
         elif yes_no "Stop forwarding all ports? [y/N] " n; then set_forward "$n" ""; fi ;;
      0 | '') return ;;
    esac
  done
}

tunnel_menu() { # name
  local n=$1 peer disguise fec
  while :; do
    peer=$(conf_get "$n" PEER_ADDR "$(peer_of "$(conf_get "$n" TUN_ADDR)")")
    disguise=$(conf_get "$n" FACADE dns) fec=$(conf_get "$n" FEC off)
    say ""
    say "${Y}Tunnel $n${N}: $(systemctl is-active "golden-gre@$n" 2>/dev/null), disguise $disguise, FEC $fec"
    say "   1) Start"
    say "   2) Stop"
    say "   3) Restart"
    say "   4) Ping test"
    say "   5) Recent logs"
    say "   6) Live logs"
    say "   7) Disguise: $disguise (switch to $([ "$disguise" = icmp ] && echo dns || echo icmp))"
    say "   8) FEC: $fec (turn $([ "$fec" = off ] && echo on || echo off))"
    say "   9) Port forwarding: $(conf_get "$n" FORWARD none)"
    say "  10) Show settings"
    say "  11) Delete"
    say "   0) Back"
    ask "> "
    case $REPLY in
      1) if systemctl is-active -q "golden-gre@$n"; then good "Already running"
         else start_tunnel "$n" && good "Started (and starts on every boot)"; fi ;;
      2) systemctl disable --now "golden-gre@$n" >/dev/null 2>&1 && good "Stopped (it stays off after reboot too)" ;;
      3) systemctl restart "golden-gre@$n" && good "Restarted" ;;
      4) interruptible ping -c 5 -W 2 "$peer" ;;
      5) journalctl -u "golden-gre@$n" -n 50 --no-pager ;;
      6) follow_logs "$n" ;;
      7) toggle_disguise "$n" ;;
      8) toggle_fec "$n" ;;
      9) forward_menu "$n" ;;
      10) cat "$CONF_DIR/$n.conf" ;;
      11) if yes_no "Delete tunnel $n? It stops now and its settings are removed. [y/N] " n; then
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
    say "  2) Manage tunnels (status, start/stop, FEC, disguise, delete)"
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
