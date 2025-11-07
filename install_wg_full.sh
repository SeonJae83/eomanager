#!/usr/bin/env bash
# install_wg_full.sh ? multi-IF WireGuard FULL
# - ensNN 자동 구성 + per-IF policy routing + SNAT + FwMark
# - add/del/list/find/ed(차단·복구) 유틸 포함
# - wg-reinit.service 부팅 자동 재적용, network-online 이후
# - uninstall 포함
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

BASE="/home/script/wg"
ETC_WG="/etc/wireguard"
BIN="/usr/local/sbin"
mkdir -p "$BASE" "$ETC_WG" /etc/systemd/system/wg-quick@.service.d
chmod 755 "$BASE"

# ===== pkgs =====
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y wireguard iproute2 >/dev/null 2>&1 || true

# ===== wg-quick drop-in =====
cat >/etc/systemd/system/wg-quick@.service.d/override.conf <<'EOF'
[Unit]
After=network-online.target
Wants=network-online.target
EOF
systemctl daemon-reload

# ===== helper: postup/postdown (ACCEPT only) =====
cat >"$BIN/wg-mi-postup" <<"EOF"
#!/usr/bin/env bash
# usage: wg-mi-postup <NIC> <IFACE> <SUBNET> <TBL> <PRI> <PORT>
set -Eeu -o pipefail
NIC="$1"; IFACE="$2"; SUBNET="$3"; TBL="$4"; PRI="$5"; PORT="$6"

for _ in {1..50}; do
  SRC=$(ip -4 -o addr show dev "$NIC" | awk '{split($4,a,"/");print a[1]}') || true
  NET=$(ip -4 route show dev "$NIC" | awk '/proto kernel/ {print $1;exit}') || true
  GW=$(ip -4 route get 8.8.8.8 oif "$NIC" 2>/dev/null | awk '/via/ {for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}') || true
  [[ -n "${SRC:-}" && -n "${NET:-}" && -n "${GW:-}" ]] && break
  sleep 0.1
done
[[ -z "${SRC:-}" || -z "${NET:-}" || -z "${GW:-}" ]] && exit 0

sysctl -wq "net.ipv4.conf.$NIC.rp_filter=2" || true
sysctl -wq "net.ipv4.conf.$IFACE.rp_filter=2" || true

ip route replace table "$TBL" "$NET" dev "$NIC" scope link src "$SRC" || true
ip route replace table "$TBL" default via "$GW" dev "$NIC" onlink src "$SRC" || true
ip rule add from "$SUBNET" lookup "$TBL" priority "$PRI" 2>/dev/null || true

IFNUM="$(sed 's/[^0-9]//g' <<<"$NIC")"
FWMARK_HEX="$(printf '0x%04X' "$(( 0x3000 + IFNUM ))")"
ip rule add fwmark "$FWMARK_HEX" lookup "$TBL" priority "$((PRI-1))" 2>/dev/null || true

iptables -w 1 -t nat -C POSTROUTING -s "$SUBNET" -o "$NIC" -j SNAT --to-source "$SRC" 2>/dev/null \
  || iptables -w 1 -t nat -A POSTROUTING -s "$SUBNET" -o "$NIC" -j SNAT --to-source "$SRC"

# INPUT ACCEPT만 추가 (DROP 없음)
iptables -w 1 -C INPUT -i "$NIC" -p udp --dport "$PORT" -m comment --comment "wg-mi:${NIC}:${PORT}:ACCEPT" -j ACCEPT 2>/dev/null || \
iptables -w 1 -I INPUT -i "$NIC" -p udp --dport "$PORT" -m comment --comment "wg-mi:${NIC}:${PORT}:ACCEPT" -j ACCEPT

ping -c1 -W1 "$GW" >/dev/null 2>&1 || true
EOF
chmod 755 "$BIN/wg-mi-postup"

cat >"$BIN/wg-mi-postdown" <<"EOF"
#!/usr/bin/env bash
# usage: wg-mi-postdown <NIC> <SUBNET> <TBL> <PRI> <PORT>
set -Eeu -o pipefail
NIC="$1"; SUBNET="$2"; TBL="$3"; PRI="$4"; PORT="$5"
SRC="$(ip -4 -o addr show dev "$NIC" 2>/dev/null | awk '{split($4,a,"/");print a[1]}')" || true

# INPUT ACCEPT만 정리
iptables -S INPUT | awk -v nic="$NIC" -v port="$PORT" '
/^-A INPUT/ && /-p udp/ && ("--dport "port) && /-m comment --comment "wg-mi:/ {
  if ($0 ~ "wg-mi:"nic":"port":ACCEPT") { sub("^-A INPUT ",""); print }
}' | while read -r spec; do iptables -w 1 -D INPUT $spec 2>/dev/null || true; done

# NAT 정리
if [[ -n "${SRC:-}" ]]; then
  iptables -w 1 -t nat -D POSTROUTING -s "$SUBNET" -o "$NIC" -j SNAT --to-source "$SRC" 2>/dev/null || true
fi

# 정책라우팅 정리
ip rule del from "$SUBNET" lookup "$TBL" priority "$PRI" 2>/dev/null || true
ip route flush table "$TBL" 2>/dev/null || true
IFNUM="$(sed 's/[^0-9]//g' <<<"$NIC")"
FWMARK_HEX="$(printf '0x%04X' "$(( 0x3000 + IFNUM ))")"
ip rule del fwmark "$FWMARK_HEX" lookup "$TBL" priority "$((PRI-1))" 2>/dev/null || true
EOF
chmod 755 "$BIN/wg-mi-postdown"

# ===== setup_wg_iface.sh ? ensNN 자동(기존 키/피어 보존 + Name 주석 보존) =====
cat >"$BIN/setup_wg_iface.sh" <<"EOF"
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "[ERR] line:$LINENO cmd:$BASH_COMMAND" >&2' ERR
tbl(){ echo $((3000+$1)); }
pri(){ echo $((30000+$1)); }
need(){ command -v "$1" >/dev/null || { echo "missing: $1"; exit 127; }; }
need awk; need ip; need wg; need wg-quick; need systemctl; need sed; need base64

get_nics(){
  ip -4 -o addr show | awk '{print $2}' | sed 's/@.*//' | sort -u | grep -E '^ens[0-9]+$' \
  | while read -r n; do ip -o link show dev "$n" | grep -q "state UP" && echo "$n"; done
}
parse_priv_port(){
  local conf="$1"; local stripped; stripped="$(wg-quick strip "$conf" 2>/dev/null || true)"
  local pkey port
  pkey="$(awk '$1=="PrivateKey"{print $3;exit}' <<<"$stripped" || true)"
  port="$(awk  '$1=="ListenPort"{print $3;exit}' <<<"$stripped" || true)"
  printf '%s|%s\n' "${pkey:-}" "${port:-}"
}
normalize_b64(){
  local s="${1:-}"; s="$(printf '%s' "$s" | tr -cd 'A-Za-z0-9+/=')"
  local mod=$(( ${#s} % 4 )); [[ $mod -eq 2 ]] && s="${s}=="; [[ $mod -eq 3 ]] && s="${s}=";
  printf '%s' "$s" | base64 -d >/dev/null 2>&1 || { echo ""; return; }; echo "$s";
}

setup_one(){
  local NIC="$1"; local NUM; NUM="$(sed 's/[^0-9]//g' <<<"$NIC")"; [[ -n "$NUM" ]] || { echo "skip $NIC"; return; }
  local IFACE="wg-${NIC}"
  local CONF="/etc/wireguard/${IFACE}.conf"
  local DEFAULT_PORT="$((50000+NUM))"
  local SUBNET="10.10.${NUM}.0/24" GIP="10.10.${NUM}.1/24" TBL="$(tbl "$NUM")" PRI="$(pri "$NUM")"
  local IFNUM="$NUM" FWMARK_HEX; FWMARK_HEX="$(printf '0x%04X' "$(( 0x3000 + IFNUM ))")"
  local SRC; SRC="$(ip -4 -o addr show dev "$NIC" 2>/dev/null | awk '{split($4,a,"/");print a[1]}')" || true
  [[ -n "${SRC:-}" ]] || { echo "skip $NIC: no IPv4"; return; }

  umask 077; local SRV_PRIV="" PORT="" PEERS=""

  # 키/포트: 파일 우선 파싱, 부족하면 showconf 백업
  if [[ -f "$CONF" ]]; then IFS='|' read -r SRV_PRIV PORT < <(parse_priv_port "$CONF"); fi
  if [[ -z "${SRV_PRIV:-}" || -z "${PORT:-}" ]]; then
    local RUN; RUN="$(wg showconf "$IFACE" 2>/dev/null || true)"
    [[ -z "${SRV_PRIV:-}" ]] && SRV_PRIV="$(awk '/^PrivateKey/{print $3;exit}' <<<"$RUN" || true)"
    [[ -z "${PORT:-}"     ]] && PORT="$(awk '/^ListenPort/{print $3;exit}' <<<"$RUN" || true)"
  fi
  PORT="${PORT:-$DEFAULT_PORT}"
  SRV_PRIV="$(normalize_b64 "${SRV_PRIV:-}")"; [[ -n "${SRV_PRIV:-}" ]] || SRV_PRIV="$(wg genkey)"

  # [Peer] 블록: 우선 showconf(기존 동작 유지) → 그 다음 "파일에 [Peer]가 있으면 그 원문으로 최종 덮어쓰기"로 Name 주석 보존
  PEERS="$( { wg showconf "$IFACE" 2>/dev/null || true; } | sed -n '/^\[Peer\]/,$p')"
  if [[ -f "$CONF" ]]; then
    FP="$(sed -n '/^\[Peer\]/,$p' "$CONF")"
    [[ -n "${FP//[[:space:]]/}" ]] && PEERS="$FP"
  fi

  local TMPDIR TMP; TMPDIR="$(mktemp -d)"; TMP="${TMPDIR}/${IFACE}.conf"
  cat >"$TMP" <<CFG
[Interface]
Address = ${GIP}
ListenPort = ${PORT}
PrivateKey = ${SRV_PRIV}
FwMark = ${FWMARK_HEX}
PostUp = /usr/local/sbin/wg-mi-postup ${NIC} ${IFACE} ${SUBNET} ${TBL} ${PRI} ${PORT}
PostDown = /usr/local/sbin/wg-mi-postdown ${NIC} ${SUBNET} ${TBL} ${PRI} ${PORT}

${PEERS}
CFG
  wg-quick strip "$TMP" >/dev/null        # 유효성 체크만
  install -m 600 "$TMP" "$CONF"; rm -rf "$TMPDIR"
  systemctl enable "wg-quick@${IFACE}" >/dev/null
  systemctl restart "wg-quick@${IFACE}"

  local CUR; CUR="$(ip -4 -o addr show dev "${NIC}" | awk '{split($4,a,"/");print a[1]}')"
  for f in /home/script/wg/*.conf; do
    [[ -f "$f" ]] || continue
    head -n1 "$f" | grep -q "^# IFACE=${IFACE}$" || continue
    sed -i "s/^Endpoint *= *.*/Endpoint = ${CUR}:${PORT}/" "$f"
  done

  echo "UP ${IFACE} (${SUBNET} via ${NIC}, port ${PORT}, fwmark ${FWMARK_HEX})"
}
main(){ mapfile -t NICS < <(get_nics); ((${#NICS[@]})) || { echo "no ensNN"; exit 1; }; for n in "${NICS[@]}"; do setup_one "$n"; done; }
main
EOF
chmod 755 "$BIN/setup_wg_iface.sh"

# ===== 부팅 자동 재적용 =====
cat >/etc/systemd/system/wg-reinit.service <<'EOF'
[Unit]
Description=Reinit WireGuard IFs after boot (ensNN auto)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/bash /usr/local/sbin/setup_wg_iface.sh
[Install]
WantedBy=multi-user.target
EOF
systemctl enable wg-reinit.service

# ===== add-user (정확일치 중복차단, DNS=168.126.63.1) =====
cat >"$BIN/wg-add-user.sh" <<"EOF"
#!/usr/bin/env bash
set -euo pipefail
WG_ADD_IFACE="${1:?usage: wg-add-user <wg-ensNN> <username>}"
WG_ADD_USERNAME="${2:?usage: wg-add-user <wg-ensNN> <username>}"

WG_ADD_CONF="/etc/wireguard/${WG_ADD_IFACE}.conf"; [[ -f "$WG_ADD_CONF" ]] || { echo "no conf: $WG_ADD_CONF"; exit 1; }
WG_ADD_NIC="${WG_ADD_IFACE#wg-}"

WG_ADD_SRV_PUB="$(wg show ${WG_ADD_IFACE} public-key 2>/dev/null || awk -F'= *' '/^PrivateKey/{print $2}' "$WG_ADD_CONF" | head -n1 | wg pubkey)"
WG_ADD_SRV_PORT="$(awk -F'= *' '/^ListenPort/{print $2}' "$WG_ADD_CONF")"
WG_ADD_SRV_IP="$(ip -4 -o addr show dev "${WG_ADD_NIC}" | awk '{split($4,a,"/");print a[1]}')"
WG_ADD_BASE_NET="$(awk -F'[ ./]' '/^Address/{print $3"."$4"."$5}' "$WG_ADD_CONF" | head -n1)"

mapfile -t WG_ADD_NAMES < <(
  awk '/^#[[:space:]]*Name[[:space:]]*=/{
         t=$0; sub(/.*=/,"",t);
         gsub(/^[[:space:]]+|[[:space:]]+$/,"",t);
         print t
       }' "$WG_ADD_CONF"
)
if printf '%s\n' "${WG_ADD_NAMES[@]}" | grep -qxF "$WG_ADD_USERNAME"; then
  echo "user name already exists on ${WG_ADD_IFACE}: ${WG_ADD_USERNAME}" >&2
  exit 3
fi

mapfile -t WG_ADD_USED < <(wg show ${WG_ADD_IFACE} allowed-ips 2>/dev/null | awk '{print $2}' | cut -d/ -f1 | awk -F. -v b="$WG_ADD_BASE_NET" '$1"."$2"."$3==b{print $4}' | sort -n)
WG_ADD_NEXT=2; for i in {2..254}; do if ! printf '%s\n' "${WG_ADD_USED[@]}" | grep -qx "$i"; then WG_ADD_NEXT="$i"; break; fi; done
[[ $WG_ADD_NEXT -le 254 ]] || { echo "pool exhausted"; exit 2; }
WG_ADD_CLT_IP="${WG_ADD_BASE_NET}.${WG_ADD_NEXT}"

umask 077
WG_ADD_CLT_PRIV="$(wg genkey)"; WG_ADD_CLT_PUB="$(printf "%s" "$WG_ADD_CLT_PRIV" | wg pubkey)"
wg set ${WG_ADD_IFACE} peer "$WG_ADD_CLT_PUB" allowed-ips "${WG_ADD_CLT_IP}/32" persistent-keepalive 10

tail -c1 "$WG_ADD_CONF" | read -r _ || echo >> "$WG_ADD_CONF"
cat >> "$WG_ADD_CONF" <<EOC

[Peer]
# Name = ${WG_ADD_USERNAME}
PublicKey = ${WG_ADD_CLT_PUB}
AllowedIPs = ${WG_ADD_CLT_IP}/32
PersistentKeepalive = 10
EOC

WG_ADD_USER_CONF="/home/script/wg/${WG_ADD_USERNAME}__${WG_ADD_NIC}.conf"
cat > "$WG_ADD_USER_CONF" <<EOC
# IFACE=${WG_ADD_IFACE}
[Interface]
PrivateKey = ${WG_ADD_CLT_PRIV}
Address = ${WG_ADD_CLT_IP}/32
DNS = 168.126.63.1
MTU = 1380

[Peer]
PublicKey = ${WG_ADD_SRV_PUB}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${WG_ADD_SRV_IP}:${WG_ADD_SRV_PORT}
PersistentKeepalive = 10
EOC
chmod 600 "$WG_ADD_USER_CONF"
echo "created: $WG_ADD_USER_CONF"
EOF
chmod 755 "$BIN/wg-add-user.sh"

# ===== del-user (단락 파서 + 백업 + syncconf) =====
cat >"$BIN/wg-del-user.sh" <<"EOF"
#!/usr/bin/env bash
set -euo pipefail
WG_DEL_IFACE="${1:?usage: wg-del-user <wg-ensNN> <username_or_pubkey>}"
WG_DEL_ID="${2:?usage: wg-del-user <wg-ensNN> <username_or_pubkey>}"
WG_DEL_CONF="/etc/wireguard/${WG_DEL_IFACE}.conf"
[[ -f "$WG_DEL_CONF" ]] || { echo "no conf: $WG_DEL_CONF"; exit 1; }

WG_DEL_TS=$(date +%Y%m%d-%H%M%S)
cp -a "$WG_DEL_CONF" "${WG_DEL_CONF}.bak.${WG_DEL_TS}"

WG_DEL_MODE="name"
[[ "$WG_DEL_ID" =~ ^[A-Za-z0-9+/=]{40,}$ ]] && WG_DEL_MODE="key"

WG_DEL_TMP="$(mktemp)"
awk -v RS="" -v ORS="\n\n" -v mode="$WG_DEL_MODE" -v id="$WG_DEL_ID" '
  BEGIN{drop=0}
  /\[Peer\]/ {
    name=""; pub="";
    if (match($0, /(^|\n)[[:space:]]*#[[:space:]]*Name[[:space:]]*=[[:space:]]*([^\n\r]+)/, m)) {
      name=m[2]; gsub(/^[[:space:]]+|[[:space:]]+$/,"",name);
    }
    if (match($0, /(^|\n)[[:space:]]*PublicKey[[:space:]]*=[[:space:]]*([A-Za-z0-9+\/=]+)/, k)) {
      pub=k[2];
    }
    hit=0;
    if (mode=="name" && name==id) hit=1;
    else if (mode=="key" && pub==id) hit=1;
    if (hit==1) { drop++; next }
  }
  { print $0 }
  END{
    if (drop==0) exit 10;
    if (drop>1)  exit 11;
  }
' "$WG_DEL_CONF" > "$WG_DEL_TMP" || rc=$?

if [[ "${rc:-0}" -eq 10 ]]; then
  echo "peer not found: $WG_DEL_ID"; rm -f "$WG_DEL_TMP"; exit 1
elif [[ "${rc:-0}" -eq 11 ]]; then
  echo "multiple peers matched; abort (ID=$WG_DEL_ID)"; rm -f "$WG_DEL_TMP"; exit 1
fi

install -m600 "$WG_DEL_TMP" "$WG_DEL_CONF"; rm -f "$WG_DEL_TMP"
wg syncconf "$WG_DEL_IFACE" <(wg-quick strip "$WG_DEL_CONF") || true

WG_DEL_ENS="${WG_DEL_IFACE#wg-}"
rm -f "/home/script/wg/${WG_DEL_ID}__${WG_DEL_ENS}.conf" 2>/dev/null || true

echo "removed: $WG_DEL_ID on ${WG_DEL_IFACE} (backup: ${WG_DEL_CONF}.bak.${WG_DEL_TS})"
EOF
chmod 755 "$BIN/wg-del-user.sh"

# ===== list-users =====
cat >"$BIN/wg-list-users.sh" <<"EOF"
#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
list_file() {
  local CONF="$1"
  [[ -f "$CONF" ]] || { echo "[WARN] skip (no file): $CONF" >&2; return; }
  echo "== $CONF =="
  awk -v RS="" '
    /\[Peer\]/ {
      name=""; pub="";
      if (match($0, /(^|\n)[[:space:]]*#[[:space:]]*Name[[:space:]]*=[[:space:]]*([^\n\r]+)/, m)) {
        name=m[2]; gsub(/^[[:space:]]+|[[:space:]]+$/,"",name);
      }
      if (match($0, /(^|\n)[[:space:]]*PublicKey[[:space:]]*=[[:space:]]*([A-Za-z0-9+\/=]+)/, k)) {
        pub=k[2];
      }
      printf("name=%s  pub=%s\n", name, pub);
    }
  ' "$CONF"
}
if [[ $# -ge 1 ]]; then
  list_file "$1"
else
  shopt -s nullglob
  files=(/etc/wireguard/wg-ens*.conf)
  (( ${#files[@]} )) || { echo "[INFO] no wg-ens*.conf under /etc/wireguard" >&2; exit 0; }
  for f in "${files[@]}"; do list_file "$f"; done
fi
EOF
chmod 755 "$BIN/wg-list-users.sh"

# ===== find-user =====
cat >"$BIN/wg-find-user.sh" <<"EOF"
#!/usr/bin/env bash
# usage: wg-find-user.sh <wg-ensNN> <username> [THRESHOLD_SEC]
set -euo pipefail
wg_find_main() {
  local WG_FIND_IFACE="${1:?usage: wg-find-user.sh <wg-ensNN> <username> [THRESHOLD_SEC]}"
  local WG_FIND_USERNAME="${2:?usage: wg-find-user.sh <wg-ensNN> <username> [THRESHOLD_SEC]}"
  local WG_FIND_THRESHOLD="${3:-180}"

  local WG_FIND_CONF="/etc/wireguard/${WG_FIND_IFACE}.conf"
  [[ -f "$WG_FIND_CONF" ]] || { echo "conf not found: $WG_FIND_CONF" >&2; return 1; }

  local WG_FIND_PUBKEY
  WG_FIND_PUBKEY="$(
    awk -v RS="" -v ORS="\n\n" -v WG_USERNAME="$WG_FIND_USERNAME" '
      /^\[Peer\]/ {
        name=""; pub="";
        if (match($0, /(^|\n)[[:space:]]*#[[:space:]]*Name[[:space:]]*=[[:space:]]*([^\n\r]+)/, m)) {
          name=m[2]; gsub(/^[[:space:]]+|[[:space:]]+$/,"",name);
        }
        if (match($0, /(^|\n)[[:space:]]*PublicKey[[:space:]]*=[[:space:]]*([A-Za-z0-9+\/=]+)/, k)) {
          pub=k[2];
        }
        if (name==WG_USERNAME) { print pub; exit }
      }
    ' "$WG_FIND_CONF"
  )"
  [[ -n "${WG_FIND_PUBKEY:-}" ]] || { echo "user ${WG_FIND_USERNAME} not found in ${WG_FIND_CONF}" >&2; return 2; }

  wg show "$WG_FIND_IFACE" dump | awk -v WG_PUB="$WG_FIND_PUBKEY" -v WG_TH="$WG_FIND_THRESHOLD" '
    BEGIN{found=0}
    $1==WG_PUB{
      found=1
      t=$5
      if (t==0) { print "False (never)"; next }
      age = systime()-t
      if (age>WG_TH) print "False (" age "s)"
      else print "True (" age "s)"
    }
    END{
      if (!found) print "peer-not-in-dump"
    }'
}
wg_find_main "$@"
EOF
chmod 755 "$BIN/wg-find-user.sh"

# ===== ed-user (enable/disable) =====
cat >"$BIN/wg-ed-user.sh" <<"EOF"
#!/usr/bin/env bash
# wg-ed-user.sh <wg-ensNN> <username> <enable|disable>
set -euo pipefail
I="${1:?iface}"; U="${2:?user}"; A="${3:?enable|disable}"
C="/etc/wireguard/${I}.conf"; [[ -f "$C" ]] || { echo "no conf: $C" >&2; exit 1; }
DENY="${WG_DENY_PUB:-COBLIX7ffX0CxUtkxgvmr1qRE91CNQHvhnU2z2RJ5G4=}"
if ! { printf '%s' "$DENY" | base64 -d >/dev/null 2>&1 && [ "$(printf '%s' "$DENY" | base64 -d | wc -c)" -eq 32 ]; }; then
  echo "invalid deny key" >&2; exit 2
fi
ts="$(date +%Y%m%d-%H%M%S)"; cp -a "$C" "${C}.bak.${ts}"
tmp="$(mktemp)"
awk -v RS="" -v ORS="\n\n" -v U="$U" -v A="$A" -v D="$DENY" '
function trim(s){gsub(/^[ \t]+|[ \t]+$/,"",s);return s}
BEGIN{found=0}
{
 if($0 ~ /^\[Peer\]/){
   name=""; if(match($0,/(^|\n)[[:space:]]*#[[:space:]]*Name[[:space:]]*=[[:space:]]*([^\n\r]+)/,m)) name=trim(m[2]);
   if(name==U){
     found++
     cur=""; if(match($0,/(^|\n)[[:space:]]*PublicKey[[:space:]]*=[[:space:]]*([A-Za-z0-9+\/=]+)/,k)) cur=k[2];
     orig=""; if(match($0,/(^|\n)[[:space:]]*#[[:space:]]*OrigPublicKey[[:space:]]*=[[:space:]]*([A-Za-z0-9+\/=]+)/,o)) orig=o[2];
     if(A=="disable"){
       if(orig=="") gsub(/(^|\n)[[:space:]]*PublicKey[[:space:]]*=[[:space:]]*[A-Za-z0-9+\/=]+/,
                         "\n# OrigPublicKey = " cur "\nPublicKey = " D, $0);
       else         gsub(/(^|\n)[[:space:]]*PublicKey[[:space:]]*=[[:space:]]*[A-Za-z0-9+\/=]+/,
                         "\nPublicKey = " D, $0);
       print $0; next
     } else if(A=="enable"){
       if(orig==""){ print "OrigPublicKey missing for user="U > "/dev/stderr"; exit 10 }
       gsub(/(^|\n)[[:space:]]*PublicKey[[:space:]]*=[[:space:]]*[A-Za-z0-9+\/=]+/,
            "\nPublicKey = " orig, $0);
       print $0; next
     } else { print "action must be enable|disable" > "/dev/stderr"; exit 11 }
   }
 }
 print $0
}
END{
 if(found==0){ print "peer not found: "U > "/dev/stderr"; exit 12 }
 if(found>1){ print "multiple peers matched for: "U > "/dev/stderr"; exit 13 }
}
' "$C" > "$tmp"
install -m600 "$tmp" "$C"; rm -f "$tmp"
wg syncconf "$I" <(wg-quick strip "$C") || { echo "syncconf failed; restored ${C}.bak.${ts}" >&2; cp -a "${C}.bak.${ts}" "$C"; exit 20; }
echo "OK: $A $U on $I"
EOF
chmod 755 "$BIN/wg-ed-user.sh"

# ===== uninstall =====
cat >"$BIN/uninstall_wg.sh" <<"EOF"
#!/usr/bin/env bash
set -euo pipefail
echo "[+] Stop wg-quick services"
systemctl list-units --type=service --all | awk '/wg-quick@wg-ens[0-9]+\.service/{print $1}' \
| while read -r s; do systemctl stop "$s" 2>/dev/null || true; systemctl disable "$s" 2>/dev/null || true; done

echo "[+] Remove policy rules/routes"
for n in $(seq 1 254); do
  ip rule del from 10.10.$n.0/24 lookup $((3000+n)) priority $((30000+n)) 2>/dev/null || true
  ip route flush table $((3000+n)) 2>/dev/null || true
  FM=$(printf '0x%04X' $((0x3000 + n)))
  ip rule del fwmark "$FM" lookup $((3000+n)) priority $((30000+n-1)) 2>/dev/null || true
done
ip rule show | awk '/lookup 30[0-9]{2}/ {print $1}' | while read -r p; do ip rule del priority "$p" 2>/dev/null || true; done

echo "[+] Remove WG SNAT rules"
iptables -t nat -S POSTROUTING | awk '/-s 10\.10\.[0-9]+\.0\/24/ && /-j SNAT/ {sub(/^-A POSTROUTING /,""); print}' \
| while read -r spec; do iptables -w 1 -t nat -D POSTROUTING $spec 2>/dev/null || true; done

echo "[+] Remove INPUT ACCEPT tags"
iptables -S INPUT | awk '/-m comment --comment "wg-mi:.*:[0-9]+:ACCEPT"/{sub("^-A INPUT ","",$0); print}' \
| while read -r spec; do iptables -w 1 -D INPUT $spec 2>/dev/null || true; done

rm -f /etc/systemd/system/wg-reinit.service
rm -f /etc/systemd/system/wg-quick@.service.d/override.conf
rm -rf /etc/wireguard /home/script/wg
systemctl daemon-reload
echo "[+] Done."
EOF
chmod 755 "$BIN/uninstall_wg.sh"

# ===== 초기 자동 구성 =====
systemctl daemon-reload
echo "[+] Running setup_wg_iface.sh (auto ensNN)"
"$BIN/setup_wg_iface.sh" || echo "[WARN] setup_wg_iface.sh failed"

echo "[OK] WireGuard ready for all ensNN."
echo "Add user: $BIN/wg-add-user.sh wg-ens33 <user>"
echo "Del user: $BIN/wg-del-user.sh wg-ens33 <user>"
echo "List users: $BIN/wg-list-users.sh [/etc/wireguard/wg-ensNN.conf]"
echo "Find user(active<=180s?): $BIN/wg-find-user.sh wg-ens33 <user> [threshold]"
echo "Edit user(enable/disable): $BIN/wg-ed-user.sh wg-ens33 <user> <enable|disable>"
echo "Uninstall: $BIN/uninstall_wg.sh"
