#!/usr/bin/env bash
# install_wg_full.sh — multi-IF WireGuard FULL (무인자 자동, 안전 del)
# - ensNN 자동 + per-IF policy routing + SNAT + FwMark(응답 경로 고정)
# - NIC:PORT 입력 필터(코멘트 태깅)
# - add/del 유틸(정확일치, del은 단락 파서+백업+syncconf), list 유틸
# - 부팅 후 재적용(wg-reinit.service), network-online 이후
# - uninstall 포함 (OpenVPN/기존 SNAT 훼손 없음)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

BASE="/home/script/wg"
ETC_WG="/etc/wireguard"
BIN="/usr/local/sbin"
mkdir -p "$BASE" "$ETC_WG" /etc/systemd/system/wg-quick@.service.d
chmod 755 "$BASE"

# ===== pkgs =====
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y wireguard qrencode iproute2 >/dev/null 2>&1 || true

# ===== wg-quick drop-in: network-online 이후 =====
cat >/etc/systemd/system/wg-quick@.service.d/override.conf <<'EOF'
[Unit]
After=network-online.target
Wants=network-online.target
EOF
systemctl daemon-reload

# ===== helper: postup/postdown =====
cat >"$BIN/wg-mi-postup" <<"EOF"
#!/usr/bin/env bash
# usage: wg-mi-postup <NIC> <IFACE> <SUBNET> <TBL> <PRI> <PORT>
set -Eeu -o pipefail
NIC="$1"; IFACE="$2"; SUBNET="$3"; TBL="$4"; PRI="$5"; PORT="$6"

# NIC 상태/경로 파악
for _ in {1..50}; do
  SRC=$(ip -4 -o addr show dev "$NIC" | awk '{split($4,a,"/");print a[1]}') || true
  NET=$(ip -4 route show dev "$NIC" | awk '/proto kernel/ {print $1;exit}') || true
  GW=$(ip -4 route get 8.8.8.8 oif "$NIC" 2>/dev/null | awk '/via/ {for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}') || true
  [[ -n "${SRC:-}" && -n "${NET:-}" && -n "${GW:-}" ]] && break
  sleep 0.1
done
[[ -z "${SRC:-}" || -z "${NET:-}" || -z "${GW:-}" ]] && { echo "[wg-mi-postup] missing param" >&2; exit 0; }

# 정책 라우팅(rp_filter loose)
sysctl -wq "net.ipv4.conf.$NIC.rp_filter=2" || true
sysctl -wq "net.ipv4.conf.$IFACE.rp_filter=2" || true
ip route replace table "$TBL" "$NET" dev "$NIC" scope link src "$SRC" || true
ip route replace table "$TBL" default via "$GW" dev "$NIC" onlink src "$SRC" || true
ip rule add from "$SUBNET" lookup "$TBL" priority "$PRI" 2>/dev/null || true

# fwmark -> 응답경로 고정
IFNUM="$(sed 's/[^0-9]//g' <<<"$NIC")"
FWMARK_HEX="$(printf '0x%04X' "$(( 0x3000 + IFNUM ))")"
ip rule add fwmark "$FWMARK_HEX" lookup "$TBL" priority "$((PRI-1))" 2>/dev/null || true

# SNAT
iptables -w 1 -t nat -C POSTROUTING -s "$SUBNET" -o "$NIC" -j SNAT --to-source "$SRC" 2>/dev/null \
  || iptables -w 1 -t nat -A POSTROUTING -s "$SUBNET" -o "$NIC" -j SNAT --to-source "$SRC"

# 입력 필터(NIC:PORT만 허용, 동일 포트 타 NIC 드롭)
iptables -w 1 -C INPUT -i "$NIC" -p udp --dport "$PORT" -m comment --comment "wg-mi:$NIC:$PORT:ACCEPT" -j ACCEPT 2>/dev/null || \
iptables -w 1 -I INPUT -i "$NIC" -p udp --dport "$PORT" -m comment --comment "wg-mi:$NIC:$PORT:ACCEPT" -j ACCEPT
iptables -w 1 -C INPUT -p udp --dport "$PORT" -m comment --comment "wg-mi:*:$PORT:DROP" -j DROP 2>/dev/null || \
iptables -w 1 -A INPUT -p udp --dport "$PORT" -m comment --comment "wg-mi:*:$PORT:DROP" -j DROP

# 이웃 캐시 예열
ping -c1 -W1 "$GW" >/dev/null 2>&1 || true
EOF
chmod 755 "$BIN/wg-mi-postup"

cat >"$BIN/wg-mi-postdown" <<"EOF"
#!/usr/bin/env bash
# usage: wg-mi-postdown <NIC> <SUBNET> <TBL> <PRI> <PORT>
set -Eeu -o pipefail
NIC="$1"; SUBNET="$2"; TBL="$3"; PRI="$4"; PORT="$5"
SRC="$(ip -4 -o addr show dev "$NIC" 2>/dev/null | awk '{split($4,a,"/");print a[1]}')" || true

# INPUT 필터 제거(코멘트 태그)
iptables -S INPUT | awk -v nic="$NIC" -v port="$PORT" '
/^-A INPUT/ && /-p udp/ && ("--dport "port) && /-m comment --comment "wg-mi:/ {
  if ($0 ~ "wg-mi:"nic":"port":ACCEPT" || $0 ~ "wg-mi:\\*:"port":DROP") {
    sub("^-A INPUT ",""); print
  }
}' | while read -r spec; do iptables -w 1 -D INPUT $spec 2>/dev/null || true; done

# SNAT 제거
if [[ -n "${SRC:-}" ]]; then
  iptables -w 1 -t nat -D POSTROUTING -s "$SUBNET" -o "$NIC" -j SNAT --to-source "$SRC" 2>/dev/null || true
fi

# 정책 라우팅 제거
ip rule del from "$SUBNET" lookup "$TBL" priority "$PRI" 2>/dev/null || true
ip route flush table "$TBL" 2>/dev/null || true

# fwmark 제거
IFNUM="$(sed 's/[^0-9]//g' <<<"$NIC")"
FWMARK_HEX="$(printf '0x%04X' "$(( 0x3000 + IFNUM ))")"
ip rule del fwmark "$FWMARK_HEX" lookup "$TBL" priority "$((PRI-1))" 2>/dev/null || true
EOF
chmod 755 "$BIN/wg-mi-postdown"

# ===== setup_wg_iface.sh — ensNN 자동 (BIN으로 이동) =====
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
  if [[ -f "$CONF" ]]; then IFS='|' read -r SRV_PRIV PORT < <(parse_priv_port "$CONF"); fi
  if [[ -z "${SRV_PRIV:-}" || -z "${PORT:-}" || -z "${PEERS:-}" ]]; then
    local RUN; RUN="$(wg showconf "$IFACE" 2>/dev/null || true)"
    [[ -z "${SRV_PRIV:-}" ]] && SRV_PRIV="$(awk '/^PrivateKey/{print $3;exit}' <<<"$RUN" || true)"
    [[ -z "${PORT:-}"     ]] && PORT="$(awk '/^ListenPort/{print $3;exit}' <<<"$RUN" || true)"
    [[ -z "${PEERS:-}"    ]] && PEERS="$(awk 'BEGIN{p=0} /^\[Peer\]/{p=1} p' <<<"$RUN")"
  fi
  PORT="${PORT:-$DEFAULT_PORT}"
  SRV_PRIV="$(normalize_b64 "${SRV_PRIV:-}")"; [[ -n "${SRV_PRIV:-}" ]] || SRV_PRIV="$(wg genkey)"
  if [[ -z "${PEERS:-}" && -f "$CONF" ]]; then PEERS="$(awk 'BEGIN{keep=0} /^\[Peer\]/{keep=1} {if(keep)print}' "$CONF")"; fi

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
  wg-quick strip "$TMP" >/dev/null
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

# ===== add-user (정확일치 중복차단, DNS=168.126.63.1) — BIN으로 이동 =====
cat >"$BIN/wg-add-user.sh" <<"EOF"
#!/usr/bin/env bash
set -euo pipefail
IFACE="${1:?usage: wg-add-user <wg-ensNN> <username>}"
USER="${2:?usage: wg-add-user <wg-ensNN> <username>}"

CONF="/etc/wireguard/${IFACE}.conf"; [[ -f "$CONF" ]] || { echo "no conf: $CONF"; exit 1; }
NIC="${IFACE#wg-}"

SRV_PUB="$(wg show ${IFACE} public-key 2>/dev/null || awk -F'= *' '/^PrivateKey/{print $2}' "$CONF" | head -n1 | wg pubkey)"
SRV_PORT="$(awk -F'= *' '/^ListenPort/{print $2}' "$CONF")"
SRV_IP="$(ip -4 -o addr show dev "${NIC}" | awk '{split($4,a,"/");print a[1]}')"
BASE_NET="$(awk -F'[ ./]' '/^Address/{print $3"."$4"."$5}' "$CONF" | head -n1)"

# 정확일치 중복 이름 차단
mapfile -t __NAMES__ < <(
  awk '/^#[[:space:]]*Name[[:space:]]*=/{
         t=$0; sub(/.*=/,"",t);
         gsub(/^[[:space:]]+|[[:space:]]+$/,"",t);
         print t
       }' "$CONF"
)
if printf '%s\n' "${__NAMES__[@]}" | grep -qxF "$USER"; then
  echo "user name already exists on ${IFACE}: ${USER}" >&2
  exit 3
fi

# 다음 /32 할당
mapfile -t USED < <(wg show ${IFACE} allowed-ips 2>/dev/null | awk '{print $2}' | cut -d/ -f1 | awk -F. -v b="$BASE_NET" '$1"."$2"."$3==b{print $4}' | sort -n)
NEXT=2; for i in {2..254}; do if ! printf '%s\n' "${USED[@]}" | grep -qx "$i"; then NEXT="$i"; break; fi; done
[[ $NEXT -le 254 ]] || { echo "pool exhausted"; exit 2; }
CLT_IP="${BASE_NET}.${NEXT}"

# 키 생성 & 런타임 반영
umask 077
CLT_PRIV="$(wg genkey)"; CLT_PUB="$(printf "%s" "$CLT_PRIV" | wg pubkey)"
wg set ${IFACE} peer "$CLT_PUB" allowed-ips "${CLT_IP}/32" persistent-keepalive 10

# 서버 conf append (단락 구분 한 줄 확보)
tail -c1 "$CONF" | read -r _ || echo >> "$CONF"
cat >> "$CONF" <<EOC

[Peer]
# Name = ${USER}
PublicKey = ${CLT_PUB}
AllowedIPs = ${CLT_IP}/32
PersistentKeepalive = 10
EOC

# 클라 프로필
USER_CONF="/home/script/wg/${USER}__${NIC}.conf"
cat > "$USER_CONF" <<EOC
# IFACE=${IFACE}
[Interface]
PrivateKey = ${CLT_PRIV}
Address = ${CLT_IP}/32
DNS = 168.126.63.1

[Peer]
PublicKey = ${SRV_PUB}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${SRV_IP}:${SRV_PORT}
PersistentKeepalive = 10
EOC
chmod 600 "$USER_CONF"
echo "created: $USER_CONF"
command -v qrencode >/dev/null && qrencode -t ansiutf8 < "$USER_CONF" || true
EOF
chmod 755 "$BIN/wg-add-user.sh"

# ===== del-user (단락 파서 + 백업 + 단일블록만 삭제 + syncconf) — BIN으로 이동 =====
cat >"$BIN/wg-del-user.sh" <<"EOF"
#!/usr/bin/env bash
# wg-del-user.sh — paragraph-safe deleter (exact match, single block only)
set -euo pipefail
IFACE="${1:?usage: wg-del-user <wg-ensNN> <username_or_pubkey>}"
ID="${2:?usage: wg-del-user <wg-ensNN> <username_or_pubkey>}"
CONF="/etc/wireguard/${IFACE}.conf"
[[ -f "$CONF" ]] || { echo "no conf: $CONF"; exit 1; }

TS=$(date +%Y%m%d-%H%M%S)
cp -a "$CONF" "${CONF}.bak.${TS}"

MODE="name"
[[ "$ID" =~ ^[A-Za-z0-9+/=]{40,}$ ]] && MODE="key"

TMP="$(mktemp)"
# 문단(RS="") 기준으로 [Peer] 블록만 검사, 매치된 블록만 drop
awk -v RS="" -v ORS="\n\n" -v mode="$MODE" -v id="$ID" '
  BEGIN{drop=0}
  /\[Peer\]/ {
    name=""; pub="";
    if (match($0, /(^|\n)[[:space:]]*#[[:space:]]*Name[[:space:]]*=[[:space:]]*([^\n\r]+)/, m)) {
      name=m[2]; gsub(/^[[:space:]]+|[[:space:]]+$/, "", name);
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
' "$CONF" > "$TMP" || rc=$?

if [[ "${rc:-0}" -eq 10 ]]; then
  echo "peer not found: $ID"; rm -f "$TMP"; exit 1
elif [[ "${rc:-0}" -eq 11 ]]; then
  echo "multiple peers matched; abort (ID=$ID)"; rm -f "$TMP"; exit 1
fi

install -m600 "$TMP" "$CONF"; rm -f "$TMP"

# 런타임 sync (재시작 불필요)
wg syncconf "$IFACE" <(wg-quick strip "$CONF") || true

# 관련 프로필 제거(존재하면)
ENS="${IFACE#wg-}"
rm -f "/home/script/wg/${ID}__${ENS}.conf" 2>/dev/null || true

echo "removed: $ID on ${IFACE} (backup: ${CONF}.bak.${TS})"
EOF
chmod 755 "$BIN/wg-del-user.sh"

# ===== list-users (변경 없음, BIN에 유지) =====
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
        name=m[2]; gsub(/^[[:space:]]+|[[:space:]]+$/, "", name);
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

# ===== uninstall (빠른 규칙 제거 + 코멘트 기반) =====
cat >"$BIN/uninstall_wg.sh" <<"EOF"
#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

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

echo "[+] Remove NIC-bound INPUT filters (comment-tagged fast)"
iptables -S INPUT | awk '/-m comment --comment "wg-mi:/ {sub("^-A INPUT ","",$0); print}' \
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
echo "Uninstall: $BIN/uninstall_wg.sh"
