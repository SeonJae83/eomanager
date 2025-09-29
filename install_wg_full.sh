#!/usr/bin/env bash
set -euo pipefail

# ===== guard =====
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
command -v apt-get >/dev/null || { echo "apt-based distro required"; exit 1; }

BASE="/home/script/wg"
ETC_WG="/etc/wireguard"
STATE="/var/lib/wireguard"   # IP 변경 추적
mkdir -p "$BASE" "$ETC_WG" "$STATE"
chmod 755 "$BASE"

# ===== packages + sysctl =====
apt-get update
apt-get install -y wireguard qrencode iproute2 iptables
cat >/etc/sysctl.d/99-wireguard-forward.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
sysctl --system >/dev/null

# ===== setup_wg_iface.sh =====
cat >"${BASE}/setup_wg_iface.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

NIC="${1:?usage: setup_wg_iface.sh <ensXX> [listen_port]}"
NUM="$(echo "$NIC" | sed 's/[^0-9]//g')"
[[ -n "$NUM" ]] || { echo "cannot parse number from NIC: $NIC"; exit 1; }
PORT="${2:-$((51820 + NUM))}"

IFACE="wg-${NIC}"
CONF="/etc/wireguard/${IFACE}.conf"
STATE_DIR="/var/lib/wireguard/${IFACE}"
mkdir -p "${STATE_DIR}"

SUBNET="10.10.${NUM}.0/24"
GATEWAY="10.10.${NUM}.1/24"

SRV_IP="$(ip -o -4 addr show dev "${NIC}" | awk '{print $4}' | cut -d/ -f1 || true)"
[[ -n "${SRV_IP}" ]] || { echo "no IPv4 on ${NIC}"; exit 2; }

# 유지: 기존 키/포트 재사용
EXIST_PRIV=""; EXIST_PORT=""
if [[ -f "${CONF}" ]]; then
  EXIST_PRIV="$(awk -F'= *' '/^PrivateKey/{print $2}' "${CONF}" || true)"
  EXIST_PORT="$(awk -F'= *' '/^ListenPort/{print $2}' "${CONF}" || true)"
fi

# 키 결정
umask 077
if [[ -n "${EXIST_PRIV}" ]]; then
  SRV_PRIV="${EXIST_PRIV}"
else
  SRV_PRIV="$(wg genkey)"
fi
SRV_PUB="$(printf "%s" "$SRV_PRIV" | wg pubkey)"

# 포트 결정
if [[ -n "${2:-}" ]]; then
  USE_PORT="${PORT}"
elif [[ -n "${EXIST_PORT}" ]]; then
  USE_PORT="${EXIST_PORT}"
else
  USE_PORT="${PORT}"
fi

# 설정 재작성(멱등)
cat > "${CONF}" <<EOC
[Interface]
Address = ${GATEWAY}
ListenPort = ${USE_PORT}
PrivateKey = ${SRV_PRIV}
PostUp   = iptables -t nat -A POSTROUTING -o ${NIC} -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o ${NIC} -j MASQUERADE
EOC
chmod 600 "${CONF}"

# 서비스 적용
systemctl enable wg-quick@${IFACE} >/dev/null
systemctl restart wg-quick@${IFACE}

# ----- NIC IP 변경 감지 및 유저 프로파일 Endpoint 갱신 -----
PREV_IP_FILE="${STATE_DIR}/endpoint_ip"
PREV_IP="$(cat "${PREV_IP_FILE}" 2>/dev/null || true)"
if [[ "${PREV_IP}" != "${SRV_IP}" ]]; then
  echo "${SRV_IP}" > "${PREV_IP_FILE}"
  # /home/script/wg/*.conf 중 이 IFACE에 속한 프로파일만 갱신
  # 식별: 파일 첫 줄에 "# IFACE=wg-ensXX" 태그를 둔다.
  for f in /home/script/wg/*.conf; do
    [[ -f "$f" ]] || continue
    head -n1 "$f" | grep -q "^# IFACE=${IFACE}$" || continue
    # Endpoint 라인만 새로운 IP:PORT로 교체
    if grep -q "^Endpoint = " "$f"; then
      sed -i "s/^Endpoint = .*/Endpoint = ${SRV_IP}:${USE_PORT}/" "$f"
    fi
  done
fi

echo "UP ${IFACE}  subnet=${SUBNET}  endpoint=${SRV_IP}:${USE_PORT}"
echo "ServerPubKey: ${SRV_PUB}"
EOF
chmod +x "${BASE}/setup_wg_iface.sh"

# ===== wg-add-user.sh =====
cat >"${BASE}/wg-add-user.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
IFACE="${1:?usage: wg-add-user <wg-ensXX> <username>}"
USER="${2:?usage: wg-add-user <wg-ensXX> <username>}"
CONF="/etc/wireguard/${IFACE}.conf"
[[ -f "$CONF" ]] || { echo "no conf: $CONF"; exit 1; }

NIC="${IFACE#wg-}"
SRV_PUB="$(wg show ${IFACE} public-key || true)"
SRV_PORT="$(awk -F'= *' '/^ListenPort/{print $2}' "$CONF")"
SRV_IP="$(ip -o -4 addr show dev "${NIC}" | awk '{print $4}' | cut -d/ -f1)"

BASE_NET="$(awk -F'[ ./]' '/^Address/{print $3"."$4"."$5}' "$CONF" | head -n1)"
USED_LAST="$(wg show ${IFACE} allowed-ips 2>/dev/null | awk '{print $2}' | cut -d/ -f1 | awk -F. -v b="$BASE_NET" '$1"."$2"."$3==b{print $4}')"
NEXT=2; [[ -n "$USED_LAST" ]] && NEXT=$(( $(echo "$USED_LAST" | sort -n | tail -1) + 1 ))
[[ $NEXT -le 254 ]] || { echo "pool exhausted"; exit 2; }
CLT_IP="${BASE_NET}.${NEXT}"

umask 077
CLT_PRIV="$(wg genkey)"; CLT_PUB="$(printf "%s" "$CLT_PRIV" | wg pubkey)"

wg set ${IFACE} peer "$CLT_PUB" allowed-ips "${CLT_IP}/32" persistent-keepalive 25

# 서버 conf에 영구 반영
cat >> "$CONF" <<EOC

# ${USER}
[Peer]
# Name = ${USER}
PublicKey = ${CLT_PUB}
AllowedIPs = ${CLT_IP}/32
PersistentKeepalive = 25
EOC

USER_CONF="/home/script/wg/${USER}.conf"
cat > "$USER_CONF" <<EOC
# IFACE=${IFACE}
[Interface]
PrivateKey = ${CLT_PRIV}
Address = ${CLT_IP}/32
DNS = 1.1.1.1

[Peer]
PublicKey = ${SRV_PUB}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${SRV_IP}:${SRV_PORT}
PersistentKeepalive = 25
EOC
chmod 600 "$USER_CONF"

echo "created: $USER_CONF"
command -v qrencode >/dev/null && qrencode -t ansiutf8 < "$USER_CONF" || true
EOF
chmod +x "${BASE}/wg-add-user.sh"

# ===== wg-del-user.sh =====
cat >"${BASE}/wg-del-user.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
IFACE="${1:?usage: wg-del-user <wg-ensXX> <username_or_pubkey>}"
ID="${2:?usage: wg-del-user <wg-ensXX> <username_or_pubkey>}"
CONF="/etc/wireguard/${IFACE}.conf"
[[ -f "$CONF" ]] || { echo "no conf: $CONF"; exit 1; }

# 공개키 or 유저명
if [[ "$ID" =~ ^[A-Za-z0-9+/=]{40,}$ ]]; then
  PUB="$ID"
else
  PUB="$(awk -v u="$ID" '
    $0 ~ "^# "u"$" { flag=1 }
    flag && $1=="PublicKey" { gsub(/[[:space:]]/,""); split($0,a,"="); print a[2]; exit }
    /^\[Peer\]/ { flag=0 }
  ' "$CONF")"
fi
[[ -n "${PUB:-}" ]] || { echo "peer not found: $ID"; exit 1; }

wg set "$IFACE" peer "$PUB" remove

awk -v pub="$PUB" '
BEGIN{RS=""; ORS="\n\n"}
{
  block=$0
  gsub(/\n+$/,"\n",block)
  if (block ~ /\[Peer\]/ && block ~ "PublicKey *= *"pub) next
  print block
}' "$CONF" | sed '/^$/d' > "${CONF}.new"
install -m 600 "${CONF}.new" "$CONF"
rm -f "${CONF}.new"

# 유저 파일 제거 시도
rm -f "/home/script/wg/${ID}.conf" || true
echo "removed: $ID"
EOF
chmod +x "${BASE}/wg-del-user.sh"

echo "ready. scripts in ${BASE}"
echo "use: ${BASE}/setup_wg_iface.sh ens34"
echo "add : ${BASE}/wg-add-user.sh wg-ens34 alice"
echo "del : ${BASE}/wg-del-user.sh wg-ens34 alice"
