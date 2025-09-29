#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

BASE="/home/script/wg"
ETC_WG="/etc/wireguard"
STATE="/var/lib/wireguard"
mkdir -p "$BASE" "$ETC_WG" "$STATE"
chmod 755 "$BASE"

apt-get update
apt-get install -y wireguard qrencode iproute2 iptables

cat >/etc/sysctl.d/99-wireguard-forward.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
sysctl --system >/dev/null

# ================= setup_wg_iface.sh =================
cat >"${BASE}/setup_wg_iface.sh" <<"EOF"
#!/usr/bin/env bash
set -euo pipefail

setup_one() {
  local NIC="$1"
  local REQ_PORT="${2:-}"

  local NUM; NUM="$(echo "$NIC" | sed 's/[^0-9]//g')"
  [[ -n "$NUM" ]] || { echo "skip $NIC: no numeric suffix"; return 0; }

  local IFACE="wg-${NIC}"
  local CONF="/etc/wireguard/${IFACE}.conf"
  local STATE_DIR="/var/lib/wireguard/${IFACE}"
  mkdir -p "${STATE_DIR}"

  local DEFAULT_PORT="$((50000 + NUM))"
  local SUBNET="10.10.${NUM}.0/24"
  local GATEWAY="10.10.${NUM}.1/24"
  local SRV_IP; SRV_IP="$(ip -o -4 addr show dev "${NIC}" | awk '{print $4}' | cut -d/ -f1 || true)"
  [[ -n "${SRV_IP}" ]] || { echo "skip $NIC: no IPv4"; return 0; }

  local EXIST_PRIV=""; local EXIST_PORT=""
  if [[ -f "${CONF}" ]]; then
    EXIST_PRIV="$(awk -F'= *' '/^PrivateKey/{print $2}' "${CONF}" || true)"
    EXIST_PORT="$(awk -F'= *' '/^ListenPort/{print $2}' "${CONF}" || true)"
  fi

  umask 077
  local SRV_PRIV
  if [[ -n "${EXIST_PRIV}" ]]; then SRV_PRIV="${EXIST_PRIV}"; else SRV_PRIV="$(wg genkey)"; fi
  local SRV_PUB; SRV_PUB="$(printf "%s" "$SRV_PRIV" | wg pubkey)"

  local USE_PORT
  if [[ -n "${REQ_PORT}" ]]; then
    USE_PORT="${REQ_PORT}"
  elif [[ -n "${EXIST_PORT}" ]]; then
    USE_PORT="${EXIST_PORT}"
  else
    USE_PORT="${DEFAULT_PORT}"
  fi

  cat > "${CONF}" <<EOC
[Interface]
Address = ${GATEWAY}
ListenPort = ${USE_PORT}
PrivateKey = ${SRV_PRIV}
PostUp   = iptables -C -t nat POSTROUTING -o ${NIC} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ${NIC} -j MASQUERADE; \
           iptables -C INPUT -p udp --dport ${USE_PORT} -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport ${USE_PORT} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${NIC} -j MASQUERADE || true; \
           iptables -D INPUT -p udp --dport ${USE_PORT} -j ACCEPT || true
EOC
  chmod 600 "${CONF}"

  systemctl enable "wg-quick@${IFACE}" >/dev/null
  systemctl restart "wg-quick@${IFACE}"

  local PREV_IP_FILE="${STATE_DIR}/endpoint_ip"
  local PREV_IP=""; [[ -f "$PREV_IP_FILE" ]] && PREV_IP="$(cat "$PREV_IP_FILE")"
  if [[ "${PREV_IP}" != "${SRV_IP}" ]]; then
    echo "${SRV_IP}" > "${PREV_IP_FILE}"
    for f in /home/script/wg/*.conf; do
      [[ -f "$f" ]] || continue
      head -n1 "$f" | grep -q "^# IFACE=${IFACE}$" || continue
      sed -i "s/^Endpoint = .*/Endpoint = ${SRV_IP}:${USE_PORT}/" "$f"
    done
  fi

  echo "UP ${IFACE}  subnet=${SUBNET}  endpoint=${SRV_IP}:${USE_PORT}"
}

# 인자 있으면 해당 NIC만 처리
if (( $# >= 1 )); then
  NIC="$1"; PORT="${2:-}"
  setup_one "$NIC" "$PORT"
  exit 0
fi

# 인자 없으면 ensNN IPv4 NIC 자동 탐색
mapfile -t CANDS < <(
  ip -o -4 addr show | awk '{print $2}' \
  | sed 's/@.*//' | sort -u | grep -E '^ens[0-9]+$'
)
if (( ${#CANDS[@]} == 0 )); then
  echo "no candidate NICs found (need ensNN with IPv4)"
  exit 1
fi

for nic in "${CANDS[@]}"; do
  if ip -o link show dev "$nic" | grep -q "state UP"; then
    setup_one "$nic"
  else
    echo "skip $nic: link DOWN"
  fi
done
EOF
chmod +x "${BASE}/setup_wg_iface.sh"

# ================= wg-add-user.sh =================
cat >"${BASE}/wg-add-user.sh" <<"EOF"
#!/usr/bin/env bash
set -euo pipefail
IFACE="${1:?usage: wg-add-user <wg-ensNN> <username>}"
USER="${2:?usage: wg-add-user <wg-ensNN> <username>}"
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
DNS = 8.8.8.8

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

# ================= wg-del-user.sh =================
cat >"${BASE}/wg-del-user.sh" <<"EOF"
#!/usr/bin/env bash
set -euo pipefail
IFACE="${1:?usage: wg-del-user <wg-ensNN> <username_or_pubkey>}"
ID="${2:?usage: wg-del-user <wg-ensNN> <username_or_pubkey>}"
CONF="/etc/wireguard/${IFACE}.conf"
[[ -f "$CONF" ]] || { echo "no conf: $CONF"; exit 1; }

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

rm -f "/home/script/wg/${ID}.conf" || true
echo "removed: $ID"
EOF
chmod +x "${BASE}/wg-del-user.sh"

echo "OK. Use:"
echo "  ${BASE}/setup_wg_iface.sh            # 자동 모드(ensNN NIC 전부)"
echo "  ${BASE}/setup_wg_iface.sh ens34      # 단일 NIC, 포트 50034"
echo "  ${BASE}/wg-add-user.sh wg-ens34 alice"
echo "  ${BASE}/wg-del-user.sh wg-ens34 alice"
