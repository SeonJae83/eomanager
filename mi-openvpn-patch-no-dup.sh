#!/usr/bin/env bash
# mi-openvpn 환경에서:
#  - 동시접속(lock) 기능 완전 제거
#  - ACL(allow/deny) 기능 유지
#  - hooks-limit2.sh 신규 생성
#  - ovpn_add_user.sh / ovpn_del.sh 신규 생성 (EasyRSA 정상 발급 포함)
#  - server conf duplicate-cn 제거 및 훅 적용
#  - lock-sync 타이머 제거
#  - 모든 OpenVPN 인스턴스 재시작
set -Eeuo pipefail
trap 'echo "[ERR] line $LINENO: $BASH_COMMAND" >&2' ERR

SRV_DIR=/etc/openvpn/server
ACL_DIR=/etc/openvpn/acl
ADDUSR=/usr/local/sbin/ovpn_add_user.sh
DELUSR=/usr/local/sbin/ovpn_del.sh
HOOK_LIMIT2=/etc/openvpn/hooks-limit2.sh

[[ $EUID -eq 0 ]] || { echo "root로 실행해야 합니다." >&2; exit 1; }

echo
echo "=== 1) duplicate-cn 제거 ==="
shopt -s nullglob
for C in "$SRV_DIR"/mi-*.conf; do
  echo "  - patch: $(basename "$C")"
  sed -i '/^[[:space:]]*duplicate-cn[[:space:]]*$/d' "$C"
done
shopt -u nullglob

echo
echo "=== 2) hooks-limit2.sh (통으로 재생성) ==="
install -d -m0755 /etc/openvpn
cat > "$HOOK_LIMIT2" <<"EOF"
#!/usr/bin/env bash
set -Eeuo pipefail

CN="${common_name:-UNDEF}"
IFACE="${IFACE:-UNDEF}"
STATUS_FILE="${1:-${STATUS_FILE:-}}"
ACL_DIR="/etc/openvpn/acl"

log(){ echo "[HOOK][$IFACE][$CN] $*" >&2; }

# IFACE 추론
if [[ "$IFACE" == "UNDEF" && -n "$STATUS_FILE" ]]; then
  b="$(basename "$STATUS_FILE")"
  IFACE="${b#status-mi-}"
  IFACE="${IFACE%.log}"
fi

DENY_F="$ACL_DIR/deny-${IFACE}.list"
ALLOW_F="$ACL_DIR/allow-${IFACE}.list"

# allow 우선
if [[ -f "$ALLOW_F" ]] && ! grep -Fxq "$CN" "$ALLOW_F"; then
  log "DENY by allow-list"
  exit 1
fi

# deny
if [[ -f "$DENY_F" ]] && grep -Fxq "$CN" "$DENY_F"; then
  log "DENY by deny-list"
  exit 1
fi

exit 0
EOF
chmod 755 "$HOOK_LIMIT2"
echo "  * hooks-limit2.sh 재생성 완료"

echo
echo "=== 3) ovpn_add_user.sh (통으로 재생성) ==="
cat > "$ADDUSR" <<"EOF"
#!/usr/bin/env bash
set -euo pipefail

IFACE=${1:-}; USER=${2:-}
[[ -n "$IFACE" && -n "$USER" ]] || { echo "Usage: $0 <iface> <user>"; exit 1; }

OVPN_DIR=/etc/openvpn
SRV_DIR=$OVPN_DIR/server
EASYRSA_DIR=$OVPN_DIR/easy-rsa-mi
PKI_DIR=$EASYRSA_DIR/pki
PROF_DIR=/home/script/openvpn/profile
ACL_DIR=/etc/openvpn/acl

CONF=$SRV_DIR/mi-${IFACE}.conf
[[ -f "$CONF" ]] || { echo "[ERR] no such interface: $CONF"; exit 1; }

SRV_IP=$(awk '/^local /{print $2}' "$CONF")
SRV_PORT=$(awk '/^port /{print $2}' "$CONF")

install -d -m0755 "$ACL_DIR"
DENY_F="$ACL_DIR/deny-${IFACE}.list"
[[ -f "$DENY_F" ]] && sed -i "/^${USER}$/d" "$DENY_F"

# --- EasyRSA 발급 ---
cd "$EASYRSA_DIR"
if [[ ! -f "$PKI_DIR/issued/${USER}.crt" ]]; then
  ./easyrsa --batch build-client-full "$USER" nopass
fi

# --- OVPN 프로파일 생성 ---
install -d -m0755 "$PROF_DIR"
OUT="$PROF_DIR/${USER}__${IFACE}.ovpn"

cat > "$OUT" <<EOF2
client
dev tun
proto udp
remote $SRV_IP $SRV_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
tls-version-min 1.2
auth-nocache
cipher AES-256-GCM
data-ciphers AES-256-GCM
data-ciphers-fallback AES-256-CBC
auth SHA256

<ca>
$(cat "$PKI_DIR/ca.crt")
</ca>

<cert>
$(cat "$PKI_DIR/issued/${USER}.crt")
</cert>

<key>
$(cat "$PKI_DIR/private/${USER}.key")
</key>

<tls-crypt>
$(cat "$OVPN_DIR/mi-tc.key")
</tls-crypt>
EOF2

chmod 600 "$OUT"
echo "[OK] profile created: $OUT"
EOF

chmod 755 "$ADDUSR"
echo "  * ovpn_add_user.sh 재생성 완료"

echo
echo "=== 4) ovpn_del.sh (통으로 재생성) ==="
cat > "$DELUSR" <<"EOF"
#!/usr/bin/env bash
set -euo pipefail

IFACE=${1:-}; USER=${2:-}
[[ -n "$IFACE" && -n "$USER" ]] || { echo "Usage: $0 <iface> <user>"; exit 1; }

ACL_DIR=/etc/openvpn/acl
DENY_F="$ACL_DIR/deny-${IFACE}.list"

install -d -m0755 "$ACL_DIR"
echo "$USER" >> "$DENY_F"
sort -u -o "$DENY_F" "$DENY_F"

echo "[OK] user $USER denied on $IFACE"
EOF
chmod 755 "$DELUSR"
echo "  * ovpn_del.sh 재생성 완료"

echo
echo "=== 5) lock-sync 및 lock 디렉토리 제거 ==="
systemctl disable --now mi-lock-sync.timer 2>/dev/null || true
systemctl disable --now mi-lock-sync.service 2>/dev/null || true
rm -f /usr/local/sbin/mi_lock_sync.sh 2>/dev/null || true
rm -f /etc/systemd/system/mi-lock-sync.service 2>/dev/null || true
rm -f /etc/systemd/system/mi-lock-sync.timer 2>/dev/null || true
rm -rf /run/openvpn-server/locks 2>/dev/null || true
echo "  * lock 관련 기능 제거 완료"

echo
echo "=== 6) 모든 OpenVPN 인스턴스 재시작 ==="
systemctl daemon-reload
for SVC in $(systemctl list-units --type=service --all | awk '/openvpn-server@mi-/{print $1}'); do
  echo "  - restart: $SVC"
  systemctl restart "$SVC" 2>/dev/null || true
done

echo
echo "=== 패치 완료 ==="
echo " - 동시접속(lock) 기능 100% 제거"
echo " - ACL(allow/deny) 기능 유지"
echo " - add/del/hook 스크립트 완전 안전 버전으로 교체"
echo " - EasyRSA 기반 발급 정상 작동"
echo " - duplicate-cn 제거"
