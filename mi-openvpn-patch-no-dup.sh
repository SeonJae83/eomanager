#!/usr/bin/env bash
# mi-openvpn-patch-no-dup.sh
# -----------------------------------------------------------
# 기존 mi-openvpn 환경에서:
#  - duplicate-cn 제거
#  - 동시접속 제한(lock 기반 기능) 완전히 제거
#  - hooks-limit2.sh → ACL 전용 훅으로 덮어쓰기
#  - ovpn_add_user.sh, ovpn_del.sh 원본 기능 100% 유지
#    (deny / mgmt-kill / profile 삭제는 그대로 유지)
#  - EasyRSA 발급 기능 정상 유지
#  - per-instance ExecStartPost(mi_route_repair.sh) 제거
#  - 부팅 후 60초 뒤 1회만 mi_route_repair.sh 실행하는
#    oneshot 서비스 + 타이머 생성
# -----------------------------------------------------------
set -Eeuo pipefail
trap 'echo "[ERR] line $LINENO: $BASH_COMMAND" >&2' ERR

SRV_DIR=/etc/openvpn/server
ACL_DIR=/etc/openvpn/acl
HOOK_LIMIT2=/etc/openvpn/hooks-limit2.sh
ADDUSR=/usr/local/sbin/ovpn_add_user.sh
DELUSR=/usr/local/sbin/ovpn_del.sh
ROUTE_ONBOOT_SVC=/etc/systemd/system/mi-route-repair-onboot.service
ROUTE_ONBOOT_TMR=/etc/systemd/system/mi-route-repair-onboot.timer

echo "=== mi-openvpn-patch-no-dup.sh 실행 ==="

# -----------------------------------------------------------
# 1) server conf에서 duplicate-cn 제거
# -----------------------------------------------------------
echo "=== 1) duplicate-cn 제거 ==="
shopt -s nullglob
for C in "$SRV_DIR"/mi-*.conf; do
    echo " - 패치: $(basename "$C")"
    sed -i '/^[[:space:]]*duplicate-cn[[:space:]]*$/d' "$C"
done
shopt -u nullglob


# -----------------------------------------------------------
# 2) hooks-limit2.sh ACL 전용으로 완전 덮어쓰기
# -----------------------------------------------------------
echo "=== 2) hooks-limit2.sh -> ACL 전용으로 교체 ==="

install -d -m0755 "$(dirname "$HOOK_LIMIT2")"

cat > "$HOOK_LIMIT2" <<'EOF'
#!/usr/bin/env bash
# hooks-limit2.sh — ACL 전용 훅 (동시접속 제한 없음)
set -Eeuo pipefail

CN="${common_name:-UNDEF}"
IFACE="${IFACE:-UNDEF}"
STATUS_FILE="${1:-${STATUS_FILE:-}}"
ACL_DIR="/etc/openvpn/acl"

log(){ echo "[HOOK][$IFACE][$CN] $*" >&2; }

# STATUS_FILE 기반으로 인터페이스 추론
if [[ "$IFACE" == "UNDEF" && -n "$STATUS_FILE" ]]; then
  b="$(basename "$STATUS_FILE")"
  IFACE="${b#status-mi-}"
  IFACE="${IFACE%.log}"
fi

DENY_F="$ACL_DIR/deny-${IFACE}.list"
ALLOW_F="$ACL_DIR/allow-${IFACE}.list"

# allow 우선
if [[ -f "$ALLOW_F" ]] && ! grep -Fxq "$CN" "$ALLOW_F" 2>/dev/null; then
  log "DENY by allow-list"
  exit 1
fi

# deny 적용
if [[ -f "$DENY_F" ]] && grep -Fxq "$CN" "$DENY_F" 2>/dev/null; then
  log "DENY by deny-list"
  exit 1
fi

# 동시접속 제한/락 로직 없음
exit 0
EOF

chmod 755 "$HOOK_LIMIT2"


# -----------------------------------------------------------
# 3) 동시접속 lock sync/타이머 완전 제거
# -----------------------------------------------------------
echo "=== 3) lock-sync 제거 ==="

systemctl disable --now mi-lock-sync.timer  >/dev/null 2>&1 || true
systemctl disable --now mi-lock-sync.service >/dev/null 2>&1 || true
rm -f /usr/local/sbin/mi_lock_sync.sh >/dev/null 2>&1 || true
rm -f /etc/systemd/system/mi-lock-sync.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/mi-lock-sync.timer   >/dev/null 2>&1 || true

rm -rf /run/openvpn-server/locks >/dev/null 2>&1 || true


# -----------------------------------------------------------
# 4) ADD/DEL 스크립트 덮어쓰기
#    - EasyRSA 발급 / deny / mgmt-kill / profile 삭제 유지
#    - lock 관련 코드 없음
# -----------------------------------------------------------
echo "=== 4) ADD/DEL 스크립트 덮어쓰기 ==="

# ---------------------- ADD ----------------------
cat > "$ADDUSR" <<'EOF'
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

cd "$EASYRSA_DIR"
if [[ ! -f "$PKI_DIR/issued/${USER}.crt" ]]; then
  ./easyrsa --batch build-client-full "$USER" nopass
fi

install -d -m0755 "$PROF_DIR"
OUT="$PROF_DIR/${USER}__${IFACE}.ovpn"

cat > "$OUT" <<EOFX
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
EOFX

chmod 600 "$OUT"
echo "[OK] profile created: $OUT"
EOF

chmod 755 "$ADDUSR"


# ---------------------- DEL ----------------------
cat > "$DELUSR" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

IFACE=${1:-}; USER=${2:-}
[[ -n "$IFACE" && -n "$USER" ]] || { echo "Usage: $0 <iface> <user>"; exit 1; }

ACL_DIR=/etc/openvpn/acl
PROF_DIR=/home/script/openvpn/profile
CONF=/etc/openvpn/server/mi-${IFACE}.conf
[[ -f "$CONF" ]] || { echo "[ERR] no $CONF"; exit 1; }

install -d -m0755 "$ACL_DIR"
DENY_F="$ACL_DIR/deny-${IFACE}.list"

grep -Fxq "$USER" "$DENY_F" 2>/dev/null || echo "$USER" >> "$DENY_F"
sort -u -o "$DENY_F" "$DENY_F"

# mgmt kill 유지
IFNUM=$(sed -n 's/[^0-9]*\([0-9]\+\).*/\1/p' <<<"$IFACE")
MPORT=$((7000 + IFNUM*10))

{
  exec 3<>/dev/tcp/127.0.0.1/"$MPORT"
  printf $'kill %s\r\nquit\r\n' "$USER" >&3
  cat <&3 >/dev/null || true
  exec 3>&-
} || true

# 프로필 삭제
rm -f "$PROF_DIR/${USER}__${IFACE}.ovpn" 2>/dev/null || true

echo "[OK] iface-revoke & kill: $USER on $IFACE"
EOF

chmod 755 "$DELUSR"


# -----------------------------------------------------------
# 5) per-instance ExecStartPost(mi_route_repair.sh) 제거
#    - 설치 스크립트가 만든 mi-route.conf drop-in 삭제
# -----------------------------------------------------------
echo "=== 5) per-instance ExecStartPost(mi_route_repair.sh) 제거 ==="

shopt -s nullglob
for D in /etc/systemd/system/openvpn-server@mi-*.service.d; do
  if [[ -f "$D/mi-route.conf" ]]; then
    echo " - 삭제: $D/mi-route.conf"
    rm -f "$D/mi-route.conf"
  fi
done
shopt -u nullglob


# -----------------------------------------------------------
# 6) 부팅 후 60초 뒤 1회만 mi_route_repair.sh 실행하는
#    oneshot 서비스 + 타이머 생성
# -----------------------------------------------------------
echo "=== 6) mi-route-repair-onboot.service / .timer 생성 ==="

cat > "$ROUTE_ONBOOT_SVC" <<'EOF'
[Unit]
Description=Run mi_route_repair.sh once after boot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/mi_route_repair.sh

[Install]
WantedBy=multi-user.target
EOF

cat > "$ROUTE_ONBOOT_TMR" <<'EOF'
[Unit]
Description=Delay 60 seconds and run mi_route_repair.sh once after boot

[Timer]
OnBootSec=60s
AccuracySec=10s
Unit=mi-route-repair-onboot.service

[Install]
WantedBy=timers.target
EOF


# -----------------------------------------------------------
# 7) systemd reload + 타이머 활성화 + OpenVPN 인스턴스 재시작
# -----------------------------------------------------------
echo "=== 7) systemd reload + 타이머 활성화 + 인스턴스 재시작 ==="

systemctl daemon-reload

# 타이머 활성화
systemctl enable --now mi-route-repair-onboot.timer >/dev/null 2>&1 || true

# 모든 mi- 인스턴스 재시작
for SVC in $(systemctl list-units --type=service --all | awk '/openvpn-server@mi-/{print $1}'); do
  echo " - 재시작: $SVC"
  systemctl restart "$SVC" || true
done

echo "=== 패치 완료 ==="
echo " - duplicate-cn 제거"
echo " - 동시접속 lock/mi-lock-sync 완전 제거"
echo " - hooks-limit2.sh → ACL 전용 훅"
echo " - ovpn_add_user / ovpn_del 기능 + EasyRSA 발급 + mgmt-kill 유지"
echo " - per-instance ExecStartPost(mi_route_repair.sh) 제거"
echo " - 부팅 후 60초 뒤 1회만 mi_route_repair.sh 실행"
