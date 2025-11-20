#!/usr/bin/env bash
# mi-openvpn 기존 설치 환경에서:
#  - duplicate-cn 제거
#  - 동시접속 제한용 lock sync/타이머 제거
#  - hooks-limit2.sh 를 ACL 전용 훅으로 변경
#  - ADD/DEL 의 deny 로직은 유지, lock 관련만 제거
set -Eeuo pipefail
trap 'echo "[ERR] line $LINENO: $BASH_COMMAND" >&2' ERR

SRV_DIR=/etc/openvpn/server
ACL_DIR=/etc/openvpn/acl
HOOK_LIMIT2=/etc/openvpn/hooks-limit2.sh
ADDUSR=/usr/local/sbin/ovpn_add_user.sh
DELUSR=/usr/local/sbin/ovpn_del.sh

if [[ $EUID -ne 0 ]]; then
  echo "root로 실행해야 합니다." >&2
  exit 1
fi

echo "=== 1) server conf 패치: duplicate-cn 제거 ==="
shopt -s nullglob
CONFS=( "$SRV_DIR"/mi-*.conf )
if (( ${#CONFS[@]} == 0 )); then
  echo "  * $SRV_DIR/mi-*.conf 없음. (mi-openvpn 아직 설치 안됐거나 다른 경로)" >&2
else
  for C in "${CONFS[@]}"; do
    echo "  - 패치: $(basename "$C")"
    # duplicate-cn 제거
    sed -i '/^[[:space:]]*duplicate-cn[[:space:]]*$/d' "$C"
  done
fi
shopt -u nullglob

echo
echo "=== 2) hooks-limit2.sh 를 ACL 전용 훅으로 교체 ==="
install -d -m0755 "$(dirname "$HOOK_LIMIT2")"
cat > "$HOOK_LIMIT2" <<'HOOK'
#!/usr/bin/env bash
# hooks-limit2.sh (patched) — 동시접속 제한 제거, ACL(allow/deny)만 적용
set -Eeuo pipefail

CN="${common_name:-UNDEF}"
IFACE="${IFACE:-UNDEF}"
STATUS_FILE="${1:-${STATUS_FILE:-}}"
ACL_DIR="/etc/openvpn/acl"

log(){ echo "[HOOK][$IFACE][$CN] $*" >&2; }

# STATUS_FILE 또는 IFACE 환경변수로 인터페이스 추론
if [[ "$IFACE" == "UNDEF" && -n "$STATUS_FILE" ]]; then
  bn="$(basename "$STATUS_FILE")"
  IFACE="${bn#status-mi-}"
  IFACE="${IFACE%.log}"
fi

DENY_F="$ACL_DIR/deny-${IFACE}.list"
ALLOW_F="$ACL_DIR/allow-${IFACE}.list"

# ALLOW 우선 적용
if [[ -f "$ALLOW_F" ]] && ! grep -Fxq "$CN" "$ALLOW_F" 2>/dev/null; then
  log "DENY by allow-list (not allowed)"
  exit 1
fi

# DENY 적용
if [[ -f "$DENY_F" ]] && grep -Fxq "$CN" "$DENY_F" 2>/dev/null; then
  log "DENY by deny-list"
  exit 1
fi

# 동시접속 제한/락 로직은 완전히 제거
exit 0
HOOK
chmod 755 "$HOOK_LIMIT2"
echo "  * hooks-limit2.sh -> ACL 전용 훅으로 변경 완료"

echo
echo "=== 3) mi_lock_sync 타이머/서비스 제거 (동시접속 락 sync) ==="
systemctl disable --now mi-lock-sync.timer  2>/dev/null || true
systemctl disable --now mi-lock-sync.service 2>/dev/null || true
rm -f /usr/local/sbin/mi_lock_sync.sh 2>/dev/null || true
rm -f /etc/systemd/system/mi-lock-sync.service 2>/dev/null || true
rm -f /etc/systemd/system/mi-lock-sync.timer   2>/dev/null || true

# 락 디렉토리 정리 (있으면 삭제)
if [[ -d /run/openvpn-server/locks ]]; then
  rm -rf /run/openvpn-server/locks 2>/dev/null || true
fi

echo "  * mi-lock-sync.* 및 기존 lock 디렉토리 정리 완료"

echo
echo "=== 4) ADD/DEL 스크립트에서 lock 관련 코드만 제거 (deny 로직은 유지) ==="

if [[ -x "$ADDUSR" ]]; then
  echo "  - 패치: $(basename "$ADDUSR")"
  # LOCK_BASE=/run/openvpn-server/locks 줄과 바로 아래 rm -rf 줄 제거
  sed -i '
    /LOCK_BASE=\/run\/openvpn-server\/locks/ {
      N
      /rm -rf "\$LOCK_BASE\/\$IFACE\/\$USER"/ d
    }
  ' "$ADDUSR" || true
else
  echo "  * 경고: $ADDUSR 없음(ADD 스크립트 건너뜀)"
fi

if [[ -x "$DELUSR" ]]; then
  echo "  - 패치: $(basename "$DELUSR")"
  # DELUSR에서도 같은 패턴 제거 (deny는 유지)
  sed -i '
    /LOCK_BASE=\/run\/openvpn-server\/locks/ {
      N
      /rm -rf "\$LOCK_BASE\/\$IFACE\/\$USER"/ d
    }
  ' "$DELUSR" || true
else
  echo "  * 경고: $DELUSR 없음(DEL 스크립트 건너뜀)"
fi

echo
echo "=== 5) systemd 데몬 재로드 및 OpenVPN 인스턴스 재시작 ==="
systemctl daemon-reload || true

shopt -s nullglob
UNITS=( /etc/systemd/system/openvpn-server@mi-*.service )
if (( ${#UNITS[@]} > 0 )); then
  for U in "${UNITS[@]}"; do
    inst="$(basename "$U" .service)"
    echo "  - 재시작: $inst"
    systemctl restart "$inst" 2>/dev/null || true
  done
else
  # 유닛 파일이 심볼릭 링크 등으로만 있을 수 있으니 fallback
  for SVC in $(systemctl list-units --type=service --all | awk '/openvpn-server@mi-/{print $1}'); do
    echo "  - 재시작: $SVC"
    systemctl restart "$SVC" 2>/dev/null || true
  done
fi
shopt -u nullglob

echo
echo "=== 패치 완료 ==="
echo " - duplicate-cn 제거"
echo " - hooks-limit2.sh -> ACL 전용 (deny-ensXX.list / allow-ensXX.list 유지)"
echo " - mi_lock_sync.* 및 lock 기반 동시접속 제한 제거"
echo " - ADD/DEL 스크립트의 deny 로직은 그대로 유지됨"
