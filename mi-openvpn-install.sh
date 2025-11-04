#!/usr/bin/env bash
# 최소반영판: 훅 활성화 + status 권한 고정만
set -Eeuo pipefail

OVPN_DIR=/etc/openvpn
SRV_DIR=$OVPN_DIR/server
RUN_DIR=/run/openvpn-server
LOCK_BASE=$RUN_DIR/locks
HOOK=/etc/openvpn/hooks-limit2.sh
DROPIN_DIR=/etc/systemd/system/openvpn-server@.service.d
FIX=/usr/local/sbin/mi_fix_status_perm.sh

# 0) 런타임 디렉터리 준비(훅이 lock 만들 수 있도록 nobody 소유)
install -d -m0755 -o nobody -g nogroup "$RUN_DIR" "$LOCK_BASE"

# 1) 훅 스크립트(로깅 1줄 포함). 동시세션 제한 파일은 /etc/openvpn/acl/limit-ensNN.list 사용(없으면 1)
install -d -m0755 /etc/openvpn/acl
cat > "$HOOK" <<'HOOK'
#!/usr/bin/env bash
set -Eeuo pipefail
# 로깅(문제 재현·확인용)
logger -t ovpn-hook "TYPE=${script_type:-} IF=$IFACE CN=$common_name SF=${1:-}"

MAX="${MAX_SESSIONS_PER_CN:-1}"
CN="${common_name:-UNDEF}"
STATUS_FILE="${1:-${STATUS_FILE:-}}"
ACL_DIR="/etc/openvpn/acl"
BASE="/run/openvpn-server/locks"
IP="${trusted_ip:-${untrusted_ip:-X}}"
PORT="${trusted_port:-${untrusted_port:-Y}}"
TOKEN="${IP}:${PORT}"

# IFACE 추론
IFACE="${IFACE:-UNDEF}"
if [[ "$IFACE" == "UNDEF" && -n "$STATUS_FILE" ]]; then
  b="$(basename "$STATUS_FILE")"; IFACE="${b#status-mi-}"; IFACE="${IFACE%.log}"
fi

# per-IF 제한 파일: limit-ensNN.list  (형식: "<CN><공백/탭><허용동시수>")
LIM="$ACL_DIR/limit-${IFACE}.list"
if [[ -f "$LIM" ]]; then
  v="$(awk -v cn="$CN" '$1==cn{print $2; exit}' "$LIM" 2>/dev/null || true)"
  [[ "$v" =~ ^[0-9]+$ ]] && MAX="$v"
fi
[[ "$MAX" == "0" ]] && exit 1

# 현재 상태파일에서 같은 CN의 엔드포인트 카운트
mapfile -t EP_NOW < <(awk -F'[,\t ]+' -v cn="$CN" '$1=="CLIENT_LIST"&&$2==cn{print $3}' "$STATUS_FILE" 2>/dev/null)

# 락 디렉터리
install -d -m0755 -o nobody -g nogroup "$BASE/$IFACE/$CN" 2>/dev/null || true

case "${script_type:-client-connect}" in
  client-connect)
    # 고아락 정리
    shopt -s nullglob
    for lf in "$BASE/$IFACE/$CN"/*.lock; do
      ep="$(basename "$lf" .lock)"; keep=0
      for epn in "${EP_NOW[@]:-}"; do [[ "$epn" == "$ep" ]] && keep=1 && break; done
      (( keep==1 )) || rm -f "$lf"
    done
    # 현재 동시수 = max(STATUS, 락수)
    sc=${#EP_NOW[@]}
    lc=$(find "$BASE/$IFACE/$CN" -type f -name '*.lock' 2>/dev/null | wc -l | tr -d ' ')
    cur=$(( sc>lc ? sc : lc ))
    (( cur >= MAX )) && exit 1
    install -o nobody -g nogroup -m0644 /dev/null "$BASE/$IFACE/$CN/$TOKEN.lock"
    ;;
  client-disconnect)
    rm -f "$BASE/$IFACE/$CN/$TOKEN.lock" 2>/dev/null || true
    ;;
esac
exit 0
HOOK
chmod 755 "$HOOK"

# 2) 서버 conf에 훅 라인이 없으면 추가(setenv/STATUS_FILE 포함). 기존 내용은 유지.
shopt -s nullglob
for CONF in "$SRV_DIR"/mi-*.conf; do
  [[ -f "$CONF" ]] || continue
  IFACE=$(basename "$CONF" .conf); IFACE=${IFACE#mi-}
  ST="$RUN_DIR/status-mi-${IFACE}.log"

  # status 줄이 없으면 추가(1초 주기)
  if ! grep -qE '^[[:space:]]*status[[:space:]]+/run/openvpn-server/status-mi-.*\.log[[:space:]]+1' "$CONF"; then
    printf '\n# status (1s)\nstatus %s 1\nstatus-version 3\n' "$ST" >> "$CONF"
  fi

  # 훅/환경 변수 없으면 추가
  if ! grep -qE '^[[:space:]]*setenv[[:space:]]+IFACE[[:space:]]+'"$IFACE" "$CONF"; then
    {
      echo ''
      echo '# 훅/제한 환경'
      echo "setenv IFACE ${IFACE}"
      echo "setenv-safe STATUS_FILE $ST"
      echo "client-connect /etc/openvpn/hooks-limit2.sh $ST"
      echo "client-disconnect /etc/openvpn/hooks-limit2.sh $ST"
    } >> "$CONF"
  fi
done
shopt -u nullglob

# 3) status 권한 고정 스크립트(인스턴스명 인자로 받아 처리)
cat > "$FIX" <<'EOF'
#!/usr/bin/env bash
# usage: mi_fix_status_perm.sh mi-ensNN
set -Eeuo pipefail
inst="${1:-}"; [[ -n "$inst" ]] || exit 0
iface="${inst#mi-}"
f="/run/openvpn-server/status-mi-${iface}.log"
# 존재하면 소유권/퍼미션 보정. 없으면 생성.
install -o nobody -g nogroup -m 664 /dev/null "$f"
EOF
chmod 755 "$FIX"

# 4) systemd 드롭인: ExecStartPost로 권한 보정만 수행. 다른 보안옵션은 그대로 둠.
install -d -m0755 "$DROPIN_DIR"
cat > "$DROPIN_DIR/mi-fix-status.conf" <<'EOF'
[Service]
# 인스턴스 문자열(%i)을 그대로 쉘 인자로 넘김
ExecStartPost=/usr/local/sbin/mi_fix_status_perm.sh %i
# 훅이 쓰는 경로만 최소 허용
ReadWritePaths=/run/openvpn-server /etc/openvpn/acl
EOF

# 5) 리로드 후 인스턴스 재시작 없이도 다음 스타트부터 적용.
systemctl daemon-reload

echo "[OK] 최소 반영 완료."
echo "- 훅: $HOOK"
echo "- 드롭인: $DROPIN_DIR/mi-fix-status.conf"
echo "- 권한보정: $FIX"
echo
echo "필요 시 수동 적용 예:"
echo "  systemctl restart openvpn-server@mi-ens34.service"
echo
echo "동시세션 제한 예:"
echo "  echo 'sjlee 1'  >> /etc/openvpn/acl/limit-ens34.list"
echo "  echo 'seonjae 2' >> /etc/openvpn/acl/limit-ens34.list"
