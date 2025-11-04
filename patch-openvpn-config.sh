#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="/home/script/openvpn-config.sh"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="${TARGET}.${STAMP}.bak"
TMP="/tmp/openvpn-config.sh.patched.$$"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[ERR] missing $1"; exit 127; }; }
need perl
need grep
need awk
need diff

[[ -f "$TARGET" ]] || { echo "[ERR] not found: $TARGET"; exit 1; }

# ---- 패치 여부 판단 ----
COND_A=$(grep -E 'ip -4 -o addr show[[:space:]]*\|[[:space:]]*awk.*\^ens\[0-9]\+\$' "$TARGET" || true)
COND_B=$(grep -E 'ip -4 -o addr show dev "?\$\{?(IF|i)\}?"?' "$TARGET" || true)

if [[ -n "$COND_A" && -n "$COND_B" ]]; then
  echo "[OK] Already patched: $TARGET"
  exit 0
fi

# ---- 백업 ----
cp -a "$TARGET" "$BACKUP"
echo "[BK] Backup created: $BACKUP"

# ---- 패치 적용 ----
perl -0777 -pe '
  s#ip\s+-4\s+addr\s*\|\s*grep\s+inet\s*\|\s*grep\s+-vE\s*'\''127\(\.\[0-9\]\{1,3\}\)\{3\}\|tun'\''\s*\|\s*awk\s*'\''\{print \$10\}'\''#ip -4 -o addr show | awk '\''$2 ~ /^ens[0-9]+$/ {print $2}'\''#g;
  s#ip\s+-4\s+addr\s*\|\s*grep\s+inet\s*\|\s*grep\s+-vE\s*'\''127\(\.\[0-9\]\{1,3\}\)\{3\}\|tun'\''#ip -4 -o addr show | awk '\''$2 ~ /^ens[0-9]+$/ {print $2}'\''#g;
  s#ip\s*-?\'?4\'?\s*addr\s*\|\s*grep\s+inet\s*\|\s*grep\s+ens\$\{i\}[^\n]*?\|\s*cut\s*-d\s*'\''/'\''\s*-f\s*1\s*\|\s*awk\s*'\''\{print \$2\}'\''#ip -4 -o addr show dev "ens${i}" | awk '"'"'{print $4}'"'"' | cut -d/ -f1#g;
  s#ip\s*-?\'?4\'?\s*addr\s*\|\s*grep\s+inet\s*\|\s*grep\s+ens\$\{IF\}[^\n]*?\|\s*cut\s*-d\s*'\''/'\''\s*-f\s*1\s*\|\s*awk\s*'\''\{print \$2\}'\''#ip -4 -o addr show dev "ens${IF}" | awk '"'"'{print $4}'"'"' | cut -d/ -f1#g;
  s#grep\s+ens\$\{i\}#grep -w ens${i}#g;
' "$TARGET" > "$TMP"

bash -n "$TMP" || { echo "[ERR] syntax check failed, restore original"; rm -f "$TMP"; exit 2; }

echo "[DIFF] Preview of changes:"
diff -u "$TARGET" "$TMP" | sed -n '1,100p' || true

mv -f "$TMP" "$TARGET"
chmod --reference="$BACKUP" "$TARGET" || true
chown --reference="$BACKUP" "$TARGET" || true

echo "[OK] Patched successfully: $TARGET"
