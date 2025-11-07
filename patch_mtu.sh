#!/usr/bin/env bash
# wg-mtu-retrofit.sh — add/replace MTU in wg-add-user.sh and existing client confs
# usage: sudo bash wg-mtu-retrofit.sh [MTU]
set -Eeuo pipefail
MTU="${1:-1380}"
[[ "$MTU" =~ ^[0-9]+$ ]] || { echo "MTU must be integer"; exit 2; }

BIN="/usr/local/sbin"
ADD="${BIN}/wg-add-user.sh"
CLIENT_DIR="/home/script/wg"
TS="$(date +%Y%m%d-%H%M%S)"

backup() { cp -a "$1" "$1.bak.${TS}"; }

patch_add_user() {
  [[ -f "$ADD" ]] || { echo "not found: $ADD"; return 0; }
  backup "$ADD"

  # 1) MTU 라인이 있으면 숫자만 교체
  if grep -qE '^[[:space:]]*MTU[[:space:]]*=' "$ADD"; then
    sed -ri "s@^([[:space:]]*MTU[[:space:]]*=[[:space:]]*)[0-9]+@\1${MTU}@g" "$ADD"
  else
    # 2) MTU 라인이 없으면, here-doc 내 [Interface]의 DNS 라인 바로 아래에 삽입
    awk -v MTU="$MTU" '
      BEGIN{in_hd=0}
      {
        print $0
        if ($0 ~ /^cat[ \t]*>[^<]*<<EOC[ \t]*$/) in_hd=1
        if (in_hd && $0 ~ /^\[Interface\][ \t]*$/) seen_if=1
        if (in_hd && seen_if && $0 ~ /^DNS[ \t]*=/) { print "MTU = " MTU; seen_if=0 }
        if (in_hd && $0 ~ /^EOC[ \t]*$/) { in_hd=0; seen_if=0 }
      }' "$ADD" > "${ADD}.tmp"
    mv -f "${ADD}.tmp" "$ADD"
  fi
  chmod 755 "$ADD"
  echo "[OK] patched: $ADD (bak: ${ADD}.bak.${TS})"
}

patch_client_confs() {
  [[ -d "$CLIENT_DIR" ]] || { echo "skip: no dir $CLIENT_DIR"; return 0; }
  shopt -s nullglob
  files=("$CLIENT_DIR"/*.conf)
  ((${#files[@]})) || { echo "skip: no client confs"; return 0; }

  for f in "${files[@]}"; do
    backup "$f"
    awk -v MTU="$MTU" '
      BEGIN{RS="\n"; ORS="\n"; in_if=0; saw_mtu=0}
      function print_mtu_if_needed(){
        if(in_if && !saw_mtu){ print "MTU = " MTU; saw_mtu=1 }
      }
      {
        line=$0
        if (line ~ /^\[Interface\][ \t]*$/) { in_if=1; saw_mtu=0; print line; next }
        if (in_if && line ~ /^\[Peer\][ \t]*$/) { print_mtu_if_needed(); in_if=0; saw_mtu=0; print line; next }
        if (in_if && line ~ /^[ \t]*MTU[ \t]*=/) { print "MTU = " MTU; saw_mtu=1; next }
        print line
      }
      END { print_mtu_if_needed() }' "$f" > "${f}.tmp"

    mv -f "${f}.tmp" "$f"
    chmod 600 "$f" || true
    echo "[OK] patched: $f (bak: $f.bak.${TS})"
  done
}

patch_add_user
patch_client_confs
echo "[DONE] MTU=${MTU}"
