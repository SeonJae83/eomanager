#!/usr/bin/env bash
# mi-openvpn-install.sh — per-IF OpenVPN with CN 동시접속 제한(기본 1), ACL, token-locks, status-sync(복원+안전삭제)
# - IF별 인스턴스, 관리포트, 정책라우팅, SNAT
# - deny/allow ACL
# - 훅: CN 정합화(STATUS 비교) + 토큰 생성
# - LOCK SYNC 타이머(OK)
# - DEL: deny 추가 + mgmt kill + 락 정리
# - FIND: status-mi-ensXX.log 기반 CN 활동여부(True/False + age)
set -Eeuo pipefail
LOGFILE=/var/log/mi-openvpn-install.log
exec > >(tee -a "$LOGFILE") 2>&1
trap 'echo "[ERR] line $LINENO: $BASH_COMMAND" >&2' ERR

# ===== PARAM =====
IFACES_INPUT="${1:-}"   # "ens34 ens35" 또는 "ens34,ens35"
DNS1=168.126.63.1
DNS2=168.126.63.2

OVPN_DIR=/etc/openvpn
SRV_DIR=/etc/openvpn/server
EASYRSA_DIR=/etc/openvpn/easy-rsa-mi
PKI_DIR=$EASYRSA_DIR/pki
PROF_DIR=/home/script/openvpn/profile
ACL_DIR=/etc/openvpn/acl
RUN_DIR=/run/openvpn-server
LOCK_BASE=$RUN_DIR/locks

HOOK_LIMIT2=/etc/openvpn/hooks-limit2.sh
REPAIR=/usr/local/sbin/mi_route_repair.sh
PREWRAP=/usr/local/sbin/mi_pre_repair.sh
LOCKSYNC=/usr/local/sbin/mi_lock_sync.sh
ADDUSR=/usr/local/sbin/ovpn_add_user.sh
DELUSR=/usr/local/sbin/ovpn_del.sh
LISTUSR=/usr/local/sbin/ovpn_list_users.sh
FINDUSR=/usr/local/sbin/ovpn-find-user.sh
UNINST=/usr/local/sbin/mi-openvpn-uninstall.sh

unset IFACE 2>/dev/null || true

install -d -m0755 "$SRV_DIR" "$PROF_DIR" /usr/local/sbin "$ACL_DIR" "$RUN_DIR" "$LOCK_BASE"
chown nobody:nogroup "$RUN_DIR" "$LOCK_BASE" || true
tee /etc/tmpfiles.d/openvpn-mi.conf >/dev/null <<EOF
d $RUN_DIR 0755 nobody nogroup -
d $LOCK_BASE 0755 nobody nogroup -
EOF
systemd-tmpfiles --create /etc/tmpfiles.d/openvpn-mi.conf >/dev/null 2>&1 || true

# ===== PKGS =====
if ! command -v openvpn >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y openvpn easy-rsa iproute2 iptables jq lsof
else
  DEBIAN_FRONTEND=noninteractive apt-get install -y easy-rsa iproute2 iptables jq lsof
fi
[[ -d /usr/share/easy-rsa ]] || { echo "[ERR] easy-rsa missing"; exit 1; }

# ===== IPTABLES HELPERS =====
open_if_port(){ # INPUT 허용
  local IFACE_P="${1:-}" IP="${2:-}" PORT="${3:-}" PROTO="${4:-udp}" TAG
  [[ -n "$IFACE_P" && -n "$IP" && -n "$PORT" ]] || return 0
  TAG="mi-${IFACE_P}"
  iptables -C INPUT -p "$PROTO" -d "$IP" --dport "$PORT" -j ACCEPT -m comment --comment "$TAG" 2>/dev/null \
    || iptables -I INPUT -p "$PROTO" -d "$IP" --dport "$PORT" -j ACCEPT -m comment --comment "$TAG"
}
cleanup_input_rules(){ local IFACE="$1"; while read -r line; do eval iptables "${line/-A /-D }" 2>/dev/null || true; done < <(iptables -S INPUT | grep -F -- "-m comment --comment mi-${IFACE}" || true); }
ensure_nat_chain(){ iptables -t nat -N MI-OVPN 2>/dev/null || true; iptables -t nat -C POSTROUTING -j MI-OVPN 2>/dev/null || iptables -t nat -I POSTROUTING -j MI-OVPN; }
add_snat_rule(){ # per-IF SNAT
  local SUB="${1:-}" IFACE_P="${2:-}" SRCIP="${3:-}"
  [[ -n "$SUB" && -n "$IFACE_P" && -n "$SRCIP" ]] || return 0
  ensure_nat_chain
  iptables -t nat -C MI-OVPN -s "$SUB" -o "$IFACE_P" -j SNAT --to-source "$SRCIP" -m comment --comment "mi-$IFACE_P" 2>/dev/null \
    || iptables -t nat -A MI-OVPN -s "$SUB" -o "$IFACE_P" -j SNAT --to-source "$SRCIP" -m comment --comment "mi-$IFACE_P"
}

# ===== HOOK: CN 정합화 + 토큰 생성 (기본 1개 제한)
cat > "$HOOK_LIMIT2" <<'HOOK'
#!/usr/bin/env bash
set -Eeuo pipefail
MAX="${MAX_SESSIONS_PER_CN:-1}"
CN="${common_name:-UNDEF}"
STATUS_FILE="${1:-${STATUS_FILE:-}}"
ACL_DIR="/etc/openvpn/acl"
BASE="/run/openvpn-server/locks"
IP="${trusted_ip:-${untrusted_ip:-X}}"
PORT="${trusted_port:-${untrusted_port:-Y}}"
TOKEN="${IP}:${PORT}"

IFACE="${IFACE:-UNDEF}"
if [[ "$IFACE" == "UNDEF" && -n "$STATUS_FILE" ]]; then
  bn="$(basename "$STATUS_FILE")"; IFACE="${bn#status-mi-}"; IFACE="${IFACE%.log}"
fi

DENY_F="$ACL_DIR/deny-${IFACE}.list"; ALLOW_F="$ACL_DIR/allow-${IFACE}.list"
if [[ -f "$ALLOW_F" ]] && ! grep -Fxq "$CN" "$ALLOW_F" 2>/dev/null; then exit 1; fi
if [[ -f "$DENY_F" ]] &&  grep -Fxq "$CN" "$DENY_F" 2>/dev/null;  then exit 1; fi

mapfile -t EP_NOW < <(awk -F'[,\t ]+' -v cn="$CN" '$1=="CLIENT_LIST"&&$2==cn{print $3}' "$STATUS_FILE" 2>/dev/null)

install -d -m0755 -o nobody -g nogroup "$BASE/$IFACE/$CN"

prune_stale() {
  local d="$1"; shift
  local -A alive=()
  for ep in "$@"; do alive["$ep"]=1; done
  shopt -s nullglob
  for lf in "$d"/*.lock; do
    ep="$(basename "$lf" .lock)"
    [[ -n "${alive[$ep]:-}" ]] || rm -f "$lf"
  done
}
prune_stale "$BASE/$IFACE/$CN" "${EP_NOW[@]}"

case "${script_type:-client-connect}" in
  client-connect)
    sc=${#EP_NOW[@]}
    lc=$(find "$BASE/$IFACE/$CN" -type f -name '*.lock' 2>/dev/null | wc -l | tr -d ' ')
    c=$(( sc>lc ? sc : lc ))
    (( c >= MAX )) && exit 1
    install -o nobody -g nogroup -m0644 /dev/null "$BASE/$IFACE/$CN/$TOKEN.lock"
    ;;
  client-disconnect)
    rm -f "$BASE/$IFACE/$CN/$TOKEN.lock" 2>/dev/null || true
    prune_stale "$BASE/$IFACE/$CN" "${EP_NOW[@]}"
    rmdir "$BASE/$IFACE/$CN" 2>/dev/null || true
    ;;
esac
exit 0
HOOK
chmod 755 "$HOOK_LIMIT2"

# ===== LOCK SYNC =====
cat > "$LOCKSYNC" <<'RB'
#!/usr/bin/env bash
set -euo pipefail
BASE="/run/openvpn-server"; LOCK_DIR="$BASE/locks"; mkdir -p "$LOCK_DIR"

declare -A active
for st in "$BASE"/status-mi-*.log; do
  [[ -r "$st" ]] || continue
  iface="${st##*/}"; iface="${iface#status-mi-}"; iface="${iface%.log}"
  while IFS=$'\t' read -r tag cn ep _a _b _c _d _e _f _g _h _i _j; do
    [[ "$tag" == "CLIENT_LIST" ]] || continue
    active["$iface/$cn/$ep"]=1
  done < "$st"
done

while IFS= read -r -d '' lf; do
  rel="${lf#$LOCK_DIR/}"
  if [[ -n "${active[$rel]:-}" ]]; then
    touch "$lf"; rm -f "${lf}.gone" 2>/dev/null || true
  else
    mark="${lf}.gone"
    if [[ -f "$mark" ]]; then
      rm -f "$lf" "$mark" 2>/dev/null || true
      rmdir "$(dirname "$lf")" 2>/dev/null || true
    else
      : >"$mark"
    fi
  fi
done < <(find "$LOCK_DIR" -type f -name '*.lock' -print0 2>/dev/null)

# 고아 .gone 정리(짝 .lock 없음 + 40초 경과)
while IFS= read -r -d '' mg; do
  lf="${mg%.gone}"; rel="${lf#$LOCK_DIR/}"
  if [[ -n "${active[$rel]:-}" ]]; then
    rm -f "$mg" 2>/dev/null || true
  elif [[ ! -f "$lf" ]]; then
    if [[ $(($(date +%s) - $(stat -c %Y "$mg"))) -ge 40 ]]; then
      rm -f "$mg" 2>/dev/null || true
      rmdir "$(dirname "$lf")" 2>/dev/null || true
    fi
  fi
done < <(find "$LOCK_DIR" -type f -name '*.lock.gone' -print0 2>/dev/null)

for key in "${!active[@]}"; do
  dir="$LOCK_DIR/$(dirname "$key")"; f="$LOCK_DIR/$key.lock"
  install -d -m0755 -o nobody -g nogroup "$dir"
  [[ -f "$f" ]] || install -m0644 -o nobody -g nogroup /dev/null "$f"
done
RB
chmod 755 "$LOCKSYNC"

tee /etc/systemd/system/mi-lock-sync.service >/dev/null <<'UNIT'
[Unit]
Description=Synchronize OpenVPN MI locks (rebuild + prune)
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/mi_lock_sync.sh
UNIT

tee /etc/systemd/system/mi-lock-sync.timer >/dev/null <<'TMR'
[Unit]
Description=Run lock sync every 15s
[Timer]
OnBootSec=20s
OnUnitActiveSec=15s
AccuracySec=1s
Unit=mi-lock-sync.service
[Install]
WantedBy=timers.target
TMR

# ===== ADD USER =====
cat > "$ADDUSR" <<'ADDUSR'
#!/usr/bin/env bash
set -euo pipefail
IFACE=${1:-}; USER=${2:-}
[[ -n "$IFACE" && -n "$USER" ]] || { echo "Usage: $0 <iface> <cn>"; exit 1; }
OVPN_DIR=/etc/openvpn; SRV_DIR=$OVPN_DIR/server
EASYRSA_DIR=$OVPN_DIR/easy-rsa-mi; PKI_DIR=$EASYRSA_DIR/pki
PROF_DIR=/home/script/openvpn/profile; ACL_DIR=/etc/openvpn/acl
CONF=$SRV_DIR/mi-${IFACE}.conf; [[ -f "$CONF" ]] || { echo "[ERR] no $CONF"; exit 1; }
SRV_IP=$(awk '/^local /{print $2}' "$CONF"); SRV_PORT=$(awk '/^port /{print $2}' "$CONF")
install -d -m0755 "$ACL_DIR"
DENY_F="$ACL_DIR/deny-${IFACE}.list"
[[ -f "$DENY_F" ]] && sed -i "/^${USER}\$/d" "$DENY_F"
LOCK_BASE=/run/openvpn-server/locks; rm -rf "$LOCK_BASE/$IFACE/$USER" 2>/dev/null || true
cd "$EASYRSA_DIR"; [[ -f "$PKI_DIR/issued/${USER}.crt" ]] || ./easyrsa --batch build-client-full "$USER" nopass
OUT="$PROF_DIR/${USER}__${IFACE}.ovpn"; install -d -m0755 "$PROF_DIR"
cat >"$OUT" <<EOF
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
EOF
chmod 600 "$OUT"; echo "[OK] profile: $OUT"
ADDUSR
chmod 755 "$ADDUSR"

# ===== DEL USER =====
cat > "$DELUSR" <<'DELUSR'
#!/usr/bin/env bash
set -euo pipefail
IFACE=${1:-}; USER=${2:-}
[[ -n "$IFACE" && -n "$USER" ]] || { echo "Usage: $0 <iface> <cn>"; exit 1; }
ACL_DIR=/etc/openvpn/acl
PROF_DIR=/home/script/openvpn/profile
CONF=/etc/openvpn/server/mi-${IFACE}.conf
[[ -f "$CONF" ]] || { echo "[ERR] no $CONF"; exit 1; }
install -d -m0755 "$ACL_DIR"
DENY_F="$ACL_DIR/deny-${IFACE}.list"
grep -Fxq "$USER" "$DENY_F" 2>/dev/null || echo "$USER" >> "$DENY_F"
IFNUM=$(sed -n 's/[^0-9]*\([0-9]\+\).*/\1/p' <<<"$IFACE")
MPORT=$((7000 + IFNUM*10))
{ exec 3<>/dev/tcp/127.0.0.1/"$MPORT"; printf $'kill %s\r\nquit\r\n' "$USER" >&3; cat <&3 >/dev/null || true; exec 3>&-; } || true
rm -f "$PROF_DIR/${USER}__${IFACE}.ovpn" 2>/dev/null || true
LOCK_BASE=/run/openvpn-server/locks; rm -rf "$LOCK_BASE/$IFACE/$USER" 2>/dev/null || true
echo "[OK] iface-revoke & kill: $USER on $IFACE"
DELUSR
chmod 755 "$DELUSR"

# ===== LIST / FIND =====
cat > "$LISTUSR" <<'LISTUSR'
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob
had=0
for st in /run/openvpn-server/status-mi-*.log; do
  [[ -f "$st" ]] || continue
  echo "== $(basename "$st" .log) =="
  awk -F'[,\t ]+' '$1=="CLIENT_LIST"{printf "%-18s %-22s VIP=%-15s CID=%s\n",$2,$3,$4,$12}' "$st" || true
  echo; had=1
done
[[ $had -eq 1 ]] || echo "(no active clients)"
LISTUSR
chmod 755 "$LISTUSR"

cat > "$FINDUSR" <<'FIND'
#!/usr/bin/env bash
# usage: ovpn-find-user.sh <ensNN> <CN> [THRESHOLD_SEC]
set -euo pipefail
IFACE="${1:?usage: ovpn-find-user.sh <ensNN> <CN> [THRESHOLD_SEC] }"
CN="${2:?usage: ovpn-find-user.sh <ensNN> <CN> [THRESHOLD_SEC] }"
TH="${3:-180}"
LOG=""
for p in "/run/openvpn-server/status-mi-${IFACE}.log" "/run/openvpn-server/status-mi-${IFACE}-log"; do
  [[ -f "$p" ]] && { LOG="$p"; break; }
done
[[ -n "$LOG" ]] || { echo "False (no-status-file)"; exit 1; }
awk -v cn="$CN" -v TH="$TH" '
BEGIN{ FS = "[\t ]+"; now=0; lastref=-1 }
$1=="TIME" { if ($NF ~ /^[0-9]+$/) now=$NF+0; next }
$1=="ROUTING_TABLE" { gsub(/^[ \t]+|[ \t]+$/, "", $3); if ($3==cn && $NF ~ /^[0-9]+$/) { lr=$NF+0; if (lr>lastref) lastref=lr } next }
$1=="CLIENT_LIST" { gsub(/^[ \t]+|[ \t]+$/, "", $2); if ($2==cn) { for(i=NF;i>=1;i--) if ($i ~ /^[0-9]+$/) { lr=$i+0; break } if (lr>0 && lr>lastref) lastref=lr } next }
END{ if (now==0 || lastref<0) { print "False (no-data)"; exit } age=now-lastref; if (age<=TH) printf "True (%ds)\n", age; else printf "False (%ds)\n", age }' "$LOG"
FIND
chmod 755 "$FINDUSR"

# ===== RP_FILTER =====
apply_iface_sysctl(){
  : > /etc/sysctl.d/99-mi-openvpn-ifaces.conf
  for ifc in "$@"; do
    printf 'net.ipv4.conf.%s.rp_filter=2\n' "$ifc" >> /etc/sysctl.d/99-mi-openvpn-ifaces.conf
    printf 'net.ipv4.conf.tun-mi-%s.rp_filter=2\n' "$ifc" >> /etc/sysctl.d/99-mi-openvpn-ifaces.conf
  done
  sysctl --system >/dev/null
}

# ===== IFACE DISCOVERY =====
get_pub_ifaces(){
  ip -o -4 addr show up scope global | awk '{print $2}' | while read -r nic; do
    [[ "$nic" == "lo" ]] && continue
    ip route show default dev "$nic" >/dev/null 2>&1 && echo "$nic"
  done
}
if [[ -n "$IFACES_INPUT" ]]; then mapfile -t IFACES < <(echo "$IFACES_INPUT" | tr ',' ' ' | xargs -n1)
else mapfile -t IFACES < <(get_pub_ifaces)
fi
[[ ${#IFACES[@]} -gt 0 ]] || { echo "[ERR] no iface"; exit 1; }
apply_iface_sysctl "${IFACES[@]}"

# ===== PKI INIT =====
if [[ ! -d "$EASYRSA_DIR" ]]; then
  cp -r /usr/share/easy-rsa "$EASYRSA_DIR"; chmod 755 "$EASYRSA_DIR"; cd "$EASYRSA_DIR"
  cat >"$EASYRSA_DIR/vars" <<'VARS'
set_var EASYRSA_REQ_COUNTRY "KR"
set_var EASYRSA_REQ_PROVINCE "Seoul"
set_var EASYRSA_REQ_CITY "Seoul"
set_var EASYRSA_REQ_ORG "OVPN MI"
set_var EASYRSA_REQ_EMAIL "admin@example.local"
set_var EASYRSA_REQ_OU "IT"
set_var EASYRSA_ALGO "ec"
set_var EASYRSA_DIGEST "sha256"
VARS
  ./easyrsa --batch init-pki
  ./easyrsa --batch build-ca nopass
  openvpn --genkey secret "$OVPN_DIR/mi-tc.key"
  ( cd "$EASYRSA_DIR" && EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl )
  install -D -m0644 "$PKI_DIR/crl.pem" /etc/openvpn/mi-crl.pem
fi

systemctl daemon-reload

# ===== PER-IF INSTANCE =====
for IFDEV in "${IFACES[@]}"; do
  IFNUM=$(sed -n 's/[^0-9]*\([0-9][0-9]*\).*/\1/p' <<<"$IFDEV") || true
  [[ -n "$IFNUM" ]] || { echo "[WARN] $IFDEV: no number"; continue; }
  SRV_IP=$(ip -o -4 addr show dev "$IFDEV" | awk '/inet /{print $4}' | cut -d/ -f1 | head -n1)
  NET=$(ip route show dev "$IFDEV" | awk '/proto kernel/ {print $1; exit}')
  GW=$(ip route show default | awk -v d="$IFDEV" '$0 ~ (" dev " d "($| )"){print $3; exit}')
  [[ -n "$SRV_IP" && -n "$GW" && -n "$NET" ]] || { echo "[WARN] $IFDEV missing ip/gw/net"; continue; }

  PORT=$((4100 + IFNUM)); (( PORT<=65535 )) || PORT=51194
  SUBNET=10.0.${IFNUM}.0; MASK=255.255.255.0
  DEV=tun-mi-${IFDEV}; SRV_CN=mi-srv-${IFDEV}
  CONF=$SRV_DIR/mi-${IFDEV}.conf
  TABLE=tbl${IFNUM}; TNUM=$((100 + IFNUM)); PREF=$((10000 + IFNUM))
  MPORT=$((7000 + IFNUM*10))
  ST_FILE="$RUN_DIR/status-mi-${IFDEV}.log"

  [[ -f "$PKI_DIR/issued/${SRV_CN}.crt" ]] || ( cd "$EASYRSA_DIR" && ./easyrsa --batch build-server-full "$SRV_CN" nopass )

  cat >"$CONF" <<EOF
port $PORT
proto udp
local $SRV_IP
server $SUBNET $MASK

dev $DEV
persist-key
persist-tun

# management 은 user/group 앞에 둔다
management 127.0.0.1 $MPORT

user nobody
group nogroup
script-security 2

# duplicate-cn
topology subnet
client-to-client
keepalive 10 120
explicit-exit-notify 1

# setenv MAX_SESSIONS_PER_CN 2

push "dhcp-option DNS $DNS1"
push "dhcp-option DNS $DNS2"
push "redirect-gateway def1 bypass-dhcp"

cipher AES-256-GCM
auth SHA256
data-ciphers AES-256-GCM
dh none
ecdh-curve prime256v1
tls-crypt $OVPN_DIR/mi-tc.key

ca $PKI_DIR/ca.crt
cert $PKI_DIR/issued/${SRV_CN}.crt
key $PKI_DIR/private/${SRV_CN}.key

crl-verify /etc/openvpn/mi-crl.pem

# status (1s)
status $ST_FILE 1
status-version 3

# 훅/제한 환경 (원하면 주석 해제)
setenv IFACE ${IFDEV}
setenv-safe STATUS_FILE $ST_FILE
# client-connect "/etc/openvpn/hooks-limit2.sh $ST_FILE"
# client-disconnect "/etc/openvpn/hooks-limit2.sh $ST_FILE"

mute-replay-warnings
verb 3
EOF

  install -o nobody -g nogroup -m 664 /dev/null "$ST_FILE"

  grep -q "^$TNUM $TABLE$" /etc/iproute2/rt_tables 2>/dev/null || echo "$TNUM $TABLE" >> /etc/iproute2/rt_tables
  ip route replace "$NET" dev "$IFDEV" proto kernel scope link src "$SRV_IP" table "$TABLE" || true
  ip route replace default via "$GW" dev "$IFDEV" src "$SRV_IP" table "$TABLE" || true
  while ip rule show | grep -q "from 10.0.${IFNUM}.0/24 lookup $TABLE"; do ip rule del from "10.0.${IFNUM}.0/24" table "$TABLE" 2>/dev/null || break; done
  ip rule add from "10.0.${IFNUM}.0/24" table "$TABLE" 2>/dev/null || true
  ip rule show | grep -q "from $SRV_IP/32 lookup $TABLE" || ip rule add pref "$PREF" from "$SRV_IP/32" lookup "$TABLE" 2>/dev/null || true

  add_snat_rule "10.0.${IFNUM}.0/255.255.255.0" "$IFDEV" "$SRV_IP"
  open_if_port "$IFDEV" "$SRV_IP" "$PORT" udp

  # per-instance ExecStartPost: route/profiles repair
  instdir="/etc/systemd/system/openvpn-server@mi-${IFDEV}.service.d"; install -d -m0755 "$instdir"
  cat > "$instdir/mi-route.conf" <<EON
[Service]
ExecStartPost=-/usr/local/sbin/mi_route_repair.sh --only $IFDEV
EON

  systemctl daemon-reload
  systemctl enable --now "openvpn-server@mi-${IFDEV}.service" || true
  echo "[OK] mi-${IFDEV}: ${SRV_IP}:${PORT} mgmt 127.0.0.1:${MPORT} subnet 10.0.${IFNUM}.0/24"
done

# ===== TEMPLATE DROP-INS: allow profile writes + root for Pre/Post =====
install -d -m0755 /etc/systemd/system/openvpn-server@.service.d
tee /etc/systemd/system/openvpn-server@.service.d/mi-profile-write.conf >/dev/null <<'EONP'
[Service]
ProtectHome=false
ReadWritePaths=/home/script/openvpn/profile
EONP
tee /etc/systemd/system/openvpn-server@.service.d/mi-perms.conf >/dev/null <<'EONQ'
[Service]
PermissionsStartOnly=yes
EONQ

# ===== PRE WRAPPER (optional hook point) =====
cat > "$PREWRAP" <<'PWR'
#!/usr/bin/env bash
set -Eeuo pipefail
unit="${1:-}"; [[ -n "$unit" ]] || exit 0
case "$unit" in
  mi-*) iface="${unit#mi-}"; /usr/local/sbin/mi_route_repair.sh --only "$iface" || true ;;
  *) exit 0 ;;
esac
PWR
chmod 755 "$PREWRAP"

# ===== ROUTE REPAIR (INPUT/프로필 동기화 포함) =====
cat > "$REPAIR" <<'REP'
#!/usr/bin/env bash
set -Eeuo pipefail
only=""; [[ "${1:-}" == "--only" && -n "${2:-}" ]] && only="$2"
log(){ echo "[repair] $*"; }
wait_if(){ local ifc="$1" n=60; while ((n-- > 0)); do ip -4 addr show dev "$ifc" | grep -q 'inet ' && return 0; sleep 1; done; return 1; }
ensure_nat(){ iptables -t nat -N MI-OVPN 2>/dev/null || true; iptables -t nat -C POSTROUTING -j MI-OVPN 2>/dev/null || iptables -t nat -I POSTROUTING -j MI-OVPN || true; }
add_snat(){ local SUB="$1" IFACE_P="$2" SRC="$3"; ensure_nat; iptables -t nat -C MI-OVPN -s "$SUB" -o "$IFACE_P" -j SNAT --to-source "$SRC" -m comment --comment "mi-$IFACE_P" 2>/dev/null || iptables -t nat -A MI-OVPN -s "$SUB" -o "$IFACE_P" -j SNAT --to-source "$SRC" -m comment --comment "mi-$IFACE_P" || true; }
cleanup_input_rules(){ local IFACE="$1"; while read -r line; do eval iptables "${line/-A /-D }" 2>/dev/null || true; done < <(iptables -S INPUT | grep -F -- "-m comment --comment mi-${IFACE}" || true); }
open_if_port(){ local IFACE_P="${1:-}" IP="${2:-}" PORT="${3:-}" PROTO="${4:-udp}"; [[ -n "$IFACE_P" && -n "$IP" && -n "$PORT" ]] || return 0; iptables -C INPUT -p "$PROTO" -d "$IP" --dport "$PORT" -j ACCEPT -m comment --comment "mi-$IFACE_P" 2>/dev/null || iptables -I INPUT -p "$PROTO" -d "$IP" --dport "$PORT" -j ACCEPT -m comment --comment "mi-$IFACE_P"; }

update_profiles(){ # *__<IFACE>.ovpn + 같은 PORT 쓰는 파일들 교체, 없으면 맨 끝에 append
  local IFACE="$1" SRV_IP="$2" PORT="$3" PROF_DIR="/home/script/openvpn/profile"
  [[ -d "$PROF_DIR" && -n "$SRV_IP" && -n "$PORT" ]] || return 0
  shopt -s nullglob
  declare -A seen=()
  local files=( "$PROF_DIR"/*__"${IFACE}".ovpn )
  while IFS= read -r -d '' extra; do files+=( "$extra" ); done < <(
    grep -Zl -E '^[[:space:]]*remote[[:space:]]+[^[:space:]]+[[:space:]]+'"$PORT"'([[:space:]]|$)' "$PROF_DIR"/*.ovpn 2>/dev/null || true
  )
  for f in "${files[@]}"; do
    [[ -e "$f" && -z "${seen[$f]:-}" ]] || continue; seen["$f"]=1
    sed -i 's/\r$//' "$f"  # CRLF 제거
    awk -v ip="$SRV_IP" -v port="$PORT" '
      BEGIN{ done=0; inb=0 }
      /^[ \t]*<(ca|cert|key|tls-crypt)>[ \t]*$/   { inb=1 }
      /^[ \t]*<\/(ca|cert|key|tls-crypt)>[ \t]*$/ { inb=0 }
      !inb && done==0 && $0 ~ /^[ \t]*remote[ \t]+/ {
        n=split($0,a,/[ \t]+/); extra=""
        if(n>=3){ for(i=4;i<=n;i++) if(a[i]!="") extra=extra " " a[i] }
        print "remote " ip " " port extra
        done=1; next
      }
      { print }
      END{
        if(done==0) print "remote " ip " " port
      }
    ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
    echo "[repair] ${IFACE}: profile updated $(basename "$f") -> remote $SRV_IP $PORT"
  done
  shopt -u nullglob
}

fix(){
  local IFACE="$1" IFNUM; IFNUM=$(sed -n 's/[^0-9]*\([0-9]\+\).*/\1/p' <<<"$IFACE" || true); [[ -n "$IFNUM" ]] || return 0
  wait_if "$IFACE" || { log "$IFACE not ready"; return 0; }
  local IP NET GW TABLE="tbl${IFNUM}" TNUM=$((100+IFNUM)) PREF=$((10000+IFNUM))
  IP=$(ip -4 addr show dev "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)
  NET=$(ip route show dev "$IFACE" | awk '/proto kernel/ {print $1; exit}' || true)
  GW=$(ip route show default | awk -v d="$IFACE" '$0 ~ (" dev " d "($| )"){print $3; exit}' || true)
  [[ -n "$IP" && -n "$NET" && -n "$GW" ]] || { log "$IFACE missing"; return 0; }

  grep -q "^$TNUM tbl${IFNUM}$" /etc/iproute2/rt_tables 2>/dev/null || echo "$TNUM tbl${IFNUM}" >> /etc/iproute2/rt_tables || true
  ip route replace "$NET" dev "$IFACE" proto kernel scope link src "$IP" table "tbl${IFNUM}" || true
  ip route replace default via "$GW" dev "$IFACE" src "$IP" table "tbl${IFNUM}" || true
  while ip rule show | grep -q "from 10.0.${IFNUM}.0/24 lookup tbl${IFNUM}"; do ip rule del from "10.0.${IFNUM}.0/24" table "tbl${IFNUM}" 2>/dev/null || break; done
  ip rule add from "10.0.${IFNUM}.0/24" table "tbl${IFNUM}" 2>/dev/null || true
  ip rule show | grep -q "from $IP/32 lookup tbl${IFNUM}" || ip rule add pref "$PREF" from "$IP/32" lookup "tbl${IFNUM}" 2>/dev/null || true

  add_snat "10.0.${IFNUM}.0/255.255.255.0" "$IFACE" "$IP"

  local CONF="/etc/openvpn/server/mi-${IFACE}.conf"
  if [[ -f "$CONF" ]]; then
    local CUR PORT PROTO
    CUR=$(awk '/^local[ \t]+/{print $2; exit}' "$CONF")
    PORT=$(awk '/^port[ \t]+/{print $2; exit}' "$CONF")
    PROTO=$(awk '/^proto[ \t]+/{print $2; exit}' "$CONF")
    if [[ "$CUR" != "$IP" ]]; then
      sed -i "s/^local .*/local $IP/" "$CONF"
      systemctl try-restart "openvpn-server@mi-${IFACE}.service" >/dev/null 2>&1 || true
      log "$IFACE: local $CUR -> $IP"
    fi
    cleanup_input_rules "$IFACE"; open_if_port "$IFACE" "$IP" "$PORT" "$PROTO"
    update_profiles "$IFACE" "$IP" "$PORT"
  fi
  log "$IFACE -> $IP via $GW (profiles synced)"
}

mapfile -t IFACES < <(ls /etc/openvpn/server/mi-*.conf 2>/dev/null | sed -e 's#.*/mi-##' -e 's#\.conf$##')
for ifc in "${IFACES[@]}"; do
  [[ -n "$only" && "$ifc" != "$only" ]] && continue
  fix "$ifc"
done
exit 0
REP
chmod 755 "$REPAIR"

# ===== ENABLE LOCK SYNC TIMER =====
systemctl daemon-reload
systemctl enable --now mi-lock-sync.timer

# ===== UNINSTALL =====
cat > "$UNINST" <<'UN'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "[ERR] line $LINENO: $BASH_COMMAND" >&2' ERR
OVPN_DIR=/etc/openvpn; SRV_DIR=/etc/openvpn/server; EASYRSA_DIR=/etc/openvpn/easy-rsa-mi
ACL_DIR=/etc/openvpn/acl; PROF_DIR=/home/script/openvpn/profile

systemctl disable --now mi-lock-sync.timer 2>/dev/null || true
systemctl disable --now mi-lock-sync.service 2>/dev/null || true

CONFS=( $(ls -1 $SRV_DIR/mi-*.conf 2>/dev/null || true) )
for C in "${CONFS[@]}"; do inst=$(basename "$C" .conf); systemctl disable --now "openvpn-server@${inst}.service" 2>/dev/null || true; done
for C in "${CONFS[@]}"; do IFACE=$(basename "$C" .conf | sed 's/^mi-//'); rm -rf "/etc/systemd/system/openvpn-server@mi-${IFACE}.service.d" 2>/dev/null || true; done
rm -f /etc/systemd/system/openvpn-server@.service.d/mi-profile-write.conf /etc/systemd/system/openvpn-server@.service.d/mi-perms.conf 2>/dev/null || true
systemctl daemon-reload || true

for C in "${CONFS[@]}"; do
  IP=$(awk '/^local /{print $2}' "$C"); PORT=$(awk '/^port /{print $2}' "$C"); PROTO=$(awk '/^proto /{print $2}' "$C"); IFACE=$(basename "$C" .conf | sed 's/^mi-//')
  while read -r line; do eval iptables "${line/-A /-D }" 2>/dev/null || true; done < <(iptables -S INPUT | grep -F -- "-m comment --comment mi-${IFACE}" || true)
  if iptables -t nat -S MI-OVPN >/dev/null 2>&1; then
    SUBNET="10.0.$(sed -n 's/[^0-9]*\([0-9]\+\).*/\1/p' <<<"$IFACE").0/24"
    while iptables -t nat -C MI-OVPN -s "$SUBNET" -o "$IFACE" -m comment --comment "mi-$IFACE" -j SNAT 2>/dev/null; do
      iptables -t nat -D MI-OVPN -s "$SUBNET" -o "$IFACE" -m comment --comment "mi-$IFACE" -j SNAT || break
    done
  fi
done
if iptables -t nat -S MI-OVPN >/dev/null 2>&1; then
  if ! iptables -t nat -S MI-OVPN | grep -q ' -A MI-OVPN '; then
    iptables -t nat -D POSTROUTING -j MI-OVPN 2>/dev/null || true
    iptables -t nat -X MI-OVPN 2>/dev/null || true
  fi
fi

for C in "${CONFS[@]}"; do
  IFACE=$(basename "$C" .conf | sed 's/^mi-//'); IFNUM=$(sed -n 's/[^0-9]*\([0-9]\+\).*/\1/p' <<<"$IFACE")
  SUBNET="10.0.${IFNUM}.0/24"; TABLE="tbl${IFNUM}"; TNUM=$((100+IFNUM)); PREF=$((10000+IFNUM))
  while ip rule show | grep -q "from $SUBNET lookup $TABLE"; do ip rule del from "$SUBNET" table "$TABLE" 2>/dev/null || break; done
  IP=$(ip -4 addr show dev "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)
  [[ -n "$IP" ]] && ip rule del pref "$PREF" from "$IP/32" lookup "$TABLE" 2>/dev/null || true
  ip route flush table "$TABLE" 2>/dev/null || true
  sed -i "/^$TNUM $TABLE$/d" /etc/iproute2/rt_tables 2>/dev/null || true
done

rm -rf "$SRV_DIR"/mi-*.conf "$ACL_DIR" "$PROF_DIR" "$EASYRSA_DIR" 2>/dev/null || true
rm -f  "$OVPN_DIR/mi-crl.pem" "$OVPN_DIR/mi-tc.key" /etc/openvpn/hooks-limit2.sh /etc/sysctl.d/99-mi-openvpn-ifaces.conf /etc/tmpfiles.d/openvpn-mi.conf 2>/dev/null || true
rm -f  /usr/local/sbin/mi_lock_sync.sh /etc/systemd/system/mi-lock-sync.service /etc/systemd/system/mi-lock-sync.timer 2>/dev/null || true
sysctl --system >/dev/null 2>&1 || true
echo "[DONE] MI OpenVPN uninstalled (no impact to other OpenVPN instances)"
UN
chmod 755 "$UNINST"

# ===== ENABLE LOCK SYNC TIMER (again, idempotent) =====
systemctl daemon-reload
systemctl enable --now mi-lock-sync.timer

echo "[DONE] install script finished"
echo "UTILS:"
echo "  Add user        : $ADDUSR <ensNN> <cn>"
echo "  Del user        : $DELUSR <ensNN> <cn>"
echo "  List users      : $LISTUSR"
echo "  Find user(OVPN) : $FINDUSR <ensNN> <cn> [threshold]"
