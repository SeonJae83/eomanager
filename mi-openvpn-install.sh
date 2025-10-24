#!/usr/bin/env bash
# mi-openvpn-install.sh — per-IF OpenVPN with per-IF CN limit(2), deny ACL, instant kill on delete
set -Eeuo pipefail
LOGFILE=/var/log/mi-openvpn-install.log
exec > >(tee -a "$LOGFILE") 2>&1
trap 'echo "[ERR] line $LINENO: $BASH_COMMAND" >&2' ERR

# ====== PARAM ======
IFACES_INPUT="${1:-}"   # 예: "ens34 ens35" 또는 "ens34,ens35"

DNS1=168.126.63.1
DNS2=168.126.63.2

OVPN_DIR=/etc/openvpn
SRV_DIR=/etc/openvpn/server
EASYRSA_DIR=/etc/openvpn/easy-rsa-mi
PKI_DIR=$EASYRSA_DIR/pki
PROF_DIR=/home/script/openvpn/profile
ACL_DIR=/etc/openvpn/acl
RUN_DIR=/run/openvpn-server

HOOK_LIMIT2=/etc/openvpn/hooks-limit2.sh
REPAIR=/usr/local/sbin/mi_route_repair.sh
ADDUSR=/usr/local/sbin/ovpn_add_user.sh
DELUSR=/usr/local/sbin/ovpn_del.sh
LISTUSR=/usr/local/sbin/ovpn_list_users.sh
UNINST=/usr/local/sbin/mi-openvpn-uninstall.sh

install -d -m0755 "$SRV_DIR" "$PROF_DIR" /usr/local/sbin "$ACL_DIR" "$RUN_DIR"
chown nobody:nogroup "$RUN_DIR" || true
tee /etc/tmpfiles.d/openvpn-mi.conf >/dev/null <<EOF
d $RUN_DIR 0755 nobody nogroup -
EOF
systemd-tmpfiles --create /etc/tmpfiles.d/openvpn-mi.conf >/dev/null 2>&1 || true

# ====== PKGS ======
if ! command -v openvpn >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y openvpn easy-rsa iproute2 iptables jq lsof
else
  DEBIAN_FRONTEND=noninteractive apt-get install -y easy-rsa iproute2 iptables jq lsof
fi
[[ -d /usr/share/easy-rsa ]] || { echo "[ERR] easy-rsa missing"; exit 1; }

# ====== IPTABLES HELPERS ======
open_if_port(){ # INPUT 허용
  local IFACE_P="${1:-}" IP="${2:-}" PORT="${3:-}" PROTO="${4:-udp}" TAG
  [[ -n "$IFACE_P" && -n "$IP" && -n "$PORT" ]] || return 0
  TAG="mi-${IFACE_P}"
  iptables -C INPUT -p "$PROTO" -d "$IP" --dport "$PORT" -j ACCEPT -m comment --comment "$TAG" 2>/dev/null \
    || iptables -I INPUT -p "$PROTO" -d "$IP" --dport "$PORT" -j ACCEPT -m comment --comment "$TAG"
}
ensure_nat_chain(){ iptables -t nat -N MI-OVPN 2>/dev/null || true; iptables -t nat -C POSTROUTING -j MI-OVPN 2>/dev/null || iptables -t nat -I POSTROUTING -j MI-OVPN; }
add_snat_rule(){ # per-IF SNAT
  local SUB="${1:-}" IFACE_P="${2:-}" SRCIP="${3:-}"
  [[ -n "$SUB" && -n "$IFACE_P" && -n "$SRCIP" ]] || return 0
  ensure_nat_chain
  iptables -t nat -C MI-OVPN -s "$SUB" -o "$IFACE_P" -j SNAT --to-source "$SRCIP" -m comment --comment "mi-$IFACE_P" 2>/dev/null \
    || iptables -t nat -A MI-OVPN -s "$SUB" -o "$IFACE_P" -j SNAT --to-source "$SRCIP" -m comment --comment "mi-$IFACE_P"
}

# ====== HOOK: per-IF CN 동시 2 제한, STATUS 파일만 사용(안정) ======
cat > "$HOOK_LIMIT2" <<'HOOK'
#!/usr/bin/env bash
set -Eeuo pipefail
MAX="${MAX_SESSIONS_PER_CN:-2}"
CN="${common_name:-UNDEF}"
STATUS_FILE="${STATUS_FILE:-}"
ACL_DIR="/etc/openvpn/acl"

# IFACE: setenv IFACE > STATUS_FILE 추정
IFACE="${IFACE:-UNDEF}"
if [[ "$IFACE" == "UNDEF" && -n "$STATUS_FILE" ]]; then
  bn="$(basename "$STATUS_FILE")"; IFACE="${bn#status-mi-}"; IFACE="${IFACE%.log}"
fi

DENY_F="$ACL_DIR/deny-${IFACE}.list"; ALLOW_F="$ACL_DIR/allow-${IFACE}.list"
if [[ -f "$ALLOW_F" ]] && ! grep -Fxq "$CN" "$ALLOW_F" 2>/dev/null; then exit 1; fi
if [[ -f "$DENY_F" ]] &&  grep -Fxq "$CN" "$DENY_F" 2>/dev/null;  then exit 1; fi

count_via_status(){ # 공백/탭/CSV 모두
  local f="$1" cn="$2"
  [[ -r "$f" ]] || { echo 0; return; }
  awk -F'[,\t ]+' -v cn="$cn" '$1=="CLIENT_LIST" && $2==cn{c++} END{print 0+c}' "$f"
}

CNT=0
if [[ -n "$STATUS_FILE" ]]; then
  CNT="$(count_via_status "$STATUS_FILE" "$CN")"
fi
(( CNT >= MAX )) && exit 1
exit 0
HOOK
chmod 755 "$HOOK_LIMIT2"

# ====== ADD USER ======
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
DENY_F="$ACL_DIR/deny-${IFACE}.list"; install -d -m0755 "$ACL_DIR"; [[ -f "$DENY_F" ]] && sed -i "/^${USER}\$/d" "$DENY_F"
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

# ====== DEL USER: iface deny + 즉시 kill(CN) + 프로파일 삭제 ======
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

# mgmt 포트 계산(필요: conf에 미리 선언됨)
IFNUM=$(sed -n 's/[^0-9]*\([0-9]\+\).*/\1/p' <<<"$IFACE")
MPORT=$((7000 + IFNUM*10))

# CN 기준 즉시 종료(실패해도 계속)
{ exec 3<>/dev/tcp/127.0.0.1/"$MPORT"; printf $'kill %s\r\nquit\r\n' "$USER" >&3; cat <&3 >/dev/null || true; exec 3>&-; } || true

rm -f "$PROF_DIR/${USER}__${IFACE}.ovpn" 2>/dev/null || true
echo "[OK] iface-revoke & kill: $USER on $IFACE"
DELUSR
chmod 755 "$DELUSR"

# ====== LIST USERS: STATUS 파일 기반 ======
cat > "$LISTUSR" <<'LISTUSR'
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob
had=0
for st in /run/openvpn-server/status-mi-*.log; do
  [[ -f "$st" ]] || continue
  echo "== $(basename "$st" .log) =="
  awk -F'[,\t ]+' '$1=="CLIENT_LIST"{printf "%-18s %-22s VIP=%-15s CID=%s\n",$2,$3,$4,$12}' "$st" || true
  echo
  had=1
done
[[ $had -eq 1 ]] || echo "(no active clients)"
LISTUSR
chmod 755 "$LISTUSR"

# ====== RP_FILTER ======
apply_iface_sysctl(){
  : > /etc/sysctl.d/99-mi-openvpn-ifaces.conf
  for ifc in "$@"; do
    printf 'net.ipv4.conf.%s.rp_filter=2\n' "$ifc" >> /etc/sysctl.d/99-mi-openvpn-ifaces.conf
    printf 'net.ipv4.conf.tun-mi-%s.rp_filter=2\n' "$ifc" >> /etc/sysctl.d/99-mi-openvpn-ifaces.conf
  done
  sysctl --system >/dev/null
}

# ====== IFACE DISCOVERY ======
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

# ====== PKI INIT ======
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

# ====== PER-IF INSTANCE ======
for IFACE in "${IFACES[@]}"; do
  IFNUM=$(sed -n 's/[^0-9]*\([0-9][0-9]*\).*/\1/p' <<<"$IFACE") || true
  [[ -n "$IFNUM" ]] || { echo "[WARN] $IFACE: no number"; continue; }
  SRV_IP=$(ip -o -4 addr show dev "$IFACE" | awk '/inet /{print $4}' | cut -d/ -f1 | head -n1)
  NET=$(ip route show dev "$IFACE" | awk '/proto kernel/ {print $1; exit}')
  GW=$(ip route show default | awk -v d="$IFACE" '$0 ~ (" dev " d "($| )"){print $3; exit}')
  [[ -n "$SRV_IP" && -n "$GW" && -n "$NET" ]] || { echo "[WARN] $IFACE missing ip/gw/net"; continue; }

  PORT=$((4100 + IFNUM)); (( PORT<=65535 )) || PORT=51194
  SUBNET=10.0.${IFNUM}.0; MASK=255.255.255.0
  DEV=tun-mi-${IFACE}; SRV_CN=mi-srv-${IFACE}
  CONF=$SRV_DIR/mi-${IFACE}.conf
  TABLE=tbl${IFNUM}; TNUM=$((100 + IFNUM)); PREF=$((10000 + IFNUM))
  MPORT=$((7000 + IFNUM*10))

  [[ -f "$PKI_DIR/issued/${SRV_CN}.crt" ]] || ( cd "$EASYRSA_DIR" && ./easyrsa --batch build-server-full "$SRV_CN" nopass )

  cat >"$CONF" <<EOF
port $PORT
proto udp
local $SRV_IP
server $SUBNET $MASK

dev $DEV
persist-key
persist-tun

# management 은 user/group 앞에 둔다(필수)
management 127.0.0.1 $MPORT

user nobody
group nogroup
script-security 2

duplicate-cn
topology subnet
client-to-client
keepalive 10 120
explicit-exit-notify 1

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

# status (1s, 빠른 동기화)
status $RUN_DIR/status-mi-${IFACE}.log 1
status-version 3

# 훅/제한 환경
setenv IFACE ${IFACE}
setenv-safe MAX_SESSIONS_PER_CN 2
setenv-safe STATUS_FILE $RUN_DIR/status-mi-${IFACE}.log
client-connect $HOOK_LIMIT2
client-disconnect $HOOK_LIMIT2

mute-replay-warnings
verb 3
EOF

  # policy routing
  grep -q "^$TNUM $TABLE$" /etc/iproute2/rt_tables 2>/dev/null || echo "$TNUM $TABLE" >> /etc/iproute2/rt_tables
  ip route replace "$NET" dev "$IFACE" proto kernel scope link src "$SRV_IP" table "$TABLE" || true
  ip route replace default via "$GW" dev "$IFACE" src "$SRV_IP" table "$TABLE" || true
  while ip rule show | grep -q "from $SUBNET/24 lookup $TABLE"; do ip rule del from "$SUBNET/24" table "$TABLE" 2>/dev/null || break; done
  ip rule add from "$SUBNET/24" table "$TABLE" 2>/dev/null || true
  ip rule show | grep -q "from $SRV_IP/32 lookup $TABLE" || ip rule add pref "$PREF" from "$SRV_IP/32" lookup "$TABLE" 2>/dev/null || true

  add_snat_rule "$SUBNET/$MASK" "$IFACE" "$SRV_IP"
  open_if_port "$IFACE" "$SRV_IP" "$PORT" udp

  # drop-in: 라우팅 복구
  instdir="/etc/systemd/system/openvpn-server@mi-${IFACE}.service.d"; install -d -m0755 "$instdir"
  cat > "$instdir/mi-route.conf" <<EOF
[Service]
ExecStartPost=-/usr/local/sbin/mi_route_repair.sh --only $IFACE
EOF

  systemctl daemon-reload
  systemctl enable --now "openvpn-server@mi-${IFACE}.service" || true
  echo "[OK] mi-${IFACE}: ${SRV_IP}:${PORT} mgmt 127.0.0.1:${MPORT} subnet ${SUBNET}/24"
done

# ====== ROUTE REPAIR ======
cat > "$REPAIR" <<'REP'
#!/usr/bin/env bash
set -u
only=""
[[ "${1:-}" == "--only" && -n "${2:-}" ]] && only="$2"
log(){ echo "[repair] $*"; }
wait_if(){ local ifc="$1" n=40; while ((n-- > 0)); do ip -4 addr show dev "$ifc" | grep -q 'inet ' && return 0; sleep 0.5; done; return 1; }
ensure_nat(){ iptables -t nat -N MI-OVPN 2>/dev/null || true; iptables -t nat -C POSTROUTING -j MI-OVPN 2>/dev/null || iptables -t nat -I POSTROUTING -j MI-OVPN || true; }
add_snat(){ local SUB="$1" IFACE_P="$2" SRC="$3"; ensure_nat; iptables -t nat -C MI-OVPN -s "$SUB" -o "$IFACE_P" -j SNAT --to-source "$SRC" -m comment --comment "mi-$IFACE_P" 2>/dev/null || iptables -t nat -A MI-OVPN -s "$SUB" -o "$IFACE_P" -j SNAT --to-source "$SRC" -m comment --comment "mi-$IFACE_P" || true; }

fix(){
  local IFACE="$1" IFNUM; IFNUM=$(sed -n 's/[^0-9]*\([0-9]\+\).*/\1/p' <<<"$IFACE" || true); [[ -n "$IFNUM" ]] || return 0
  wait_if "$IFACE" || { log "$IFACE not ready"; return 0; }
  local IP NET GW TABLE="tbl${IFNUM}" TNUM=$((100+IFNUM)) PREF=$((10000+IFNUM))
  IP=$(ip -4 addr show dev "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)
  NET=$(ip route show dev "$IFACE" | awk '/proto kernel/ {print $1; exit}' || true)
  GW=$(ip route show default | awk -v d="$IFACE" '$0 ~ (" dev " d "($| )"){print $3; exit}' || true)
  [[ -n "$IP" && -n "$NET" && -n "$GW" ]] || { log "$IFACE missing"; return 0; }
  grep -q "^$TNUM $TABLE$" /etc/iproute2/rt_tables 2>/dev/null || echo "$TNUM $TABLE" >> /etc/iproute2/rt_tables || true
  ip route replace "$NET" dev "$IFACE" proto kernel scope link src "$IP" table "$TABLE" || true
  ip route replace default via "$GW" dev "$IFACE" src "$IP" table "$TABLE" || true
  while ip rule show | grep -q "from 10.0.${IFNUM}.0/24 lookup $TABLE"; do ip rule del from "10.0.${IFNUM}.0/24" table "$TABLE" 2>/dev/null || break; done
  ip rule add from "10.0.${IFNUM}.0/24" table "$TABLE" 2>/dev/null || true
  ip rule show | grep -q "from $IP/32 lookup $TABLE" || ip rule add pref "$PREF" from "$IP/32" lookup "$TABLE" 2>/dev/null || true
  add_snat "10.0.${IFNUM}.0/255.255.255.0" "$IFACE" "$IP"
  local CONF="/etc/openvpn/server/mi-${IFACE}.conf"; if [[ -f "$CONF" ]]; then CUR=$(awk '/^local /{print $2}' "$CONF"); [[ "$CUR" != "$IP" ]] && { sed -i "s/^local .*/local $IP/" "$CONF"; systemctl try-restart "openvpn-server@mi-${IFACE}.service" >/dev/null 2>&1 || true; }; fi
  log "$IFACE -> $IP via $GW"
}

mapfile -t IFACES < <(ls /etc/openvpn/server/mi-*.conf 2>/dev/null | sed -e 's#.*/mi-##' -e 's#\.conf$##')
for ifc in "${IFACES[@]}"; do
  [[ -n "$only" && "$ifc" != "$only" ]] && continue
  fix "$ifc"
done
exit 0
REP
chmod 755 "$REPAIR"

systemctl daemon-reload

# ====== UNINSTALL (ours only) ======
cat > "$UNINST" <<'UN'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "[ERR] line $LINENO: $BASH_COMMAND" >&2' ERR
OVPN_DIR=/etc/openvpn; SRV_DIR=/etc/openvpn/server; EASYRSA_DIR=/etc/openvpn/easy-rsa-mi
ACL_DIR=/etc/openvpn/acl; PROF_DIR=/home/script/openvpn/profile

CONFS=( $(ls -1 $SRV_DIR/mi-*.conf 2>/dev/null || true) )
for C in "${CONFS[@]}"; do inst=$(basename "$C" .conf); systemctl disable --now "openvpn-server@${inst}.service" 2>/dev/null || true; done
for C in "${CONFS[@]}"; do IFACE=$(basename "$C" .conf | sed 's/^mi-//'); rm -rf "/etc/systemd/system/openvpn-server@mi-${IFACE}.service.d" 2>/dev/null || true; done
systemctl daemon-reload || true

for C in "${CONFS[@]}"; do
  IP=$(awk '/^local /{print $2}' "$C"); PORT=$(awk '/^port /{print $2}' "$C"); PROTO=$(awk '/^proto /{print $2}' "$C"); IFACE=$(basename "$C" .conf | sed 's/^mi-//')
  while iptables -C INPUT -p "$PROTO" -d "$IP" --dport "$PORT" -j ACCEPT -m comment --comment "mi-${IFACE}" 2>/dev/null; do
    iptables -D INPUT -p "$PROTO" -d "$IP" --dport "$PORT" -j ACCEPT -m comment --comment "mi-${IFACE}" || break
  done
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
sysctl --system >/dev/null 2>&1 || true
echo "[DONE] MI OpenVPN uninstalled (no impact to other OpenVPN instances)"
UN
chmod 755 "$UNINST"

echo "[DONE] install script finished"
