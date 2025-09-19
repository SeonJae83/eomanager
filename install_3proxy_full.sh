#!/usr/bin/env bash
set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ===== 설정 =====
VER=0.9.4
IF_PREFIX="${IF_PREFIX:-ens}"              # ens*
PORT_HTTP_BASE="${PORT_HTTP_BASE:-3100}"   # ens33 -> 3133
PORT_SOCKS_BASE="${PORT_SOCKS_BASE:-1000}" # ens33 -> 1033
BLOCK_DURATION="${BLOCK_DURATION:-120}"    # 초
GRACE_SEC="$BLOCK_DURATION"                # 전환 그레이스=차단시간

# ===== 패키지 =====
apt update
apt install -y build-essential wget iptables at ca-certificates

# ===== 3proxy 설치 =====
cd /usr/local/src
[[ -d 3proxy-$VER ]] || wget -q https://github.com/z3APA3A/3proxy/archive/refs/tags/$VER.tar.gz -O 3proxy-$VER.tar.gz
[[ -d 3proxy-$VER ]] || tar xzf 3proxy-$VER.tar.gz
cd 3proxy-$VER
make -f Makefile.Linux
install -m0755 bin/3proxy /usr/local/bin/3proxy

# 사용자/디렉터리
id -u 3proxy &>/dev/null || useradd -r -s /usr/sbin/nologin 3proxy
install -d -m0755 /etc/3proxy /var/log/3proxy /run/3proxy /home/script /home/script/logs
chown -R 3proxy:3proxy /var/log/3proxy /run/3proxy
touch /etc/3proxy/3proxy.cfg && chown 3proxy:3proxy /etc/3proxy/3proxy.cfg && chmod 660 /etc/3proxy/3proxy.cfg

# ===== 3proxy 베이스 설정 =====
cat >/etc/3proxy/3proxy.base.cfg <<'EOF'
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
log /var/log/3proxy/3proxy.log
logformat "L%Y-%m-%d %H:%M:%S %n %E %U %C:%c %R:%r %I %O %T"
EOF

# 계정 파일(예시)
[[ -f /etc/3proxy/users.lst ]] || cat >/etc/3proxy/users.lst <<'EOF'

EOF
chown root:3proxy /etc/3proxy/users.lst
chmod 640 /etc/3proxy/users.lst
sed -i 's/\r$//' /etc/3proxy/users.lst

# ===== 동적 생성기 =====
cat >/home/script/gen-3proxy-dynamic.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

BASE=/etc/3proxy/3proxy.base.cfg
OUT=/etc/3proxy/3proxy.cfg
IF_PREFIX="${IF_PREFIX:-ens}"
PORT_HTTP_BASE="${PORT_HTTP_BASE:-3100}"
PORT_SOCKS_BASE="${PORT_SOCKS_BASE:-1000}"
WITH_IPTABLES="${WITH_IPTABLES:-1}"
IPT="$(command -v iptables || true)"

install -d -m0750 -o root -g 3proxy /etc/3proxy/if-allow
install -d -m0755 -o 3proxy -g 3proxy /var/log/3proxy

echo "# AUTOGEN $(date -Iseconds)" >"$OUT"
cat "$BASE" >>"$OUT"; echo >>"$OUT"

mapfile -t IFACES < <(ip -o -4 addr show | awk -v pfx="^${IF_PREFIX}[0-9]+" '$2 ~ pfx {print $2}' | sort -u)

for ifc in "${IFACES[@]}"; do
  ipaddr="$(ip -4 addr show dev "$ifc" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  [[ -n "$ipaddr" ]] || continue
  num="$(sed -E 's/[^0-9]//g' <<<"$ifc")"
  hport=$((PORT_HTTP_BASE + num))
  sport=$((PORT_SOCKS_BASE + num))
  [[ $hport -le 65535 && $sport -le 65535 ]] || continue

  ufile="/etc/3proxy/if-allow/$ifc"
  ipfile="/etc/3proxy/if-allow/$ifc.ip"
  [[ -e "$ufile"  ]] || install -m0640 -o root -g 3proxy /dev/null "$ufile"
  [[ -e "$ipfile" ]] || install -m0640 -o root -g 3proxy /dev/null "$ipfile"

  {
    echo "# ---- $ifc ($ipaddr) ----"
    echo "flush"
    echo "auth iponly strong"
    echo "users \$/etc/3proxy/users.lst"

    # CIDR 화이트리스트
    if [[ -s "$ipfile" ]]; then
      while IFS= read -r raw; do
        ip="$(sed 's/#.*//' <<<"$raw" | tr -d '\r' | xargs)"
        [[ -z "$ip" ]] && continue
        echo "allow * $ip *"
      done < "$ipfile"
    fi
    # 유저 화이트리스트
    if [[ -s "$ufile" ]]; then
      while IFS= read -r raw; do
        u="$(sed 's/#.*//' <<<"$raw" | tr -d '\r' | xargs)"
        [[ -z "$u" ]] && continue
        echo "allow $u * *"
      done < "$ufile"
    fi

    echo "deny * * *"
    echo "proxy -p${hport} -i${ipaddr} -e${ipaddr} -l/var/log/3proxy/${ifc}_access.log"
    echo "socks  -p${sport} -i${ipaddr} -e${ipaddr} -l/var/log/3proxy/${ifc}_access.log"
  } >>"$OUT"

  if [[ "$WITH_IPTABLES" = "1" && -n "$IPT" && $EUID -eq 0 ]]; then
    $IPT -C INPUT -p tcp --dport "$hport" -j ACCEPT 2>/dev/null || $IPT -I INPUT -p tcp --dport "$hport" -j ACCEPT
    $IPT -C INPUT -p tcp --dport "$sport" -j ACCEPT 2>/dev/null || $IPT -I INPUT -p tcp --dport "$sport" -j ACCEPT
  fi
done

echo "# EOF" >>"$OUT"
EOF
chmod 755 /home/script/gen-3proxy-dynamic.sh
sed -i 's/\r$//' /home/script/gen-3proxy-dynamic.sh

# ===== systemd: 3proxy =====
cat >/etc/systemd/system/3proxy.service <<'EOF'
[Unit]
Description=3proxy multi-interface proxy
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=3proxy
Group=3proxy
PermissionsStartOnly=yes
ExecStartPre=/home/script/gen-3proxy-dynamic.sh
ExecStart=/usr/local/bin/3proxy /etc/3proxy/3proxy.cfg
ExecReload=/home/script/gen-3proxy-dynamic.sh
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=1
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF

# ===== manage.3proxy =====
cat >/home/script/manage.3proxy.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
OUT=/home/script/manage.3proxy.log
mkdir -p /home/script; touch "$OUT"
shopt -s nullglob
for LOG in /var/log/3proxy/ens*_access.log; do
  stdbuf -oL -eL tail -Fn0 "$LOG" | stdbuf -oL -eL awk -v OUT="$OUT" '
    function iserr(x){ return x ~ /^[0-9]{5}$/ }
    {
      err=""; user=""; cip=""; inb=0; outb=0;
      for (i=1;i<=NF;i++) if (iserr($i)) { err=$i; user=$(i+1); split($(i+2),a,":"); cip=a[1]; inb=$(i+4)+0; outb=$(i+5)+0; break }
      if (err=="00000" && cip!="") { printf("%d %s %s\n", inb+outb, user, cip) >> OUT; fflush(OUT) }
    }' &
done
wait
EOF
chmod +x /home/script/manage.3proxy.sh

cat >/etc/systemd/system/proxy-manage-3proxy.service <<'EOF'
[Unit]
Description=3proxy traffic tailer (per-interface logs)
After=3proxy.service
Requires=3proxy.service
[Service]
Type=simple
ExecStart=/home/script/manage.3proxy.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF

# ===== dupguard(인터페이스별 차단) =====
cat >/home/script/3proxy-ip-block-monitor-iface.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail
EXCLUDED_IPS=("59.14.186.184")
BLOCK_DURATION=$BLOCK_DURATION
GRACE_SEC=\$BLOCK_DURATION

LOG_DIR="/var/log/3proxy"
STATE_DIR="/var/run/3proxy_sessions"
OUT_DIR="/home/script/logs"
BLOCK_LOG="\$OUT_DIR/ip_blocked.log"
DBG_LOG="\$OUT_DIR/3proxy_dupguard_iface.log"

mkdir -p "\$STATE_DIR" "\$OUT_DIR"; touch "\$BLOCK_LOG" "\$DBG_LOG"
ipt="\$(command -v iptables || true)"; IPTW=""
if [[ -n "\$ipt" ]]; then \$ipt -w -L &>/dev/null && IPTW="-w"; fi
have_at=1; command -v at >/dev/null 2>&1 || have_at=0
is_excluded(){ local x; for x in "\${EXCLUDED_IPS[@]}"; do [[ "\$1" == "\$x" ]] && return 0; done; return 1; }

block_old_ip() {
  local IFACE="\$1" USER="\$2" OLDIP="\$3" NEWIP="\$4"
  exec 9> "\$STATE_DIR/blk.\${IFACE}.\${OLDIP}.lock"
  if ! flock -n 9; then
    echo "\$(date +'%F %T') SKIP already-blocking old=\$OLDIP iface=\$IFACE user=\$USER" >>"\$DBG_LOG"; return
  fi
  if [[ -n "\$ipt" ]]; then
    if ! \$ipt \$IPTW -C INPUT -i "\$IFACE" -s "\$OLDIP" -j DROP 2>/dev/null; then
      if \$ipt \$IPTW -I INPUT -i "\$IFACE" -s "\$OLDIP" -j DROP 2>>"\$DBG_LOG"; then
        echo "\$OLDIP|\$USER|\$IFACE|\$(date +'%F %T')" >>"\$BLOCK_LOG"
        echo "\$(date +'%F %T') BLOCK old=\$OLDIP new=\$NEWIP user=\$USER iface=\$IFACE" >>"\$DBG_LOG"
        if [[ \$have_at -eq 1 ]]; then
          M=\$((BLOCK_DURATION/60)); S=\$((BLOCK_DURATION%60))
          echo "sleep \$S; \$ipt \$IPTW -D INPUT -i \$IFACE -s \$OLDIP -j DROP" | at now + \${M} minutes >/dev/null 2>&1 || true
        fi
      else
        rc=\$?; echo "\$(date +'%F %T') BLOCK_FAIL rc=\$rc old=\$OLDIP new=\$NEWIP iface=\$IFACE" >>"\$DBG_LOG"
      fi
    fi
  else
    echo "\$(date +'%F %T') BLOCK_SKIP no-iptables old=\$OLDIP iface=\$IFACE" >>"\$DBG_LOG"
  fi
  flock -u 9
}

start_tailer() {
  local LOG="\$1" IFACE="\$2"
  echo "\$(date +'%F %T') ATTACH iface=\$IFACE log=\$LOG" >>"\$DBG_LOG"
  mkdir -p "\$STATE_DIR/\$IFACE"
  (
    stdbuf -oL -eL tail -Fn0 "\$LOG" | stdbuf -oL -eL awk '
      {
        err=""; user="-"; cip="";
        for (i=1;i<=NF;i++) if (\$i ~ /^[0-9]{5}$/) { err=\$i; if(i+1<=NF)user=\$(i+1); if(i+2<=NF){split(\$(i+2),a,":"); cip=a[1]} break }
        if (cip==""){ if (match(\$0,/([0-9]{1,3}\.){3}[0-9]{1,3}/)) cip=substr(\$0,RSTART,RLENGTH) }
        if (cip!="") print err "|" user "|" cip;
      }' | while IFS='|' read -r ERR USER CIP; do
        echo "\$(date +'%F %T') LOGIN err=\${ERR:-NA} user=\$USER ip=\$CIP iface=\$IFACE" >>"\$DBG_LOG"
        [[ -z "\$USER" || "\$USER" == "-" || -z "\$CIP" ]] && continue
        is_excluded "\$CIP" && continue

        exec 8> "\$STATE_DIR/\$IFACE/\${USER}.lock"
        if ! flock -n 8; then
          echo "\$(date +'%F %T') RACE user=\$USER ip=\$CIP iface=\$IFACE" >>"\$DBG_LOG"; continue
        fi

        cur_f="\$STATE_DIR/\$IFACE/\${USER}.cur"
        prev_f="\$STATE_DIR/\$IFACE/\${USER}.prev"
        ts_f="\$STATE_DIR/\$IFACE/\${USER}.ts"

        cur=""; prev=""; last_ts=0; now=\$(date +%s)
        [[ -f "\$cur_f"  ]] && cur="\$(<"\$cur_f")"  || true
        [[ -f "\$prev_f" ]] && prev="\$(<"\$prev_f")" || true
        [[ -f "\$ts_f"   ]] && last_ts="\$(<"\$ts_f")" || true

        # A) 같은 IP
        if [[ "\$CIP" == "\$cur" ]]; then
          echo "\$now" >"\$ts_f"; flock -u 8; continue
        fi

        # B) prev에서 옴: DROP 있으면 잔여로그, 없으면 전환
        if [[ -n "\$prev" && "\$CIP" == "\$prev" ]]; then
          if [[ -n "\$ipt" ]] && \$ipt \$IPTW -C INPUT -i "\$IFACE" -s "\$prev" -j DROP 2>/dev/null; then
            echo "\$(date +'%F %T') IGNORE grace(prev-blocked) prev=\$prev cur=\$cur user=\$USER iface=\$IFACE" >>"\$DBG_LOG"
            flock -u 8; continue
          fi
          if [[ -n "\$cur" && "\$cur" != "\$CIP" ]]; then
            block_old_ip "\$IFACE" "\$USER" "\$cur" "\$CIP"
          fi
          echo "\$cur" >"\$prev_f"; echo "\$CIP" >"\$cur_f"; echo "\$now" >"\$ts_f"
          echo "\$(date +'%F %T') SWITCH cur->\${CIP} (from prev) user=\$USER iface=\$IFACE" >>"\$DBG_LOG"
          flock -u 8; continue
        fi

        # C) 새로운 IP로 전환
        if [[ -n "\$cur" && "\$cur" != "\$CIP" ]]; then
          block_old_ip "\$IFACE" "\$USER" "\$cur" "\$CIP"
        fi
        echo "\$cur" >"\$prev_f"; echo "\$CIP" >"\$cur_f"; echo "\$now" >"\$ts_f"
        echo "\$(date +'%F %T') SWITCH cur->\${CIP} user=\$USER iface=\$IFACE" >>"\$DBG_LOG"

        flock -u 8
      done
  ) &
}

echo "\$(date +'%F %T') START dupguard" >>"\$DBG_LOG"
declare -A started; shopt -s nullglob
while true; do
  for LOG in "\$LOG_DIR"/ens*_access.log; do
    IFACE="\$(basename "\$LOG" | sed 's/_access\\.log\$//')"
    [[ -n "\${started[\$LOG]:-}" ]] || { started[\$LOG]=1; start_tailer "\$LOG" "\$IFACE"; }
  done
  sleep 5
done
EOF
chmod +x /home/script/3proxy-ip-block-monitor-iface.sh

cat >/etc/systemd/system/3proxy-ip-monitor.service <<'EOF'
[Unit]
Description=3proxy duplicate IP monitor per interface
After=3proxy.service
Requires=3proxy.service
[Service]
Type=simple
ExecStart=/home/script/3proxy-ip-block-monitor-iface.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF

# ===== 차단 목록 보기 =====
cat >/home/script/3proxy-block-list.sh <<'EOF'
#!/bin/bash
BLOCK_LOG="/home/script/logs/ip_blocked.log"

for IP in $(sudo iptables -S INPUT | grep "^-A INPUT -s" | grep " -j DROP" | awk '{print $4}' | sed 's#/32##'); do
    USER=$(grep "^$IP|" "$BLOCK_LOG" 2>/dev/null | tail -n1 | cut -d'|' -f2)
    [[ -z "$USER" ]] && USER="unknown"

    IFACE=$(grep "^$IP|" "$BLOCK_LOG" 2>/dev/null | tail -n1 | cut -d'|' -f3)
    [[ -z "$IFACE" ]] && IFACE="unknown"

    JOB_LINE=""
    while IFS= read -r line; do
        JOB_ID=$(echo "$line" | awk '{print $1}')
        if at -c "$JOB_ID" 2>/dev/null | grep -q -- "-s $IP"; then
            JOB_LINE="$line"
            break
        fi
    done < <(atq)

    if [[ -n "$JOB_LINE" ]]; then
        echo "$IP | $USER | $JOB_LINE | $IFACE"
    else
        echo "$IP | $USER | (no at job) | $IFACE"
    fi
done
EOF
chmod +x /home/script/3proxy-block-list.sh

# ===== unlock(인터페이스 지정 규칙만) =====
cat >/home/script/3proxy-unlock-ip.sh <<'EOF'
#!/bin/bash
BLOCK_LOG="/home/script/logs/ip_blocked.log"

for IP in $(sudo iptables -S INPUT | grep "^-A INPUT -s" | grep " -j DROP" | awk '{print $4}' | sed 's#/32##'); do
    USER=$(grep "^$IP|" "$BLOCK_LOG" 2>/dev/null | tail -n1 | cut -d'|' -f2)
    [[ -z "$USER" ]] && USER="unknown"

    IFACE=$(grep "^$IP|" "$BLOCK_LOG" 2>/dev/null | tail -n1 | cut -d'|' -f3)
    [[ -z "$IFACE" ]] && IFACE="unknown"

    JOB_LINE=""
    while IFS= read -r line; do
        JOB_ID=$(echo "$line" | awk '{print $1}')
        if at -c "$JOB_ID" 2>/dev/null | grep -q -- "-s $IP"; then
            JOB_LINE="$line"
            break
        fi
    done < <(atq)

    if [[ -n "$JOB_LINE" ]]; then
        echo "$IP | $USER | $JOB_LINE | $IFACE"
    else
        echo "$IP | $USER | (no at job) | $IFACE"
    fi
done
root@sg100:/home/script# cat unlock-ip.sh
#!/bin/bash
BLOCK_LOG="/home/script/logs/ip_blocked.log"

if [[ -z "$1" ]]; then
  echo "Usage: $0 <IP_ADDRESS>"
  exit 1
fi

IP="$1"
echo "Unblocking IP: $IP"

IFACES=$(grep "^$IP|" "$BLOCK_LOG" | cut -d'|' -f3 | sort -u)

if [[ -z "$IFACES" ]]; then
  echo "[WARN] No interface found for $IP in $BLOCK_LOG"
else
  for IFACE in $IFACES; do
    sudo iptables -D INPUT -i "$IFACE" -s "$IP" -j DROP && \
      echo "Removed $IP from iptables DROP rules on $IFACE"
  done
fi

for JOB in $(atq | awk '{print $1}'); do
  if sudo at -c "$JOB" | grep -q "$IP"; then
    sudo atrm "$JOB" && echo "Removed scheduled at job: $JOB"
  fi

done

if [[ -f "$BLOCK_LOG" ]]; then
  TMP_FILE=$(mktemp)
  grep -v "^$IP|" "$BLOCK_LOG" > "$TMP_FILE" && mv "$TMP_FILE" "$BLOCK_LOG"
  echo "Removed $IP entry from block log."
fi

EOF
chmod +x /home/script/3proxy-unlock-ip.sh

# ===== logrotate =====
cat >/etc/logrotate.d/3proxy <<'EOF'
/var/log/3proxy/3proxy.log /var/log/3proxy/ens*_access.log {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    dateext
    create 0640 3proxy 3proxy
    sharedscripts
    postrotate
        systemctl kill -s HUP 3proxy.service >/dev/null 2>&1 || true
    endscript
}
/home/script/manage.3proxy.log /home/script/logs/*.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF

# ===== rc.local 백업 후 squid/dante 비활성 주석 =====
if [[ -f /etc/rc.local ]]; then
  [[ -f /etc/rc.local.bak_3proxy ]] || cp -a /etc/rc.local /etc/rc.local.bak_3proxy
  sed -i -E 's/^([[:space:]]*su[[:space:]]+root[[:space:]]+-c[[:space:]]+"bash[[:space:]]+\/home\/script\/squid_config\.sh.*)/# \1/' /etc/rc.local
  sed -i -E 's/^([[:space:]]*su[[:space:]]+root[[:space:]]+-c[[:space:]]+"bash[[:space:]]+\/home\/script\/dante_config\.sh.*)/# \1/' /etc/rc.local
  chmod +x /etc/rc.local
fi

# ===== 활성화 =====
systemctl daemon-reload
systemctl enable --now 3proxy
systemctl enable --now proxy-manage-3proxy
systemctl enable --now 3proxy-ip-monitor

/home/script/gen-3proxy-dynamic.sh
systemctl restart 3proxy

echo "OK: ens*_access.log -> /var/log/3proxy/"
echo "OK: manage log      -> /home/script/manage.3proxy.log"
echo "OK: dupguard log    -> /home/script/logs/3proxy_dupguard_iface.log"
echo "Block list          -> /home/script/3proxy-block-list.sh"
echo "Unlock              -> /home/script/3proxy-unlock-ip.sh <IP>"
