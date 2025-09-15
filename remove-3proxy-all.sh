#!/usr/bin/env bash
set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# 설치 때 사용한 기준
IF_PREFIX="${IF_PREFIX:-ens}"
PORT_HTTP_BASE="${PORT_HTTP_BASE:-3100}"
PORT_SOCKS_BASE="${PORT_SOCKS_BASE:-1000}"

say(){ echo "[remove] $*"; }

ipt="$(command -v iptables || true)"; IPTW=""
if [[ -n "$ipt" ]]; then $ipt -w -L &>/dev/null && IPTW="-w"; fi

# 1) 서비스 중지/비활성
for svc in 3proxy-ip-monitor proxy-manage-3proxy 3proxy; do
  systemctl stop "$svc" 2>/dev/null || true
  systemctl disable "$svc" 2>/dev/null || true
done
pkill -f /home/script/manage.3proxy.sh 2>/dev/null || true
pkill -f /home/script/3proxy-ip-block-monitor-iface.sh 2>/dev/null || true

# 2) dupguard가 추가한 DROP(-i IFACE -s IP) 제거
if [[ -n "$ipt" ]]; then
  say "delete interface-bound DROP rules"
  while read -r line; do
    iface="$(sed -n 's/.* -i \([^ ]*\).*/\1/p' <<<"$line")"
    sip="$(sed -n 's/.* -s \([^ ]*\).*/\1/p' <<<"$line")"
    [[ -n "$iface" && -n "$sip" ]] || continue
    $ipt $IPTW -C INPUT -i "$iface" -s "$sip" -j DROP 2>/dev/null && \
    $ipt $IPTW -D INPUT -i "$iface" -s "$sip" -j DROP && say "DROP -i $iface -s ${sip%/32} removed"
  done < <($ipt -S INPUT 2>/dev/null | grep -E '^-A INPUT .* -i '"$IF_PREFIX"'[0-9]+ .* -s .* -j DROP' || true)

  # at 예약된 해제 작업 제거
  if command -v atq >/dev/null 2>&1; then
    while read -r jid _; do
      job="$(at -c "$jid" 2>/dev/null || true)"
      grep -q -- "$ipt .* -D INPUT -i $IF_PREFIX" <<<"$job" && atrm "$jid" && say "at job $jid removed"
    done < <(atq 2>/dev/null || true)
  fi
fi

# 3) 포트 ACCEPT 규칙 제거(생성기에서 추가함)
if [[ -n "$ipt" ]]; then
  say "delete 3proxy port ACCEPT rules"
  mapfile -t IFACES < <(ip -o -4 addr show | awk -v pfx="^${IF_PREFIX}[0-9]+" '$2 ~ pfx {print $2}' | sort -u)
  for ifc in "${IFACES[@]}"; do
    num="$(sed -E 's/[^0-9]//g' <<<"$ifc")"
    [[ -n "$num" ]] || continue
    hport=$((PORT_HTTP_BASE + num))
    sport=$((PORT_SOCKS_BASE + num))
    for p in "$hport" "$sport"; do
      $ipt $IPTW -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null && \
      $ipt $IPTW -D INPUT -p tcp --dport "$p" -j ACCEPT && say "ACCEPT dport $p removed"
    done
  done
fi

# 4) 유닛/로그/스크립트/설정/바이너리 제거
say "remove systemd units"
rm -f /etc/systemd/system/3proxy.service
rm -f /etc/systemd/system/proxy-manage-3proxy.service
rm -f /etc/systemd/system/3proxy-ip-monitor.service

say "remove logrotate"
rm -f /etc/logrotate.d/3proxy

say "remove scripts"
rm -f /home/script/gen-3proxy-dynamic.sh
rm -f /home/script/manage.3proxy.sh
rm -f /home/script/3proxy-ip-block-monitor-iface.sh
rm -f /home/script/3proxy-block-list.sh
rm -f /home/script/3proxy-unlock-ip.sh
rm -f /home/script/manage.3proxy.log
rm -rf /home/script/logs

say "remove 3proxy configs and logs"
rm -rf /etc/3proxy
rm -rf /var/log/3proxy
rm -rf /run/3proxy 2>/dev/null || true

say "remove 3proxy binary and sources"
rm -f /usr/local/bin/3proxy
rm -rf /usr/local/src/3proxy-0.9.4 /usr/local/src/3proxy-0.9.4.tar.gz 2>/dev/null || true

# 5) 사용자 삭제(필요 시)
userdel 3proxy 2>/dev/null || true
getent group 3proxy >/dev/null && groupdel 3proxy 2>/dev/null || true

# 6) rc.local 복구
if [[ -f /etc/rc.local.bak_3proxy ]]; then
  cp -a /etc/rc.local.bak_3proxy /etc/rc.local
  chmod +x /etc/rc.local
  rm -f /etc/rc.local.bak_3proxy
  say "rc.local restored from backup"
fi

# 7) 마무리
systemctl daemon-reload
say "done"
