#!/usr/bin/env bash
# start_3proxy_tail_date.sh — ens*_access.log-20251022 임시 수집기 (입력 불필요)
set -euo pipefail

DATE=20251022
OUT="/home/script/manage.3proxy.log"
MANAGE="/home/script/manage.3proxy.sh"
DUPMON="/home/script/3proxy-ip-block-monitor-iface.sh"
LOGDIR="/var/log/3proxy"

[[ -x "$MANAGE" ]] || { echo "no $MANAGE"; exit 1; }
[[ -x "$DUPMON"  ]] || { echo "no $DUPMON";  exit 1; }
mkdir -p /home/script /home/script/logs

if pgrep -f "ens\*_access\.log-$DATE" >/dev/null 2>&1; then
  echo "already running for $DATE"; exit 0
fi

# manage.3proxy 임시 인스턴스 (날짜 파일만 tail)
setsid bash -c '
for LOG in '"$LOGDIR"'/ens*_access.log-'"$DATE"'; do
  stdbuf -oL -eL tail -Fn0 "$LOG" | stdbuf -oL -eL awk -v OUT="'"$OUT"'" '"'"'
    function iserr(x){return x~/^[0-9]{5}$/}
    { err="";user="";cip="";inb=0;outb=0;
      for(i=1;i<=NF;i++) if(iserr($i)){err=$i;user=$(i+1);split($(i+2),a,":");cip=a[1];inb=$(i+4)+0;outb=$(i+5)+0;break}
      if(err=="00000" && cip!=""){printf("%d %s %s\n",inb+outb,user,cip)>>OUT; fflush(OUT)}
    }'"'"' &
done
wait' >/dev/null 2>&1 &

# dupguard 임시 인스턴스 (날짜 파일만 tail)
setsid bash <(sed 's#"\\$LOG_DIR"/ens\\*_access\\.log#"'$LOGDIR'"/ens*_access.log-'"$DATE"'#g' "$DUPMON") >/dev/null 2>&1 &

echo "started temp tailers for $DATE"
