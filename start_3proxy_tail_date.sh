#!/usr/bin/env bash
set -euo pipefail
LOG_DATE=20251022
LOG_DIR=/var/log/3proxy
OUT=/home/script/manage.3proxy.log
DUP_SCRIPT=/home/script/3proxy-ip-block-monitor-iface.sh

echo "[INFO] patching dupguard to also follow -${LOG_DATE} logs..."
sudo sed -i \
  "s#\"\$LOG_DIR\"/ens\*_access\.log#\"\$LOG_DIR\"/ens*_access.log \"\$LOG_DIR\"/ens*_access.log-${LOG_DATE}#" \
  "$DUP_SCRIPT"

echo "[INFO] restarting 3proxy-ip-monitor.service..."
sudo systemctl daemon-reload
sudo systemctl restart 3proxy-ip-monitor.service

echo "[INFO] starting temporary manage instance for ${LOG_DATE} (output -> ${OUT})"
mkdir -p /home/script
shopt -s nullglob
setsid bash -c "
for LOG in ${LOG_DIR}/ens*_access.log-${LOG_DATE}; do
  stdbuf -oL -eL tail -Fn0 \"\$LOG\" | stdbuf -oL -eL awk -v OUT=\"${OUT}\" '
    function iserr(x){return x~/^[0-9]{5}$/}
    {
      err=\"\"; user=\"\"; cip=\"\"; inb=0; outb=0;
      for(i=1;i<=NF;i++)
        if(iserr(\$i)){
          err=\$i; user=\$(i+1);
          split(\$(i+2),a,\":\"); cip=a[1];
          inb=\$(i+4)+0; outb=\$(i+5)+0;
          break
        }
      if(err==\"00000\" && cip!=\"\"){
        printf(\"%d %s %s\\n\",inb+outb,user,cip) >> OUT;
        fflush(OUT)
      }
    }' &
done
wait
" >/dev/null 2>&1 &

echo "[OK] manage temp instance running. Shared output -> ${OUT}"
