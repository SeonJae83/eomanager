#!/usr/bin/env bash
# start_3proxy_tail_20251022.sh — ens*_access.log-20251022 임시 수집 + dupguard
set -euo pipefail

# 고정값
DATE=20251022
LOGDIR="/var/log/3proxy"
OUT="/home/script/manage.3proxy.log"

# dupguard 설정
BLOCK_DURATION="${BLOCK_DURATION:-120}"   # 초
EXCLUDED_IPS=(${EXCLUDED_IPS:-})          # 공백 구분 예: "1.2.3.4 5.6.7.8"
STATE_DIR="/var/run/3proxy_sessions"
OUT_DIR="/home/script/logs"
BLOCK_LOG="$OUT_DIR/ip_blocked.log"
DBG_LOG="$OUT_DIR/3proxy_dupguard_iface.log"

# 준비
mkdir -p /home/script "$OUT_DIR" "$STATE_DIR"
touch "$OUT" "$BLOCK_LOG" "$DBG_LOG"

# 이미 돌고 있으면 스킵
if pgrep -fa 'MANAGE_3PROXY_TEMP_20251022' >/dev/null 2>&1; then
  echo "manage temp already running"; M_ALREADY=1
else
  M_ALREADY=0
fi
if pgrep -fa 'DUPGUARD_3PROXY_TEMP_20251022' >/dev/null 2>&1; then
  echo "dupguard temp already running"; D_ALREADY=1
else
  D_ALREADY=0
fi

# 없으면 시작: manage 임시 인스턴스(20251022만 tail)
if [[ $M_ALREADY -eq 0 ]]; then
  setsid bash -c '
    MARK=MANAGE_3PROXY_TEMP_20251022
    shopt -s nullglob
    for LOG in '"$LOGDIR"'/ens*_access.log-'"$DATE"'; do
      stdbuf -oL -eL tail -Fn0 "$LOG" | stdbuf -oL -eL awk -v OUT="'"$OUT"'" '"'"'
        function iserr(x){return x~/^[0-9]{5}$/}
        {
          err="";user="";cip="";inb=0;outb=0;
          for(i=1;i<=NF;i++) if(iserr($i)){err=$i;user=$(i+1);split($(i+2),a,":");cip=a[1];inb=$(i+4)+0;outb=$(i+5)+0;break}
          if(err=="00000" && cip!=""){printf("%d %s %s\n",inb+outb,user,cip)>>OUT; fflush(OUT)}
        }'"'"' &
    done
    wait
  ' >/dev/null 2>&1 &
  echo "started manage temp"
fi

# 없으면 시작: dupguard 임시 인스턴스(20251022만 tail)
if [[ $D_ALREADY -eq 0 ]]; then
  setsid bash -c '
    MARK=DUPGUARD_3PROXY_TEMP_20251022
    set -euo pipefail
    LOGDIR='"$LOGDIR"'
    DATE='"$DATE"'
    STATE_DIR='"$STATE_DIR"'
    OUT_DIR='"$OUT_DIR"'
    BLOCK_LOG='"$BLOCK_LOG"'
    DBG_LOG='"$DBG_LOG"'
    BLOCK_DURATION='"$BLOCK_DURATION"'
    declare -a EXCLUDED_IPS=('"${EXCLUDED_IPS[*]:-}"')

    mkdir -p "$STATE_DIR" "$OUT_DIR"; touch "$BLOCK_LOG" "$DBG_LOG"

    ipt="$(command -v iptables || true)"; IPTW=""
    if [[ -n "$ipt" ]]; then $ipt -w -L &>/dev/null && IPTW="-w" || true; fi
    have_at=1; command -v at >/dev/null 2>&1 || have_at=0

    is_excluded(){ local x; for x in "${EXCLUDED_IPS[@]:-}"; do [[ "$1" == "$x" ]] && return 0; done; return 1; }

    block_old_ip(){
      local IFACE="$1" USER="$2" OLDIP="$3" NEWIP="$4"
      exec 9> "$STATE_DIR/blk.${IFACE}.${OLDIP}.lock"
      if ! flock -n 9; then
        echo "$(date +"%F %T") SKIP already-blocking old=$OLDIP iface=$IFACE user=$USER" >>"$DBG_LOG"; return
      fi
      if [[ -n "$ipt" ]]; then
        if ! $ipt $IPTW -C INPUT -i "$IFACE" -s "$OLDIP" -j DROP 2>/dev/null; then
          if $ipt $IPTW -I INPUT -i "$IFACE" -s "$OLDIP" -j DROP 2>>"$DBG_LOG"; then
            echo "$OLDIP|$USER|$IFACE|$(date +'%F %T')" >>"$BLOCK_LOG"
            echo "$(date +"%F %T") BLOCK old=$OLDIP new=$NEWIP user=$USER iface=$IFACE" >>"$DBG_LOG"
            if [[ $have_at -eq 1 ]]; then
              M=$((BLOCK_DURATION/60)); S=$((BLOCK_DURATION%60))
              echo "sleep $S; $ipt $IPTW -D INPUT -i $IFACE -s $OLDIP -j DROP" | at now + ${M} minutes >/dev/null 2>&1 || true
            fi
          else
            rc=$?; echo "$(date +"%F %T") BLOCK_FAIL rc=$rc old=$OLDIP new=$NEWIP iface=$IFACE" >>"$DBG_LOG"
          fi
        fi
      else
        echo "$(date +"%F %T") BLOCK_SKIP no-iptables old=$OLDIP iface=$IFACE" >>"$DBG_LOG"
      fi
      flock -u 9
    }

    start_tailer(){
      local LOG="$1" IFACE="$2"
      echo "$(date +"%F %T") ATTACH iface=$IFACE log=$LOG" >>"$DBG_LOG"
      mkdir -p "$STATE_DIR/$IFACE"
      (
        stdbuf -oL -eL tail -Fn0 "$LOG" | stdbuf -oL -eL awk "
          {
            err=\"\"; user=\"-\"; cip=\"\";
            for (i=1;i<=NF;i++) if (\$i ~ /^[0-9]{5}\$/) { err=\$i; if(i+1<=NF)user=\$(i+1); if(i+2<=NF){split(\$(i+2),a,\":\"); cip=a[1]} break }
            if (cip==\"\" && match(\$0,/([0-9]{1,3}\\.){3}[0-9]{1,3}/)) cip=substr(\$0,RSTART,RLENGTH)
            if (cip!=\"\") print err \"|\" user \"|\" cip;
          }" | while IFS="|" read -r ERR USER CIP; do
            [[ -z "$USER" || "$USER" == "-" || -z "$CIP" ]] && continue
            is_excluded "$CIP" && continue

            exec 8> "$STATE_DIR/$IFACE/${USER}.lock"
            if ! flock -n 8; then
              echo "$(date +"%F %T") RACE user=$USER ip=$CIP iface=$IFACE" >>"$DBG_LOG"; continue
            fi

            cur_f="$STATE_DIR/$IFACE/${USER}.cur"
            prev_f="$STATE_DIR/$IFACE/${USER}.prev"
            ts_f="$STATE_DIR/$IFACE/${USER}.ts"

            cur=""; prev=""; last_ts=0; now=$(date +%s)
            [[ -f "$cur_f"  ]] && cur="$(<"$cur_f")"  || true
            [[ -f "$prev_f" ]] && prev="$(<"$prev_f")" || true
            [[ -f "$ts_f"   ]] && last_ts="$(<"$ts_f")" || true

            if [[ "$CIP" == "$cur" ]]; then
              echo "$now" >"$ts_f"; flock -u 8; continue
            fi

            if [[ -n "$prev" && "$CIP" == "$prev" ]]; then
              if [[ -n "'"$ipt"'" ]] && '"$ipt"' '"$IPTW"' -C INPUT -i "$IFACE" -s "$prev" -j DROP 2>/dev/null; then
                echo "$(date +"%F %T") IGNORE grace(prev-blocked) prev=$prev cur=$cur user=$USER iface=$IFACE" >>"$DBG_LOG"
                flock -u 8; continue
              fi
              if [[ -n "$cur" && "$cur" != "$CIP" ]]; then
                block_old_ip "$IFACE" "$USER" "$cur" "$CIP"
              fi
              echo "$cur" >"$prev_f"; echo "$CIP" >"$cur_f"; echo "$now" >"$ts_f"
              echo "$(date +"%F %T") SWITCH cur->$CIP (from prev) user=$USER iface=$IFACE" >>"$DBG_LOG"
              flock -u 8; continue
            fi

            if [[ -n "$cur" && "$cur" != "$CIP" ]]; then
              block_old_ip "$IFACE" "$USER" "$cur" "$CIP"
            fi
            echo "$cur" >"$prev_f"; echo "$CIP" >"$cur_f"; echo "$now" >"$ts_f"
            echo "$(date +"%F %T") SWITCH cur->$CIP user=$USER iface=$IFACE" >>"$DBG_LOG"

            flock -u 8
          done
      ) &
    }

    echo "$(date +"%F %T") START dupguard-temp" >>"$DBG_LOG"
    shopt -s nullglob
    for LOG in "$LOGDIR"/ens*_access.log-"$DATE"; do
      IFACE="$(basename "$LOG" | sed "s/_access\\.log-$DATE\$//")"
      start_tailer "$LOG" "$IFACE"
    done
    wait
  ' >/dev/null 2>&1 &
  echo "started dupguard temp"
fi

echo "OK: temp tailers for $DATE started"
