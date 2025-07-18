#!/bin/bash
# OpenVPN 불필요 서비스 중지
systemctl stop openvpn
systemctl disable openvpn

# 1. 디렉토리 생성
mkdir -p /home/script/logs

# 2. dante-ip-block-monitor.sh 생성
cat << 'EOF' > /home/script/dante-ip-block-monitor.sh
#!/bin/bash
EXCLUDED_IP="59.14.186.184"

SESSION_DIR="/var/run/dante_sessions"
LOG_DIR="/home/script/logs"
BLOCK_LOG="$LOG_DIR/ip_blocked.log"
LOG_FILE="$LOG_DIR/dante_debug.log"
BLOCK_DURATION=300

mkdir -p "$SESSION_DIR" "$LOG_DIR"
touch "$BLOCK_LOG" "$LOG_FILE"

for LOG in /dante/ens*_access.log; do
  IFACE=$(basename "$LOG" | cut -d_ -f1)
  (
    tail -Fn0 "$LOG" | while read line; do
      if echo "$line" | grep -q "username%.*@" && echo "$line" | grep -q "pass(1): tcp/connect"; then
        USER=$(echo "$line" | grep -oP 'username%\K[^@]+')
        IP_FULL=$(echo "$line" | grep -oP 'username%[^@]+@\K[0-9.]+')
        IP=$(echo "$IP_FULL" | grep -oP '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b')

        [[ -z "$USER" || -z "$IP" ]] && continue

        LOCK_FILE="$SESSION_DIR/${USER}_${IFACE}.lock"
        LAST_IP_FILE="$SESSION_DIR/${USER}_${IFACE}.ip"

        if ( set -o noclobber; echo "$IP" > "$LOCK_FILE" ) 2>/dev/null; then
          if [[ -f "$LAST_IP_FILE" ]]; then
            OLD_IP=$(cat "$LAST_IP_FILE" | grep -oP '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b')
            if [[ "$OLD_IP" != "$IP" && "$OLD_IP" != "$EXCLUDED_IP" ]]; then
              if ! iptables -L INPUT -n | grep -q "$OLD_IP"; then
                iptables -I INPUT -i "$IFACE" -s "$OLD_IP" -j DROP
                echo "iptables -D INPUT -i $IFACE -s $OLD_IP -j DROP" | at now + $((BLOCK_DURATION / 60)) minutes
                echo "$OLD_IP|$USER|$IFACE|$(date +'%Y-%m-%d %H:%M:%S')" >> "$BLOCK_LOG"
                echo "$(date) [ACTION] OLD IP $OLD_IP blocked on $IFACE due to NEW login $IP (user=$USER)" >> "$LOG_FILE"
              else
                echo "$(date) [INFO] Already dropped IP $OLD_IP, skip (user=$USER, iface=$IFACE)" >> "$LOG_FILE"
              fi
            fi
          fi

          echo "$IP" > "$LAST_IP_FILE"
          echo "$(date) [INFO] Normal login recorded: user=$USER, IP=$IP, iface=$IFACE" >> "$LOG_FILE"

          rm -f "$LOCK_FILE"
        else
          echo "$(date) [WARN] Detected race for user=$USER on $IFACE. Rejecting IP=$IP to protect NEW." >> "$LOG_FILE"
        fi
      fi
    done
  ) &
done

wait
EOF

# 3. squid-ip-block-monitor.sh 생성
cat << 'EOF' > /home/script/squid-ip-block-monitor.sh
#!/bin/bash
EXCLUDED_IP="59.14.186.184"

SESSION_DIR="/var/run/squid_sessions"
LOG_DIR="/home/script/logs"
BLOCK_LOG="$LOG_DIR/ip_blocked.log"
LOG_FILE="$LOG_DIR/squid_debug.log"
BLOCK_DURATION=300

mkdir -p "$SESSION_DIR" "$LOG_DIR"
touch "$BLOCK_LOG" "$LOG_FILE"

if ! command -v at >/dev/null 2>&1; then
  sudo apt update && sudo apt install -y at
fi

for LOG in /var/log/squid/ens*_access.log; do
  IFACE=$(basename "$LOG" | cut -d_ -f1)
  (
    tail -Fn0 "$LOG" | while read -r line; do
      if echo "$line" | grep -q "CONNECT" && echo "$line" | grep -q "TCP_TUNNEL/200"; then
        IP=$(echo "$line" | awk '{print $3}')
        USER=$(echo "$line" | awk '{print $8}')

        [[ -z "$USER" || "$USER" == "-" || -z "$IP" ]] && continue

        LOCK_FILE="$SESSION_DIR/${USER}_${IFACE}.lock"
        LAST_IP_FILE="$SESSION_DIR/${USER}_${IFACE}.ip"

        if ( set -o noclobber; echo "$IP" > "$LOCK_FILE" ) 2>/dev/null; then
          if [[ -f "$LAST_IP_FILE" ]]; then
            OLD_IP=$(cat "$LAST_IP_FILE" | grep -oP '([0-9]{1,3}\.){3}[0-9]{1,3}')
            if [[ "$OLD_IP" != "$IP" && "$OLD_IP" != "$EXCLUDED_IP" ]]; then
              if ! iptables -L INPUT -n | grep -q "$OLD_IP"; then
                iptables -I INPUT -i "$IFACE" -s "$OLD_IP" -j DROP
                echo "iptables -D INPUT -i $IFACE -s $OLD_IP -j DROP" | at now + $((BLOCK_DURATION / 60)) minutes
                echo "$OLD_IP|$USER|$IFACE|$(date +'%Y-%m-%d %H:%M:%S')" >> "$BLOCK_LOG"
                echo "$(date) [ACTION] OLD IP $OLD_IP blocked on $IFACE due to NEW login $IP (user=$USER)" >> "$LOG_FILE"
              else
                echo "$(date) [INFO] Already dropped IP $OLD_IP, skip (user=$USER, iface=$IFACE)" >> "$LOG_FILE"
              fi
            fi
          fi

          echo "$IP" > "$LAST_IP_FILE"
          echo "$(date) [INFO] Normal login recorded: user=$USER, IP=$IP, iface=$IFACE" >> "$LOG_FILE"

          rm -f "$LOCK_FILE"
        else
          echo "$(date) [WARN] Detected race for user=$USER on $IFACE. Rejecting IP=$IP to protect NEW." >> "$LOG_FILE"
        fi
      fi
    done
  ) &
done

wait
EOF


# 4. 기타 도우미 스크립트 추가

# 차단 목록 보기
cat << 'EOF' > /home/script/lock-list.sh
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

# 차단 해제 스크립트
cat << 'EOF' > /home/script/unlock-ip.sh
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

# 5. 권한 부여
chmod +x /home/script/*.sh

# 6. systemd 서비스 등록
cat << EOF | tee /etc/systemd/system/squid-ip-monitor.service > /dev/null
[Unit]
Description=Squid IP Duplicate Session Monitor
After=network.target

[Service]
Type=simple
ExecStart=/home/script/squid-ip-block-monitor.sh
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

cat << EOF | tee /etc/systemd/system/dante-ip-monitor.service > /dev/null
[Unit]
Description=Dante IP Duplicate Session Monitor
After=network.target

[Service]
Type=simple
ExecStart=/home/script/dante-ip-block-monitor.sh
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

# 7. 서비스 유지
systemctl daemon-reload
systemctl enable squid-ip-monitor.service
systemctl restart squid-ip-monitor.service
systemctl enable dante-ip-monitor.service
systemctl restart dante-ip-monitor.service

# 8. logrotate 설정
cat << EOF | tee /etc/logrotate.d/block-monitor > /dev/null
/home/script/logs/*.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF
