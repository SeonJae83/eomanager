
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
SESSION_TIMEOUT=300
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
        IP=$(echo "$IP_FULL" | cut -d. -f1-4)
        NOW=$(date +%s)

        [[ -z "$USER" || -z "$IP" ]] && continue

        LAST_IP_FILE="$SESSION_DIR/${USER}_${IFACE}.ip"
        LAST_SEEN_FILE="$SESSION_DIR/${USER}_${IFACE}.last"

        if [[ -f "$LAST_IP_FILE" ]]; then
          OLD_IP=$(cat "$LAST_IP_FILE")
          [[ -f "$LAST_SEEN_FILE" ]] && LAST_SEEN=$(cat "$LAST_SEEN_FILE") || LAST_SEEN=0

          if [[ "$OLD_IP" != "$IP" ]]; then
            ELAPSED=$((NOW - LAST_SEEN))
            if [[ "$ELAPSED" -lt "$SESSION_TIMEOUT" ]]; then
              if iptables -L INPUT -n | grep -E "DROP" | grep -q "$IP"; then
                echo "$(date) [INFO] Already dropped IP $IP, skip (user=$USER, iface=$IFACE)" >> "$LOG_FILE"
                continue
              fi
              [[ "$IP" == "$EXCLUDED_IP" ]] && continue
              iptables -I INPUT -i "$IFACE" -s "$IP" -j DROP
              echo "iptables -D INPUT -i $IFACE -s $IP -j DROP" | at now + $((BLOCK_DURATION / 60)) minutes
              echo "$IP|$USER|$IFACE|$(date +'%Y-%m-%d %H:%M:%S')" >> "$BLOCK_LOG"
              echo "$(date) [ACTION] IP $IP blocked on $IFACE (user=$USER)" >> "$LOG_FILE"
            fi
          fi
        fi

        echo "$IP" > "$LAST_IP_FILE"
        echo "$NOW" > "$LAST_SEEN_FILE"
        echo "$(date) [INFO] Normal login recorded: user=$USER, IP=$IP, iface=$IFACE" >> "$LOG_FILE"
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
SESSION_TIMEOUT=300
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
      if echo "$line" | grep -q "TCP_TUNNEL/200"; then
        IP=$(echo "$line" | awk '{print $3}')
        USER=$(echo "$line" | awk '{print $8}')
        NOW=$(date +%s)

        [[ -z "$USER" || -z "$IP" ]] && continue

        LAST_IP_FILE="$SESSION_DIR/${USER}_${IFACE}.ip"
        LAST_SEEN_FILE="$SESSION_DIR/${USER}_${IFACE}.last"

        if [[ -f "$LAST_IP_FILE" ]]; then
          OLD_IP=$(cat "$LAST_IP_FILE")
          [[ -f "$LAST_SEEN_FILE" ]] && LAST_SEEN=$(cat "$LAST_SEEN_FILE") || LAST_SEEN=0

          if [[ "$OLD_IP" != "$IP" ]]; then
            ELAPSED=$((NOW - LAST_SEEN))
            if [[ "$ELAPSED" -lt "$SESSION_TIMEOUT" ]]; then
              if iptables -L INPUT -n | grep -E "DROP" | grep -q "$IP"; then
                echo "$(date) [INFO] Already dropped IP $IP, skip (user=$USER, iface=$IFACE)" >> "$LOG_FILE"
                continue
              fi
              [[ "$IP" == "$EXCLUDED_IP" ]] && continue
              iptables -I INPUT -i "$IFACE" -s "$IP" -j DROP
              echo "iptables -D INPUT -i $IFACE -s $IP -j DROP" | at now + $((BLOCK_DURATION / 60)) minutes
              echo "$IP|$USER|$IFACE|$(date +'%Y-%m-%d %H:%M:%S')" >> "$BLOCK_LOG"
              echo "$(date) [ACTION] IP $IP blocked on $IFACE (user=$USER)" >> "$LOG_FILE"
            fi
          fi
        fi

        echo "$IP" > "$LAST_IP_FILE"
        echo "$NOW" > "$LAST_SEEN_FILE"
        echo "$(date) [INFO] Normal login recorded: user=$USER, IP=$IP, iface=$IFACE" >> "$LOG_FILE"
      fi
    done
  ) &
done

wait
EOF

# 4. 권한 부여
chmod +x /home/script/*.sh

# 5. 서비스 유지
systemctl daemon-reload
systemctl enable squid-ip-monitor.service
systemctl restart squid-ip-monitor.service
systemctl enable dante-ip-monitor.service
systemctl restart dante-ip-monitor.service

# 6. logrotate 설정
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
