#!/bin/bash

# 1. 디렉토리 생성
mkdir -p /home/script/logs

# 2. dante-ip-block-monitor.sh 생성
cat << 'EOF' > /home/script/dante-ip-block-monitor.sh
#!/bin/bash
EXCLUDED_IP="59.14.186.184"

ACCESS_LOG="/dante/dante.log"
SESSION_DIR="/var/run/dante_sessions"
SESSION_TIMEOUT=300
BLOCK_DURATION=60
LOG_DIR="/home/script/logs"
BLOCK_LOG="$LOG_DIR/ip_blocked.log"
LOG_FILE="$LOG_DIR/dante_debug.log"

mkdir -p "$SESSION_DIR" "$LOG_DIR"
touch "$BLOCK_LOG" "$LOG_FILE"

tail -Fn0 "$ACCESS_LOG" | while read line; do
    if echo "$line" | grep -q "username%.*@" && echo "$line" | grep -q "pass(1): tcp/connect"; then
        USER=$(echo "$line" | grep -oP 'username%\K[^@]+')
        IP_FULL=$(echo "$line" | grep -oP 'username%[^@]+@\K[0-9.]+')
        IP=$(echo "$IP_FULL" | cut -d. -f1-4)
        NOW=$(date +%s)

        [[ -z "$USER" || -z "$IP" ]] && continue

        LAST_IP_FILE="$SESSION_DIR/${USER}.ip"
        LAST_SEEN_FILE="$SESSION_DIR/${USER}.last"

        if [[ -f "$LAST_IP_FILE" ]]; then
            OLD_IP=$(cat "$LAST_IP_FILE")
            [[ -f "$LAST_SEEN_FILE" ]] && LAST_SEEN=$(cat "$LAST_SEEN_FILE") || LAST_SEEN=0

            if [[ "$OLD_IP" != "$IP" ]]; then
                ELAPSED=$((NOW - LAST_SEEN))
                if [[ "$ELAPSED" -lt "$SESSION_TIMEOUT" ]]; then
                    if iptables -L INPUT -n | awk '$1 == "DROP" && $4 == "'$IP'"' | grep -q .; then
                        echo "$(date) [INFO] Already dropped IP $IP, skip (user=$USER)" >> "$LOG_FILE"
                        continue
                    fi
                    [[ "$IP" == "$EXCLUDED_IP" ]] && { echo "$(date) [INFO] Skipped excluded IP $IP"; continue; }
                    iptables -I INPUT -s "$IP" -j DROP
                    echo "iptables -D INPUT -s $IP -j DROP" | at now + $((BLOCK_DURATION / 60)) minutes
                    echo "$IP|$USER|$(date +'%Y-%m-%d %H:%M:%S')" >> "$BLOCK_LOG"
                    echo "$(date) [ACTION] IP $IP blocked (user=$USER), will unblock in $((BLOCK_DURATION / 60)) minutes" >> "$LOG_FILE"
                    continue
                fi
            fi
        fi

        echo "$IP" > "$LAST_IP_FILE"
        echo "$NOW" > "$LAST_SEEN_FILE"
        echo "$(date) [INFO] Normal login recorded: user=$USER, IP=$IP" >> "$LOG_FILE"
    fi
done
EOF

# 3. squid-ip-block-monitor.sh 생성
cat << 'EOF' > /home/script/squid-ip-block-monitor.sh
#!/bin/bash
EXCLUDED_IP="59.14.186.184"

ACCESS_LOG="/var/log/squid/access.log"
SESSION_DIR="/var/run/squid_sessions"
LOG_DIR="/home/script/logs"
LOG_FILE="$LOG_DIR/squid_debug.log"
BLOCK_LOG="$LOG_DIR/ip_blocked.log"
SESSION_TIMEOUT=300
BLOCK_DURATION=60

mkdir -p "$SESSION_DIR" "$LOG_DIR"
touch "$BLOCK_LOG" "$LOG_FILE"

if ! command -v at >/dev/null 2>&1; then
    sudo apt update && sudo apt install -y at
fi

tail -Fn0 "$ACCESS_LOG" | while read -r line; do
    if echo "$line" | grep -q "TCP_TUNNEL/200"; then
        IP=$(echo "$line" | awk '{print $3}')
        USER=$(echo "$line" | awk '{print $8}')
        NOW=$(date +%s)

        [[ -z "$USER" || -z "$IP" ]] && continue

        LAST_IP_FILE="$SESSION_DIR/${USER}.ip"
        LAST_SEEN_FILE="$SESSION_DIR/${USER}.last"

        if [[ -f "$LAST_IP_FILE" ]]; then
            OLD_IP=$(cat "$LAST_IP_FILE")
            [[ -f "$LAST_SEEN_FILE" ]] && LAST_SEEN=$(cat "$LAST_SEEN_FILE") || LAST_SEEN=0

            if [[ "$OLD_IP" != "$IP" ]]; then
                ELAPSED=$((NOW - LAST_SEEN))
                if [[ "$ELAPSED" -lt "$SESSION_TIMEOUT" ]]; then
                    if iptables -L INPUT -n | awk '$1 == "DROP" && $4 == "'$IP'"' | grep -q .; then
                        echo "$(date) [INFO] Already dropped IP $IP, skip (user=$USER)" >> "$LOG_FILE"
                        continue
                    fi
                    [[ "$IP" == "$EXCLUDED_IP" ]] && { echo "$(date) [INFO] Skipped excluded IP $IP"; continue; }
                    iptables -I INPUT -s "$IP" -j DROP
                    echo "iptables -D INPUT -s $IP -j DROP" | at now + $((BLOCK_DURATION / 60)) minutes
                    echo "$IP|$USER|$(date +'%Y-%m-%d %H:%M:%S')" >> "$BLOCK_LOG"
                    echo "$(date) [ACTION] IP $IP blocked (user=$USER), will unblock in $((BLOCK_DURATION / 60)) minutes" >> "$LOG_FILE"
                    continue
                fi
            fi
        fi

        echo "$IP" > "$LAST_IP_FILE"
        echo "$NOW" > "$LAST_SEEN_FILE"
        echo "$(date) [INFO] Normal login recorded: user=$USER, IP=$IP" >> "$LOG_FILE"
    fi
done
EOF

# 4. 기타 스크립트 생성
cat << 'EOF' > /home/script/lock-list.sh
#!/bin/bash

BLOCK_LOG="/home/script/logs/ip_blocked.log"

for IP in $(sudo iptables -S INPUT | grep "^-A INPUT -s" | grep " -j DROP" | awk '{print $4}' | sed 's#/32##'); do
    USER=$(grep "^$IP|" "$BLOCK_LOG" 2>/dev/null | tail -n1 | cut -d'|' -f2)
    [[ -z "$USER" ]] && USER="unknown"

    JOB_LINE=""
    while IFS= read -r line; do
        JOB_ID=$(echo "$line" | awk '{print $1}')
        if at -c "$JOB_ID" 2>/dev/null | grep -q -- "-s $IP"; then
            JOB_LINE="$line"
            break
        fi
    done < <(atq)

    if [[ -n "$JOB_LINE" ]]; then
        echo "$IP | $USER | $JOB_LINE"
    else
        echo "$IP | $USER | (no at job)"
    fi
done
EOF

cat << 'EOF' > /home/script/unlock-ip.sh
#!/bin/bash

BLOCK_LOG="/home/script/logs/ip_blocked.log"

if [[ -z "$1" ]]; then
  echo "Usage: $0 <IP_ADDRESS>"
  exit 1
fi

IP="$1"
echo "Unblocking IP: $IP"

if sudo iptables -L INPUT -n | awk -v ip="$IP" '$1 == "DROP" && $4 == ip' | grep -q .; then
  sudo iptables -D INPUT -s "$IP" -j DROP && echo "Removed $IP from iptables DROP rules."
else
  echo "$IP is not currently blocked in iptables."
fi

for JOB in $(atq | awk '{print $1}'); do
  if sudo at -c "$JOB" | grep -q "iptables -D INPUT -s $IP -j DROP"; then
    sudo atrm "$JOB" && echo "Removed scheduled at job: $JOB"
  fi
done

if [[ -f "$BLOCK_LOG" ]]; then
  TMP_FILE=$(mktemp)
  grep -v "^$IP|" "$BLOCK_LOG" > "$TMP_FILE" && mv "$TMP_FILE" "$BLOCK_LOG"
  echo "Removed $IP entry from block log."
fi
EOF

# 5. 실행 권한 부여
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

# 7. 서비스 적용 및 시작
systemctl daemon-reload
systemctl enable squid-ip-monitor.service
systemctl restart squid-ip-monitor.service
systemctl enable dante-ip-monitor.service
systemctl restart dante-ip-monitor.service

# 8. logrotate 설정 추가
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
