#!/bin/bash

echo "스크립트 및 서비스 제거를 시작합니다..."

# 1. 서비스 중지 및 비활성화
sudo systemctl stop squid-ip-monitor.service
sudo systemctl disable squid-ip-monitor.service
sudo systemctl stop dante-ip-monitor.service
sudo systemctl disable dante-ip-monitor.service

# 2. 서비스 파일 삭제
sudo rm -f /etc/systemd/system/squid-ip-monitor.service
sudo rm -f /etc/systemd/system/dante-ip-monitor.service

# 3. systemd 데몬 리로드
sudo systemctl daemon-reexec
sudo systemctl daemon-reload

# 4. 개별 스크립트 파일 삭제
rm -f /home/script/dante-ip-block-monitor.sh
rm -f /home/script/squid-ip-block-monitor.sh
rm -f /home/script/lock-list.sh
rm -f /home/script/unlock-ip.sh

# 5. 로그디렉토리 삭제 
rm -f /home/script/logs
echo "삭제 완료"
