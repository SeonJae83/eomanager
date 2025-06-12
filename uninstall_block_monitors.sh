#!/bin/bash

# 1. 서비스 중지 및 비활성화
sudo systemctl stop squid-ip-monitor.service
sudo systemctl disable squid-ip-monitor.service
sudo systemctl stop dante-ip-monitor.service
sudo systemctl disable dante-ip-monitor.service

# 2. 서비스 파일 삭제
sudo rm -rf /etc/systemd/system/squid-ip-monitor.service
sudo rm -rf /etc/systemd/system/dante-ip-monitor.service

# 3. systemd 데몬 리로드
sudo systemctl daemon-reexec
sudo systemctl daemon-reload

# 4. 개별 스크립트 파일 삭제
rm -rf /home/script/dante-ip-block-monitor.sh
rm -rf /home/script/squid-ip-block-monitor.sh
rm -rf /home/script/install_block_monitors_v3.2.sh
rm -rf /home/script/lock-list.sh
rm -rf /home/script/unlock-ip.sh
rm -rf /home/script/uninstall_block_monitors.sh

# 5. 로그디렉토리 삭제 
rm -rf /home/script/logs
