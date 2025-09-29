#!/bin/bash
# 1) 서비스 중지·비활성화
sudo systemctl stop 'wg-quick@wg-*' 2>/dev/null || true
sudo systemctl disable 'wg-quick@wg-*' 2>/dev/null || true

# 2) iptables 정리 (INPUT/UDP와 NAT MASQUERADE)
sudo iptables -S INPUT | awk '/--dport [0-9]+ .*ACCEPT/ && /udp/ {print}' | \
  while read -r r; do sudo iptables -D ${r#-A }; done
for nic in $(ip -o link show | awk -F': ' '{print $2}'); do
  sudo iptables -t nat -C POSTROUTING -o "$nic" -j MASQUERADE 2>/dev/null && \
  sudo iptables -t nat -D POSTROUTING -o "$nic" -j MASQUERADE || true
done

# 3) 파일/폴더 삭제
sudo rm -rf /etc/wireguard
sudo rm -rf /home/script/wg
sudo rm -rf /var/lib/wireguard
sudo rm -f  /etc/sysctl.d/99-wireguard-forward.conf
sudo sysctl --system >/dev/null

# 4) 패키지까지 지우려면(선택)
sudo apt-get purge -y wireguard qrencode && sudo apt-get autoremove -y
