# /usr/local/sbin/replace-openvpn-config.sh 로 저장
sudo tee /usr/local/sbin/replace-openvpn-config.sh >/dev/null <<'REPLACE'
#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="/home/script/openvpn-config.sh"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="${TARGET}.${STAMP}.bak"

install -d -m 755 /home/script
if [[ -f "$TARGET" ]]; then
  cp -a "$TARGET" "$BACKUP"
  echo "[BK] Backup -> $BACKUP"
fi

# ===== 새 openvpn-config.sh 본문 쓰기 (실행은 안 함) =====
cat >"$TARGET" <<'OVPNCFG'
#!/usr/bin/env bash
# OpenVPN per-ensNN 자동 구성 스크립트
# - ensNN만 대상으로 함(wg-ens*, tun*, lo 제외)
# - 인터페이스별 server11NN.conf 생성/갱신
# - 인터페이스별 SNAT/포트 ACCEPT 규칙을 openvpn-iptables.service로 구성

set -Eeuo pipefail

# ---- rc.local 보장 (한번만 구성) ----
if [[ ! -s /etc/rc.local ]]; then
  cat >/etc/rc.local <<'RCLOCAL'
#!/bin/bash
bash /home/script/openvpn-config.sh
exit 0
RCLOCAL
  chmod 755 /etc/rc.local
fi

# ---- rc-local.service Install 섹션 보강 ----
if ! grep -q "WantedBy=multi-user.target" /lib/systemd/system/rc-local.service 2>/dev/null; then
  printf "\n[Install]\nWantedBy=multi-user.target\n" >> /lib/systemd/system/rc-local.service
  systemctl daemon-reload || true
  systemctl enable rc-local || true
fi

# ---- 기존 단일 server.conf 제거 ----
if [[ -s /etc/openvpn/server/server.conf ]]; then
  systemctl disable openvpn-server.service || true
  systemctl stop openvpn-server@server.service || true
  rm -f /etc/openvpn/server/server.conf
fi

# ---- iptables 서비스 헤더 작성 ----
systemctl stop openvpn-iptables.service 2>/dev/null || true
cat >/etc/systemd/system/openvpn-iptables.service <<'IPTSVC'
[Unit]
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
# 관리 포트 접근 허용(사전 허용 IP 예시 + 사내대역)
ExecStart=/sbin/iptables -I INPUT -s 59.14.186.184 -p icmp --icmp-type echo-request -j ACCEPT
ExecStop=/sbin/iptables  -D INPUT -s 59.14.186.184 -p icmp --icmp-type echo-request -j ACCEPT
ExecStart=/sbin/iptables -I INPUT -s 59.14.186.184 -p tcp --dport 5555 -j ACCEPT
ExecStop=/sbin/iptables  -D INPUT -s 59.14.186.184 -p tcp --dport 5555 -j ACCEPT
ExecStart=/sbin/iptables -I INPUT -s 192.168.0.0/24 -p icmp --icmp-type echo-request -j ACCEPT
ExecStop=/sbin/iptables  -D INPUT -s 192.168.0.0/24 -p icmp --icmp-type echo-request -j ACCEPT
ExecStart=/sbin/iptables -I INPUT -s 192.168.0.0/24 -p tcp --dport 5555 -j ACCEPT
ExecStop=/sbin/iptables  -D INPUT -s 192.168.0.0/24 -p tcp --dport 5555 -j ACCEPT
# 기본 DROP (5555)
ExecStart=/sbin/iptables -A INPUT -s 0.0.0.0/0 -p tcp --dport 5555 -j DROP
ExecStop=/sbin/iptables  -D INPUT -s 0.0.0.0/0 -p tcp --dport 5555 -j DROP
IPTSVC

# ---- ensNN만 순회 ----
mapfile -t IFACES < <(ip -4 -o addr show | awk '$2 ~ /^ens[0-9]+$/ {print $2}' | sort -V)

for IF in "${IFACES[@]}"; do
  i="${IF#ens}"
  ipaddr="$(ip -4 -o addr show dev "$IF" | awk '{print $4}' | cut -d/ -f1)"
  [[ -n "$ipaddr" ]] || { echo "[WARN] skip $IF: no IPv4"; continue; }

  echo "[GEN] /etc/openvpn/server/server11${i}.conf (${ipaddr})"

  cat >"/etc/openvpn/server/server11${i}.conf" <<EOF
local ${ipaddr}
port 11${i}
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.${i}.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
ifconfig-pool-persist ipp.txt
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "block-outside-dns"
keepalive 10 120
user nobody
group nogroup
persist-key
persist-tun
verb 3
crl-verify crl.pem
explicit-exit-notify
management ${ipaddr} 5555
EOF

  # iptables per-IF 규칙 추가
  cat >>/etc/systemd/system/openvpn-iptables.service <<EOF
ExecStart=/sbin/iptables -t nat -A POSTROUTING -s 10.${i}.0.0/24 ! -d 10.${i}.0.0/24 -j SNAT --to ${ipaddr}
ExecStart=/sbin/iptables -I INPUT -p udp --dport 11${i} -j ACCEPT
ExecStart=/sbin/iptables -I FORWARD -s 10.${i}.0.0/24 -j ACCEPT
ExecStop=/sbin/iptables  -t nat -D POSTROUTING -s 10.${i}.0.0/24 ! -d 10.${i}.0.0/24 -j SNAT --to ${ipaddr}
ExecStop=/sbin/iptables  -D INPUT -p udp --dport 11${i} -j ACCEPT
ExecStop=/sbin/iptables  -D FORWARD -s 10.${i}.0.0/24 -j ACCEPT
EOF

  # 부팅 시 적용되므로 여기서는 재시작 생략
  # 필요시: systemctl restart "openvpn-server@server11${i}.service"
done

# 공통 FORWARD 상태 트래킹 규칙
cat >>/etc/systemd/system/openvpn-iptables.service <<'TAIL'
ExecStart=/sbin/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=/sbin/iptables  -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

[Install]
WantedBy=multi-user.target
TAIL

# 유닛 로드만 (즉시 start 하지 않음)
systemctl daemon-reload || true
# systemctl enable openvpn-iptables.service || true

echo "[OK] generation complete."
OVPNCFG

chmod 755 "$TARGET"
chown root:root "$TARGET"
echo "[OK] Replaced -> $TARGET (not executed now)"
REPLACE

sudo chmod 755 /usr/local/sbin/replace-openvpn-config.sh
