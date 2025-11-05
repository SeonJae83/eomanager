#!/usr/bin/env bash
# ===========================================
#  OpenVPN per-interface 자동 설정 스크립트
#  Author : SeonJae Lee
#  Updated: 2025-11-05
# ===========================================

set -Eeuo pipefail

# ---- rc.local 자동 생성 ----
if [[ ! -s /etc/rc.local ]]; then
  cat >/etc/rc.local <<'RCLOCAL'
#!/bin/bash
bash /home/script/openvpn-config.sh
exit 0
RCLOCAL
  chmod 755 /etc/rc.local
fi

# ---- rc-local.service 보강 ----
if ! grep -q "WantedBy=multi-user.target" /lib/systemd/system/rc-local.service 2>/dev/null; then
  printf "\n[Install]\nWantedBy=multi-user.target\n" >> /lib/systemd/system/rc-local.service
  systemctl daemon-reload || true
  systemctl enable rc-local || true
fi

# ---- 기본 server.conf 제거 ----
if [[ -s /etc/openvpn/server/server.conf ]]; then
  systemctl disable openvpn-server.service || true
  systemctl stop openvpn-server@server.service || true
  rm -f /etc/openvpn/server/server.conf
fi

# ---- openvpn-iptables.service 헤더 작성 ----
systemctl stop openvpn-iptables.service 2>/dev/null || true
cat >/etc/systemd/system/openvpn-iptables.service <<HEAD
[Unit]
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
# 관리 포트 허용 예시
ExecStart=$(command -v iptables) -I INPUT -s 59.14.186.184 -p icmp --icmp-type echo-request -j ACCEPT
ExecStop=$(command -v iptables)  -D INPUT -s 59.14.186.184 -p icmp --icmp-type echo-request -j ACCEPT
ExecStart=$(command -v iptables) -I INPUT -s 59.14.186.184 -p tcp --dport 5555 -j ACCEPT
ExecStop=$(command -v iptables)  -D INPUT -s 59.14.186.184 -p tcp --dport 5555 -j ACCEPT
ExecStart=$(command -v iptables) -I INPUT -s 192.168.0.0/24 -p tcp --dport 5555 -j ACCEPT
ExecStop=$(command -v iptables)  -D INPUT -s 192.168.0.0/24 -p tcp --dport 5555 -j ACCEPT
ExecStart=$(command -v iptables) -A INPUT -p tcp --dport 5555 -j DROP
ExecStop=$(command -v iptables)  -D INPUT -p tcp --dport 5555 -j DROP
HEAD

# ---- ensNN 인터페이스별 설정 ----
mapfile -t IFACES < <(ip -4 -o addr show | awk '$2 ~ /^ens[0-9]+$/ {print $2}' | sort -V)

for IF in "${IFACES[@]}"; do
  i="${IF#ens}"
  ipaddr="$(ip -4 -o addr show dev "$IF" | awk '{print $4}' | cut -d/ -f1)"
  [[ -n "$ipaddr" ]] || { echo "[WARN] skip $IF(no IPv4)"; continue; }

  echo "[GEN] server11${i}.conf ($ipaddr)"

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

  cat >>/etc/systemd/system/openvpn-iptables.service <<EOF
ExecStart=$(command -v iptables) -t nat -A POSTROUTING -s 10.${i}.0.0/24 ! -d 10.${i}.0.0/24 -j SNAT --to ${ipaddr}
ExecStart=$(command -v iptables) -I INPUT -p udp --dport 11${i} -j ACCEPT
ExecStart=$(command -v iptables) -I FORWARD -s 10.${i}.0.0/24 -j ACCEPT
ExecStop=$(command -v iptables)  -t nat -D POSTROUTING -s 10.${i}.0.0/24 ! -d 10.${i}.0.0/24 -j SNAT --to ${ipaddr}
ExecStop=$(command -v iptables)  -D INPUT -p udp --dport 11${i} -j ACCEPT
ExecStop=$(command -v iptables)  -D FORWARD -s 10.${i}.0.0/24 -j ACCEPT
EOF
done

# ---- 공통 FORWARD 규칙 ----
cat >>/etc/systemd/system/openvpn-iptables.service <<TAIL
ExecStart=$(command -v iptables) -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$(command -v iptables)  -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

[Install]
WantedBy=multi-user.target
TAIL

systemctl daemon-reload || true
systemctl start openvpn-iptables
echo "[OK] generation complete."

# === network-online 보장 후 서비스 시작 ===
# 네트워크가 완전히 올라올 때까지 대기
until systemctl is-active --quiet network-online.target; do
  sleep 1
done

# 유닛 리로드
systemctl daemon-reload || true

# iptables 유닛 활성화+즉시 적용
systemctl enable --now openvpn-iptables.service || true

# 생성된 conf 기준으로 OpenVPN 인스턴스 활성화+즉시 시작
for conf in /etc/openvpn/server/server11*.conf; do
  [[ -f "$conf" ]] || continue
  svc="$(basename "$conf" .conf)"              # e.g. server1133
  systemctl enable --now "openvpn-server@${svc}.service" || true
done
