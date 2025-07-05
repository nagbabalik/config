#!/bin/bash

# === CONFIG ===
DOMAIN="xovnb.tranz.shop"
NS_DOMAIN="ns.xovnb.tranz.shop"
KCP_PORT="4000"
KCP_KEY="gtmkcp2025"
SLOWDNS_PORT="5300"
SSH_FORWARD_PORT="2222"

# === UPDATE & INSTALL ===
apt update && apt install -y curl git make gcc net-tools sudo wget unzip socat screen iproute2 iptables

# === CREATE WORK DIRS ===
mkdir -p /opt/slowdns /opt/kcptun
cd /opt/slowdns

# === BUILD SlowDNS ===
echo "[+] Installing SlowDNS server..."
wget -q https://raw.githubusercontent.com/ambrop72/badvpn/master/dns.c -O dns.c
gcc dns.c -o dns-server
mv dns-server /usr/local/bin/
chmod +x /usr/local/bin/dns-server

# === GEN KEYS ===
dns-server -gen-key -privkey-file /opt/slowdns/private.key -pubkey-file /opt/slowdns/public.key

# === DOWNLOAD KCP ===
cd /opt/kcptun
wget https://github.com/xtaci/kcptun/releases/download/v20240315/kcptun-linux-amd64-20240315.tar.gz
tar -xvzf kcptun-linux-amd64-*.tar.gz
mv server_linux_amd64 /usr/local/bin/kcp-server
mv client_linux_amd64 /usr/local/bin/kcp-client
chmod +x /usr/local/bin/kcp-server /usr/local/bin/kcp-client

# === CREATE KCP SERVER CONFIG ===
cat > /etc/kcp-server.json <<EOF
{
  "listen": ":$KCP_PORT",
  "target": "127.0.0.1:22",
  "key": "$KCP_KEY",
  "crypt": "aes-128",
  "mode": "fast2",
  "mtu": 1350,
  "sndwnd": 1024,
  "rcvwnd": 1024,
  "nocomp": true
}
EOF

# === CREATE KCP LOCAL CLIENT SERVICE ===
cat > /etc/systemd/system/kcp-client.service <<EOF
[Unit]
Description=KCP Client Tunnel
After=network.target

[Service]
ExecStart=/usr/local/bin/kcp-client -l 127.0.0.1:$SSH_FORWARD_PORT -r 127.0.0.1:$KCP_PORT -key $KCP_KEY -crypt aes-128 -mode fast2
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# === START KCP CLIENT ===
systemctl daemon-reload
systemctl enable kcp-client
systemctl start kcp-client

# === CREATE SlowDNS SYSTEMD SERVICE ===
cat > /etc/systemd/system/slowdns.service <<EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
ExecStart=/usr/local/bin/dns-server -udp :$SLOWDNS_PORT -privkey-file /opt/slowdns/private.key -dns 8.8.8.8:53 -forward 127.0.0.1:$SSH_FORWARD_PORT
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable slowdns
systemctl start slowdns

# === ENABLE BBR BOOST ===
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p

# === CREATE MENU SCRIPT ===
cat > /usr/bin/xovnb-menu <<'EOF'
#!/bin/bash
clear
echo "★ XOVNB SlowDNS + KCP Panel ★"
echo ""
echo "1. Create SSH User"
echo "2. Delete SSH User"
echo "3. List SSH Users"
echo "4. Restart Services"
echo "5. Show Connection Info"
echo "6. Exit"
read -p "Select an option: " opt

case $opt in
1)
  read -p "Username: " user
  read -p "Password: " pass
  read -p "Valid (days): " days
  useradd -e $(date -d "$days days" +%Y-%m-%d) -s /bin/false -M $user
  echo "$user:$pass" | chpasswd
  echo "User $user created. Expires in $days days."
  ;;
2)
  read -p "Username to delete: " deluser
  userdel -f $deluser && echo "Deleted $deluser"
  ;;
3)
  echo "=== SSH Users ==="
  awk -F: '$3>=1000&&$3!=65534{ print $1 }' /etc/passwd
  ;;
4)
  systemctl restart slowdns
  systemctl restart kcp-client
  echo "Services restarted."
  ;;
5)
  echo "=== XOVNB Connection Info ==="
  echo "IP Address     : $(curl -s ipv4.icanhazip.com)"
  echo "DNS Port       : $SLOWDNS_PORT"
  echo "KCP Tunnel     : Internal (no client needed)"
  echo "NS Domain      : $NS_DOMAIN"
  echo "Public Key     :"
  cat /opt/slowdns/public.key
  ;;
6) exit ;;
*) echo "Invalid option." ;;
esac
EOF

chmod +x /usr/bin/xovnb-menu

# === DONE ===
echo ""
echo "✅ Installation Complete!"
echo "🔑 Run this command to manage users:"
echo "   xovnb-menu"
echo ""
xovnb-menu
