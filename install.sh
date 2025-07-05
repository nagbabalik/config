#!/bin/bash
# Clean SlowDNS + KCP Installer (no compile, works with prebuilt binary)

DOMAIN="xovnb.tranz.shop"
NS="ns.xovnb.tranz.shop"
KCP_PORT="4000"
DNS_PORT="5300"
KCP_KEY="gtmkcp2025"
SLOWDNS_DIR="/opt/slowdns"

echo "✅ Checking network..."
ping -c 1 google.com &>/dev/null || {
    echo "❌ Internet not working. Fix DNS first (e.g. echo 'nameserver 8.8.8.8' > /etc/resolv.conf)"
    exit 1
}

echo "📦 Installing dependencies..."
apt update && apt install -y wget curl unzip iptables screen net-tools sudo

echo "📁 Setting up folders..."
mkdir -p $SLOWDNS_DIR && cd $SLOWDNS_DIR

echo "⬇️ Downloading prebuilt dns-server binary..."
wget -qO dns-server https://github.com/fisabiliyusri/Mantap/raw/main/slowdns/dns-server
chmod +x dns-server
mv dns-server /usr/local/bin/

echo "🔐 Generating SlowDNS keys..."
/usr/local/bin/dns-server -gen-key -privkey-file $SLOWDNS_DIR/private.key -pubkey-file $SLOWDNS_DIR/public.key

echo "⬇️ Downloading KCPtun..."
mkdir -p /opt/kcptun && cd /opt/kcptun
wget https://github.com/xtaci/kcptun/releases/download/v20240315/kcptun-linux-amd64-20240315.tar.gz
tar -xzf kcptun-linux-amd64-*.tar.gz
mv server_linux_amd64 /usr/local/bin/kcp-server
mv client_linux_amd64 /usr/local/bin/kcp-client
chmod +x /usr/local/bin/kcp-*

echo "⚙️ Creating KCP client service..."
cat > /etc/systemd/system/kcp-client.service <<EOF
[Unit]
Description=KCP Client
After=network.target

[Service]
ExecStart=/usr/local/bin/kcp-client -l 127.0.0.1:2222 -r 127.0.0.1:$KCP_PORT -key $KCP_KEY -crypt aes-128 -mode fast2
Restart=always

[Install]
WantedBy=multi-user.target
EOF

echo "⚙️ Creating SlowDNS service..."
cat > /etc/systemd/system/slowdns.service <<EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
ExecStart=/usr/local/bin/dns-server -udp :$DNS_PORT -privkey-file $SLOWDNS_DIR/private.key -dns 1.1.1.1:53 -forward 127.0.0.1:2222
Restart=always

[Install]
WantedBy=multi-user.target
EOF

echo "🚀 Enabling services..."
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable kcp-client
systemctl enable slowdns
systemctl restart kcp-client
systemctl restart slowdns

echo "🔧 Enabling BBR TCP boost..."
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p

echo "🧰 Installing SSH user menu..."
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
read -p "Select option: " opt

case $opt in
1)
  read -p "Username: " user
  read -p "Password: " pass
  read -p "Valid days: " days
  useradd -e $(date -d "$days days" +%Y-%m-%d) -s /bin/false -M $user
  echo "$user:$pass" | chpasswd
  echo "✅ User $user created, valid $days days."
  ;;
2)
  read -p "Username to delete: " u
  userdel -f $u && echo "✅ Deleted user $u"
  ;;
3)
  echo "=== Users ==="
  awk -F: '$3>=1000&&$3!=65534{print $1}' /etc/passwd
  ;;
4)
  systemctl restart slowdns
  systemctl restart kcp-client
  echo "✅ Services restarted."
  ;;
5)
  echo "🔑 XOVNB Connection Info"
  echo "IP Address : $(curl -s ipv4.icanhazip.com)"
  echo "DNS Port   : 5300"
  echo "KCP Tunnel : Internal (auto-routed)"
  echo "NS Domain  : ns.xovnb.tranz.shop"
  echo "Public Key:"
  cat /opt/slowdns/public.key
  ;;
6) exit ;;
*) echo "❌ Invalid option." ;;
esac
EOF

chmod +x /usr/bin/xovnb-menu

echo ""
echo "✅ Done!"
echo "📌 Use this command to manage users:"
echo ""
echo "   xovnb-menu"
echo ""
