#!/bin/bash
# Auto-Installer: SlowDNS + SSH (443) + ZIVPN KCP Tunnel Boost

# === Prompt Domain Config ===
echo -n "Enter your main domain (e.g. trial.tranz.shop): "; read DOMAIN
echo -n "Enter your NS domain (e.g. ns.trial.tranz.shop): "; read NS_DOMAIN

# === System Prep ===
echo "[+] Updating system..."
apt update -y && apt upgrade -y
apt install -y curl wget screen sudo dropbear git build-essential golang net-tools dnsutils unzip make cmake libssl-dev iptables cron whois

# === Variables ===
SLOWDNS_DIR="/etc/slowdns"
KCP_DIR="/opt/kcptun"
ZIVPN_PORT=7000
SSH_PORT=443
BANNER_FILE="/etc/issue.net"

# === Create SlowDNS Keypair ===
echo "[+] Setting up SlowDNS..."
rm -rf $SLOWDNS_DIR && mkdir -p $SLOWDNS_DIR
cd $SLOWDNS_DIR
wget -qO sldns https://raw.githubusercontent.com/fisabiliyusri/SLDNS/main/slowdns/sldns-server
chmod +x sldns

# Generate keys safely
if ./sldns keygen -privkey-file server.key -pubkey-file server.pub; then
  echo "[+] SlowDNS keys generated."
else
  echo "[!] Failed to generate SlowDNS keys. Exiting."
  exit 1
fi

# === Install SlowDNS Server Binary ===
wget -qO sldns-server https://raw.githubusercontent.com/fisabiliyusri/SLDNS/main/slowdns/sldns-server
wget -qO sldns-client https://raw.githubusercontent.com/fisabiliyusri/SLDNS/main/slowdns/sldns-client
chmod +x sldns-server sldns-client

# === SSH Server on Port 443 ===
echo "[+] Configuring SSH on port $SSH_PORT..."
echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
sed -i 's/#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's|#\?Banner.*|Banner /etc/issue.net|' /etc/ssh/sshd_config
systemctl restart ssh || service ssh restart
echo "Welcome to your private VPN server!" > $BANNER_FILE

# === SlowDNS Systemd Service ===
cat > /etc/systemd/system/slowdns-server.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
ExecStart=$SLOWDNS_DIR/sldns-server -udp :5300 -privkey-file $SLOWDNS_DIR/server.key $DOMAIN 127.0.0.1:$SSH_PORT
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable slowdns-server
systemctl start slowdns-server

# === ZIVPN / KCP Boost Setup ===
echo "[+] Installing KCP server (ZIVPN-style)..."
mkdir -p $KCP_DIR && cd $KCP_DIR
wget -qO kcptun.tar.gz https://github.com/xtaci/kcptun/releases/download/v20240315/kcptun-linux-amd64-20240315.tar.gz
tar -xzf kcptun.tar.gz && mv server_linux_amd64 kcp-server
chmod +x kcp-server

cat > /etc/systemd/system/kcp-server.service << EOF
[Unit]
Description=ZIVPN/KCP Tunnel Server
After=network.target

[Service]
ExecStart=$KCP_DIR/kcp-server -t 127.0.0.1:$SSH_PORT -l :$ZIVPN_PORT -mode fast2 -nocomp -key zivpnboost
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable kcp-server
systemctl start kcp-server

# === Menu System ===
menu() {
  while true; do
    clear
    echo "========================="
    echo "   SlowDNS + ZIVPN Menu"
    echo "========================="
    echo "1. Add SSH User"
    echo "2. Extend SSH User"
    echo "3. Set SSH Banner Message"
    echo "4. Show SlowDNS Public Key"
    echo "5. Show Server Info"
    echo "6. Edit Domain/NS Settings"
    echo "7. Uninstall All"
    echo "0. Exit"
    echo -n "Select: "; read opt
    case $opt in
      1)
        echo -n "Username: "; read uname
        echo -n "Password: "; read upass
        echo -n "Expire (days): "; read udays
        useradd -e $(date -d "$udays days" +%Y-%m-%d) -s /bin/false -M $uname
        echo "$uname:$upass" | chpasswd
        echo "User $uname added. Expire: $udays days"
        ;;
      2)
        echo -n "Extend which user: "; read uname
        echo -n "Add how many days?: "; read extend
        current_expiry=$(chage -l $uname | grep "Account expires" | cut -d: -f2 | sed 's/^ *//')
        new_date=$(date -d "$current_expiry +$extend days" +%Y-%m-%d)
        usermod -e $new_date $uname
        echo "User $uname extended until $new_date"
        ;;
      3)
        echo -n "Enter banner message: "; read banner
        echo "$banner" > $BANNER_FILE
        systemctl restart ssh
        echo "Banner updated."
        ;;
      4)
        echo -e "\n[+] SlowDNS Public Key:"
        cat $SLOWDNS_DIR/server.pub
        ;;
      5)
        echo -e "\n[+] Server Info"
        echo "Domain: $DOMAIN"
        echo "NS Domain: $NS_DOMAIN"
        echo "SlowDNS Port: 5300"
        echo "SSH Port: $SSH_PORT"
        echo "ZIVPN UDP Port: $ZIVPN_PORT"
        ip -4 addr show | grep inet | grep -v 127.0.0.1
        ;;
      6)
        echo -n "New Main Domain: "; read DOMAIN
        echo -n "New NS Domain: "; read NS_DOMAIN
        echo "Domain settings updated."
        ;;
      7)
        echo "Uninstalling services..."
        systemctl stop slowdns-server kcp-server
        systemctl disable slowdns-server kcp-server
        rm -f /etc/systemd/system/slowdns-server.service /etc/systemd/system/kcp-server.service
        systemctl daemon-reload
        rm -rf $SLOWDNS_DIR $KCP_DIR
        echo "SlowDNS and KCP server removed."
        ;;
      0)
        exit 0
        ;;
      *)
        echo "Invalid option"
        ;;
    esac
    echo -e "\nPress Enter to return to menu..."; read
  done
}

# === Menu Launch Condition ===
if [[ "$1" == "menu" ]]; then
  menu
fi

# === Done Message ===
echo -e "\n[✓] Installation Complete!"
echo "NS Domain: $NS_DOMAIN"
echo "Main Domain: $DOMAIN"
echo "SlowDNS UDP Port: 5300"
echo "SSH Port (Internal): $SSH_PORT"
echo "ZIVPN UDP Port: $ZIVPN_PORT"
echo "Run './install.sh menu' to manage users and settings"
echo "SlowDNS Public Key:"
cat $SLOWDNS_DIR/server.pub
