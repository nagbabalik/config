#!/bin/bash
# SlowDNS + SSH (443) + KCP (ZIVPN) Installer with Static Key
# Author: ChatGPT (Modified to include separate install/menu modes)

# === CONFIG ===
SLOWDNS_DIR="/etc/slowdns"
KCP_DIR="/opt/kcptun"
ZIVPN_PORT=7000
SSH_PORT=443
BANNER_FILE="/etc/issue.net"
PUB_KEY="c22a412517204a0540d00b03d4f8ecd806beb75922d965beb1172f1854763268"
DOMAIN_FILE="/etc/slowdns/domain.conf"

# === MENU FUNCTION ===
menu() {
  if [ ! -f "$DOMAIN_FILE" ]; then
    echo "[!] Configuration file not found. Please run installation first."
    exit 1
  fi

  source "$DOMAIN_FILE"

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
        echo "$PUB_KEY"
        ;;
      5)
        echo -e "\n[+] Server Info"
        echo "Domain: $DOMAIN"
        echo "NS Domain: $NS_DOMAIN"
        echo "SlowDNS Port: 5300"
        echo "SSH Port: $SSH_PORT"
        echo "ZIVPN UDP Port: $ZIVPN_PORT"
        ip -4 addr | grep inet | grep -v 127.0.0.1
        ;;
      6)
        echo -n "New Main Domain: "; read DOMAIN
        echo -n "New NS Domain: "; read NS_DOMAIN
        echo "DOMAIN=\"$DOMAIN\"" > "$DOMAIN_FILE"
        echo "NS_DOMAIN=\"$NS_DOMAIN\"" >> "$DOMAIN_FILE"
        systemctl restart slowdns-server
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

# === ENTRY POINT: MENU MODE ===
if [[ "$1" == "menu" ]]; then
  menu
  exit 0
fi

# === RUN INSTALLATION ===
echo -n "Enter your main domain (e.g. trial.tranz.shop): "; read DOMAIN
echo -n "Enter your NS domain (e.g. ns.trial.tranz.shop): "; read NS_DOMAIN

mkdir -p "$SLOWDNS_DIR"
echo "DOMAIN=\"$DOMAIN\"" > "$DOMAIN_FILE"
echo "NS_DOMAIN=\"$NS_DOMAIN\"" >> "$DOMAIN_FILE"

echo "[+] Updating system and installing dependencies..."
apt update -y && apt upgrade -y
apt install -y curl wget screen sudo dropbear git build-essential golang net-tools dnsutils unzip make cmake libssl-dev iptables cron whois

echo "[+] Installing SlowDNS..."
cd "$SLOWDNS_DIR"
wget -qO sldns-server https://raw.githubusercontent.com/fisabiliyusri/SLDNS/main/slowdns/sldns-server
wget -qO sldns-client https://raw.githubusercontent.com/fisabiliyusri/SLDNS/main/slowdns/sldns-client
chmod +x sldns-server sldns-client
echo "$PUB_KEY" > server.pub

# SSH Config
echo "[+] Configuring SSH on port $SSH_PORT..."
echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
sed -i 's/#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's|#\?Banner.*|Banner /etc/issue.net|' /etc/ssh/sshd_config
echo "Welcome to your private VPN server!" > $BANNER_FILE
systemctl restart ssh || service ssh restart

# SlowDNS Service
cat > /etc/systemd/system/slowdns-server.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
ExecStart=$SLOWDNS_DIR/sldns-server -udp :5300 -pubkey $PUB_KEY $DOMAIN 127.0.0.1:$SSH_PORT
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable slowdns-server
systemctl start slowdns-server

# KCP Setup
echo "[+] Installing KCP..."
mkdir -p "$KCP_DIR"
cd "$KCP_DIR"
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

# Done
echo -e "\n[✓] Installation Complete!"
echo "NS Domain: $NS_DOMAIN"
echo "Main Domain: $DOMAIN"
echo "SlowDNS UDP Port: 5300"
echo "SSH Port (Internal): $SSH_PORT"
echo "ZIVPN UDP Port: $ZIVPN_PORT"
echo "Run './slowdns_zivpn_installer.sh menu' to manage users and settings"
echo "SlowDNS Public Key:"
echo "$PUB_KEY"
