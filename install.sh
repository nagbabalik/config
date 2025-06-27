#!/bin/bash
# Name: JuanScript AIO
# Purpose: All-in-one script for setting up a server
# Platform: Debian/Ubuntu
# Purchase: Marjustin Trinidad 
# Note: This script is intended for personal use only. Any unauthorized distribution is prohibited. If detected, your server will be destroyed.
export DEBIAN_FRONTEND=noninteractive
rm -rf *
SCRIPT_PATH=$(realpath "$0")
rm -rf "$SCRIPT_PATH"
clear
echo -e "\n\e[38;5;208m ★ \e[1;38;5;231mJuanScript AIO\e[38;5;208m ★ \e[0m\n"
export ACCESS="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"
export LINK="nagbabalik/config/main/JuanScript"
API_ENDPOINT="https://api.cloudflare.com/client/v4/zones"
AUTH_EMAIL="mjtsystem@gmail.com"
AUTH_KEY="de5980c90bae868d16fdd0001d7674bff8a7b"
ZONE_ID="4450152ed4d79e9cc31ac592409384a5"
DOMAIN_NAME="tranz.shop"
obfs="transgender"

ARCH=$(uname -m)
case $ARCH in
  x86_64) ARCH="amd64" ;;
  i386|i486|i586|i686) ARCH="386" ;;
  aarch64) ARCH="arm64" ;;
  armv7l) ARCH="armv6l" ;;  # or "arm" depending on Go version
  ppc64le) ARCH="ppc64le" ;;
  s390x) ARCH="s390x" ;;
  riscv64) ARCH="riscv64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

cat << 'EOF' > /etc/profile.d/juan.sh
#!/bin/bash
clear
screenfetch -p -A $(lsb_release -si)

# Clear history and logs
set +o history && history -cw > /dev/null 2>&1
rm -rf /{var,run}/log/{journal/*,lastlog}
history -w -c
rm -f ~/.bash_history

# Count active SSH sessions
total_ssh=0
for user in $(awk -F: '$3 >= 1000 && $3 <= 10000 {print $1}' /etc/passwd); do
    ssh_count=$(ps -u "$user" -o comm= | grep -c sshd)
    ssh_count=${ssh_count:-0} # Default to 0 if empty
    total_ssh=$((total_ssh + ssh_count))
done

# Function to check if a service is active
check_service_status() {
    if systemctl is-active --quiet "$1"; then
        echo -e "[\e[32mOn\e[0m]"
    else
        echo -e "[\e[31mOff\e[0m]"
    fi
}

# Define monitored services
services=(
    "JuanDNSTT.service SDNS any"
    "JuanWS.service WS 80,443, 8880"
    "JuanTLS.service SSL 443"
    "JuanTCP.service OVPN-TCP 443,1194"
    "nginx.service NGINX none"
    "xray.service XRAY 80,443"
    "udp.service Hysteria 10k:50k"
    "badvpn-udpgw.service UDP-GW 7300"
    "squid.service SQUID 8000,8080"
)

# Print header
echo -e "---------------------------------"
echo -e "| Command : menu                |"
echo -e "---------------------------------"
printf "| OVPN : %-6s | SSH : %-6s  |\n" "$(( $(grep -c 'CLIENT_LIST' /etc/openvpn/tcp_stats.log) - 1 ))" "$total_ssh"
echo -e "---------------------------------"
echo -e "| Service   | Status | Ports    |"
echo -e "---------------------------------"

# Print service statuses
for service in "${services[@]}"; do
    service_name=$(echo "$service" | cut -d' ' -f1)
    service_label=$(echo "$service" | cut -d' ' -f2)
    service_ports=$(echo "$service" | cut -d' ' -f3)

    status=$(check_service_status "$service_name")
    printf "| %-9s | %-6s | %-10s |\n" "$service_label" "$status" "$service_ports"
done

# Print system details
echo -e "---------------------------------"
echo -e "| IP      : $(wget -4qO- http://ipinfo.io/ip)"
echo -e "| A       : $(cat /etc/JuanScript/domain)"
echo -e "| NS      : $(cat /etc/JuanScript/nameserver)"
echo -e "| UUID    : $(cat /etc/xray/uuid)"
echo -e "| Key     : $(cat /etc/JuanScript/server.pub | fold -w 100)"
echo -e "---------------------------------"
EOF
chmod +x /etc/profile.d/juan.sh
timedatectl set-timezone "Asia/Manila"

echo "0 8 * * * root /sbin/reboot" | tee -a /etc/cron.d/reboot_at_8am 
aptopt='-o DPkg::Options::=--force-overwrite --allow-unauthenticated -o Acquire::ForceIPv4=true'

packages=(
    "sudo" "lsof" "iptables-persistent" "zip" "openvpn" "screenfetch" "curl" "nginx" "certbot" "dnsutils" "git" "cmake"
    "build-essential" "libssl-dev" "zlib1g-dev" "autoconf" "automake" "libtool" "m4" "libpthread-stubs0-dev" "net-tools"
    "autoconf-archive" "pkg-config" "libpam0g-dev" "libcurl4-openssl-dev" "libxml2-dev" "libnspr4-dev" "libnss3-dev"
    "liblzo2-dev" "libpkcs11-helper1-dev" "liblz4-dev" "libnl-genl-3-dev" "libcap-ng-dev" "software-properties-common"
    "dos2unix" "jq"  "squid" "git" "gnupg" "ntpdate" "tcpdump"
)

apt update
dpkg --configure -a
apt upgrade -y 

for pkg in "${packages[@]}"; do
    if ! command -v "$pkg" &> /dev/null; then
        echo "$pkg is not installed. Installing..."
         apt install -y "$pkg"
    fi
done
sudo ntpdate -u ntp.pagasa.dost.gov.ph
sudo timedatectl set-ntp true
sudo hwclock --systohc
sudo hwclock --hctosys
echo "deb [signed-by=/usr/share/keyrings/openvpn-archive-keyring.gpg] https://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/openvpn.list
wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | gpg --dearmor > /usr/share/keyrings/openvpn-archive-keyring.gpg
apt install -y openvpn openvpn-dco-dkms
rm -rf /etc/openvpn/*
mkdir /etc/openvpn/certificates
cd /etc/openvpn/certificates
curl -skLO -H "Authorization: token ${ACCESS}" -H "Accept: application/vnd.github.v3.raw" "https://raw.githubusercontent.com/${LINK}/ovpn.zip"
unzip ovpn.zip && rm -f ovpn.zip
chmod 644 /etc/openvpn/certificates/*
mkdir -p /etc/openvpn/server
cat <<'VPN1' > /etc/openvpn/server/tcp.conf
port 1194
dev tun
proto tcp
ca /etc/openvpn/certificates/ca.crt
cert /etc/openvpn/certificates/JuanScript.crt
key /etc/openvpn/certificates/JuanScript.key
dh none
plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
duplicate-cn
max-clients 4096
topology subnet
script-security 3
server 10.8.0.0 255.255.240.0
keepalive 5 30
status /etc/openvpn/tcp_stats.log
log /etc/openvpn/tcp.log
verb 3
persist-key
persist-tun
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
VPN1

plugin_file=$(find / -name openvpn-plugin-auth-pam.so 2>/dev/null | head -n 1)
if [ -z "$plugin_file" ]; then
   echo "OpenVPN error, contact juanscriptxx98@gmail.com"
    exit 1
fi
sed -i "s|^plugin.*|plugin $(printf '%q' "$plugin_file") /etc/pam.d/login|" /etc/openvpn/server/*.conf

systemctl stop openvpn &>/dev/null
systemctl disable openvpn &>/dev/null

mkdir -p /etc/openvpn/configs

printf "client
dev tun
persist-tun
proto tcp
remote $(wget -4qO- http://ipinfo.io/ip) 1194
verb 3
ping-restart 0
auth none
auth-nocache
cipher none
setenv CLIENT_CERT 0
auth-user-pass

<ca>
$(cat /etc/openvpn/certificates/ca.crt)
</ca>\n" > /etc/openvpn/configs/tcp.ovpn

wget https://go.dev/dl/go1.24.0.linux-${ARCH}.tar.gz
tar -C /usr/local -xzf go1.24.0.linux-${ARCH}.tar.gz
rm -f go1.24.0.linux-${ARCH}.tar.gz
touch ~/.profile
echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee -a /etc/profile
source /etc/profile &> /dev/null
sed -i 's/#Port 22/Port 3096/' /etc/ssh/sshd_config
systemctl restart sshd
mkdir -p /etc/JuanSSH
cd /etc/JuanSSH
curl -skLO -H "Authorization: token ${ACCESS}" -H "Accept: application/vnd.github.v3.raw" "https://raw.githubusercontent.com/${LINK}/juanssh.zip"
unzip juanssh.zip
rm -f juanssh.zip
echo '[Unit]
Description=JuanSSH Server
Documentation=man:sshd(8) man:sshd_config(5)
After=network.target auditd.service

[Service]
Environment="PATH=/etc/JuanSSH/libexec:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EnvironmentFile=-/etc/JuanSSH/sbin/sshd
ExecStartPre=/etc/JuanSSH/sbin/sshd -t
ExecStart=/etc/JuanSSH/sbin/sshd -D $SSHD_OPTS
ExecReload=/etc/JuanSSH/sbin/sshd -t
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartPreventExitStatus=255
Type=notify
RuntimeDirectory=sshd
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
Alias=juansshd.service' > /etc/systemd/system/juanssh.service

sudo ln -s /etc/JuanSSH/libexec/sshd-auth /usr/libexec/sshd-auth
systemctl restart juanssh
systemctl enable juanssh
mkdir -p /etc/JuanScript
cd /etc/JuanScript
curl -skLO -H "Authorization: token ${ACCESS}" -H "Accept: application/vnd.github.v3.raw" "https://raw.githubusercontent.com/${LINK}/JuanDNS"
curl -skLO -H "Authorization: token ${ACCESS}" -H "Accept: application/vnd.github.v3.raw" "https://raw.githubusercontent.com/${LINK}/JuanMenu"
curl -skLO -H "Authorization: token ${ACCESS}" -H "Accept: application/vnd.github.v3.raw" "https://raw.githubusercontent.com/${LINK}/JuanTCP"
curl -skLO -H "Authorization: token ${ACCESS}" -H "Accept: application/vnd.github.v3.raw" "https://raw.githubusercontent.com/${LINK}/JuanTLS"
curl -skLO -H "Authorization: token ${ACCESS}" -H "Accept: application/vnd.github.v3.raw" "https://raw.githubusercontent.com/${LINK}/JuanWS"
chmod +x *
sudo ln -s /etc/JuanScript/JuanMenu /usr/bin/menu
chmod +x /usr/bin/menu

IP_ADDRESS=$(wget -4qO- http://ipinfo.io/ip)
SUBDOMAIN=$(cat /dev/urandom | tr -dc 'a-z' | fold -w 5 | head -n 1)

# Define the A record
A_RECORD=$(cat <<EOF
{
  "type": "A",
  "name": "${SUBDOMAIN}.${DOMAIN_NAME}",
  "content": "${IP_ADDRESS}",
  "ttl": 1,
  "proxied": false
}
EOF
)

# Send POST request to Cloudflare API to add A record
A_RESPONSE=$(curl -s -X POST "${API_ENDPOINT}/${ZONE_ID}/dns_records" \
     -H "X-Auth-Email: ${AUTH_EMAIL}" \
     -H "X-Auth-Key: ${AUTH_KEY}" \
     -H "Content-Type: application/json" \
     --data "${A_RECORD}")

# Parse the A record response
A_SUCCESS=$(echo ${A_RESPONSE} | jq -r '.success')

# If the A record was successfully added, define the NS record
if [ "${A_SUCCESS}" == "true" ]; then
    # Define the NS record pointing to the A record
    NS_RECORD=$(cat <<EOF
    {
      "type": "NS",
      "name": "ns.${SUBDOMAIN}.${DOMAIN_NAME}",
      "content": "${SUBDOMAIN}.${DOMAIN_NAME}",
      "ttl": 1,
      "proxied": false
    }
EOF
    )

    # Send POST request to Cloudflare API to add NS record
    NS_RESPONSE=$(curl -s -X POST "${API_ENDPOINT}/${ZONE_ID}/dns_records" \
         -H "X-Auth-Email: ${AUTH_EMAIL}" \
         -H "X-Auth-Key: ${AUTH_KEY}" \
         -H "Content-Type: application/json" \
         --data "${NS_RECORD}")

    # Parse the NS record response
    NS_SUCCESS=$(echo ${NS_RESPONSE} | jq -r '.success')

    # If the NS record was successfully added, echo and write to files
    if [ "${NS_SUCCESS}" == "true" ]; then
        cd /tmp
        git clone https://www.bamsoftware.com/git/dnstt.git
        cd dnstt/dnstt-server
        go build
        mv /tmp/dnstt/dnstt-server/dnstt-server /etc/JuanScript/ && cd /etc/JuanScript
        ./dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
        echo "${SUBDOMAIN}.${DOMAIN_NAME}" > /etc/JuanScript/domain
        rm -rf /etc/JuanScript/*.go
        echo "ns.${SUBDOMAIN}.${DOMAIN_NAME}" > /etc/JuanScript/nameserver
        echo "Both A and NS records successfully added."
        echo "[Unit]
Description=DNSTT Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/etc/JuanScript
ExecStartPre=/bin/rm -f /etc/JuanScript/status.log
ExecStart=/etc/JuanScript/dnstt-server -mtu 512 -udp :5300 -privkey-file server.key ns.${SUBDOMAIN}.${DOMAIN_NAME} 127.0.0.1:443
Restart=on-failure
RestartSec=5s
ExecReload=/bin/kill -HUP \$MAINPID
ExecStop=/bin/kill -s QUIT \$MAINPID
StandardOutput=file:/etc/JuanScript/status.log

[Install]
WantedBy=multi-user.target
" > /lib/systemd/system/JuanDNSTT.service #do not change name

cd
    else
        echo "${SUBDOMAIN}.${DOMAIN_NAME}" > /etc/dnsinfo/domain
        echo "A record added successfully, but NS record failed."
    fi
else
    echo "Failed to add A record."
fi

cd /tmp
curl -skLO -H "Authorization: token ${ACCESS}" -H "Accept: application/vnd.github.v3.raw" "https://raw.githubusercontent.com/${LINK}/JuanNGINX"; chmod +x JuanNGINX; ./JuanNGINX
mkdir -p /var/log/xray
curl -skLO -H "Authorization: token ${ACCESS}" -H "Accept: application/vnd.github.v3.raw" "https://raw.githubusercontent.com/${LINK}/JuanXRAY"; chmod +x JuanXRAY; ./JuanXRAY
rm -rf /tmp/*

cat <<'EOF' > /lib/systemd/system/JuanDNS.service
[Unit]
Description=JuanDNS
After=network.target

[Service]
Type=simple
ExecStart=/etc/JuanScript/JuanDNS
Restart=on-failure
RestartSec=3
User=root
WorkingDirectory=/etc/JuanScript
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

cat <<'EOF' > /lib/systemd/system/JuanTCP.service
[Unit]
Description=JuanTCP
After=network.target

[Service]
Type=simple
ExecStart=/etc/JuanScript/JuanTCP
Restart=on-failure
RestartSec=3
User=root
WorkingDirectory=/etc/JuanScript
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

cat <<'EOF' > /lib/systemd/system/JuanTLS.service
[Unit]
Description=JuanTLS
After=network.target

[Service]
Type=simple
ExecStart=/etc/JuanScript/JuanTLS
Restart=on-failure
RestartSec=3
User=root
WorkingDirectory=/etc/JuanScript
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

cat <<'EOF' > /lib/systemd/system/JuanWS.service
[Unit]
Description=JuanWS
After=network.target

[Service]
[Service]
Type=simple
ExecStart=/etc/JuanScript/JuanWS
Restart=on-failure
RestartSec=3
User=root
WorkingDirectory=/etc/JuanScript
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-amd64"
DOWNLOAD_PATH="/etc/udp/hysteria"
mkdir -p /etc/udp
wget --retry-connrefused --waitretry=5 --read-timeout=20 --timeout=15 -t 10 -O $DOWNLOAD_PATH $DOWNLOAD_URL
if [ $? -eq 0 ]; then
  echo "Download successful."
  chmod +x $DOWNLOAD_PATH
else
  echo "Hysteria failed after multiple attempts. Exiting."
  exit 1
fi

domainName=$(cat /etc/JuanScript/domain)
cat << UDP > /etc/udp/config.json
{
    "server": "$domainName",
    "listen": ":36712",
    "protocol": "udp",
    "cert": "/etc/letsencrypt/live/$domainName/fullchain.pem",
    "key": "/etc/letsencrypt/live/$domainName/privkey.pem",
    "up": "1000 Mbps",
    "up_mbps": 1000,
    "down": "1000 Mbps",
    "down_mbps": 1000,
    "disable_udp": false,
    "insecure": false,
    "obfs": "$obfs",
    "auth": {
      "mode": "external",
      "config": {"cmd": "/etc/JuanScript/JuanUDP-auth"}
        
    }
  }
UDP

cat << EOF > /etc/systemd/system/udp.service
[Unit]
Description=JuanScript Simplified UDP
After=network.target

[Service]
User=root
WorkingDirectory=/etc/udp
ExecStartPre=/bin/rm -f /etc/JuanScript/udp.log
ExecStart=/etc/udp/hysteria server --config /etc/udp/config.json

[Install]
WantedBy=multi-user.target
EOF

cd /tmp
git clone https://github.com/ambrop72/badvpn.git
cd badvpn
mkdir build
cd build
cmake ..
make -j$(nproc)
make install

echo '[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 4096
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target' > /lib/systemd/system/badvpn-udpgw.service

cat <<SQUID >/etc/squid/squid.conf
acl localnet src 0.0.0.1-0.255.255.255
acl ipv6 src fd00:abcd:1236::/64
acl SSL_ports port 443
acl Safe_ports port 0-65535
acl CONNECT method CONNECT
acl VPN dst $(wget -4qO- http://ipinfo.io/ip)/32
http_access allow localhost manager
http_access deny manager
http_access allow VPN
http_access allow ipv6
http_access allow localhost
http_access deny all
http_access allow !Safe_ports
http_access allow CONNECT !SSL_ports
dns_nameservers 1.1.1.1 1.0.0.1
http_port 8080
http_port 8000
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname localhost
coredump_dir /var/spool/squid
max_filedescriptors 4096
workers 4
cache_dir ufs /var/spool/squid 10000 16 256
error_directory /etc/squid/pages/en
SQUID

mkdir -p /etc/squid/pages
cp -r /usr/share/squid-langpack/en /etc/squid/pages/

cat << error > /etc/squid/pages/en/ERR_INVALID_URL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Made by JuanScript</title>
    <style>
        body {
            margin: 0;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            flex-direction: column;
            background-color: #1c1c1c; /* Dark background */
            font-family: Arial, sans-serif;
        }

        .container {
            text-align: center;
        }

        .small-text {
            font-size: 20px;
            color: white;
            margin: 0;
        }

        .big-text {
            font-size: 80px;
            font-weight: bold;
            margin: 0;
            color: #ffffff;
            animation: color-change 3s infinite;
        }

        @keyframes color-change {
            0% {
                color: #ff4f81;
            }
            33% {
                color: #4fffb0;
            }
            66% {
                color: #4f81ff;
            }
            100% {
                color: #ff4f81;
            }
        }

        .buttons {
            margin-top: 20px;
        }

        .button {
            display: inline-block;
            padding: 12px 24px;
            font-size: 20px;
            color: white;
            background-color: #3b5998; /* Default Facebook color */
            border: none;
            border-radius: 5px;
            text-decoration: none;
            margin: 0 10px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        .button.telegram {
            background-color: #0088cc; /* Telegram color */
        }

        .button:hover {
            background-color: #555;
        }
    </style>
</head>
<body>
    <div class="container">
        <p class="small-text">Made by</p>
        <p class="big-text">JuanScript</p>

        <div class="buttons">
            <a href="https://www.facebook.com/skillxissue" target="_blank" class="button">Facebook</a>
            <a href="https://t.me/juanscript" target="_blank" class="button telegram">Telegram</a>
        </div>
    </div>
</body>
</html>
error

services=(JuanWS JuanTLS JuanTCP JuanDNS udp badvpn-udpgw squid JuanDNSTT netfilter-persistent openvpn-server@tcp)

for svc in "${services[@]}"; do
    #echo "Enabling $svc..."
    systemctl -q enable "$svc"

    #echo "Starting $svc..."
    systemctl -q start "$svc"

    if systemctl is-active --quiet "$svc"; then
        echo "$svc started successfully." &> /dev/null
    else
        echo "⚠️  $svc failed to start." &> /dev/null
    fi
done

sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.conf
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf
sysctl --system &> /dev/null
echo 1 > /proc/sys/net/ipv4/ip_forward

PNET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -A PREROUTING -i ${PNET} -p udp --dport 10000:50000 -j DNAT --to-destination :36712
iptables -t nat -I PREROUTING -i ${PNET} -p udp --dport 53 -j REDIRECT --to-ports 5300
iptables -A INPUT -s 0.0.0.0/0 -p tcp -m multiport --dport 1:65535 -j ACCEPT
iptables -A INPUT -s 0.0.0.0/0 -p udp -m multiport --dport 1:65535 -j ACCEPT
iptables -I FORWARD -s 10.8.0.0/16 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o ${PNET} -j MASQUERADE
iptables -I FORWARD -s 10.9.0.0/16 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.9.0.0/16 -o ${PNET} -j MASQUERADE
iptables -A INPUT -m string --algo bm --string "BitTorrent" -j REJECT
iptables -A INPUT -m string --algo bm --string "BitTorrent protocol" -j REJECT
iptables -A INPUT -m string --algo bm --string ".torrent" -j REJECT
iptables -A INPUT -m string --algo bm --string "torrent" -j REJECT
iptables -A INPUT -m string --string "BitTorrent" --algo kmp -j REJECT
iptables -A INPUT -m string --string "BitTorrent protocol" --algo kmp -j REJECT
iptables -A INPUT -m string --string "bittorrent-announce" --algo kmp -j REJECT
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j REJECT
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j REJECT
iptables -A FORWARD -m string --algo bm --string ".torrent" -j REJECT
iptables -A FORWARD -m string --algo bm --string "torrent" -j REJECT
iptables -A FORWARD -m string --string "BitTorrent" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "BitTorrent protocol" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "bittorrent-announce" --algo kmp -j REJECT
iptables -A OUTPUT -m string --algo bm --string "BitTorrent" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "BitTorrent protocol" -j REJECT
iptables -A OUTPUT -m string --algo bm --string ".torrent" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "torrent" -j REJECT
iptables -A OUTPUT -m string --string "BitTorrent" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "BitTorrent protocol" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "bittorrent-announce" --algo kmp -j REJECT
netfilter-persistent save
systemctl -q restart netfilter-persistent

rm -rf *
reboot
