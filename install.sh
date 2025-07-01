#!/bin/bash
set -e

# === CONFIGURATION ===
DNS_SERVER="123.45.67.89"          # Your SlowDNS server IP
DNS_DOMAIN="your.dns.server.com"   # Your SlowDNS domain
SLOWDNS_PORT=4443                  # Non-root port (change if needed)
SSH_USER="youruser"                # VPS SSH username
SSH_PASSWORD="yourpassword"        # VPS SSH password (plaintext)

# === Choose SSH cipher (edit here) ===
# Options: aes128-ctr (secure), arcfour (faster, less secure), chacha20-poly1305@openssh.com (modern & fast)
SSH_CIPHER="arcfour"

# === Install dependencies ===
echo "[*] Installing required packages..."
if command -v pkg &>/dev/null; then
  pkg update -y
  pkg install -y openssh sshpass
else
  sudo apt update -y
  sudo apt install -y openssh-client sshpass
fi

# === Check slowdns-client binary ===
if [ ! -f ./slowdns-client ]; then
  echo "[!] ERROR: slowdns-client binary NOT found in current directory."
  echo "Please download it and place it here, then re-run the script."
  exit 1
fi
chmod +x ./slowdns-client

echo "[*] Starting SlowDNS client..."
./slowdns-client \
  -udp 53 \
  -dns "$DNS_DOMAIN" \
  -client \
  -server "$DNS_SERVER" \
  -listen 127.0.0.1:$SLOWDNS_PORT &

sleep 5

echo "[*] Connecting to SSH on localhost:$SLOWDNS_PORT with cipher $SSH_CIPHER..."

sshpass -p "$SSH_PASSWORD" ssh -C \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o TCPKeepAlive=no \
  -o ServerAliveInterval=30 \
  -o CompressionLevel=9 \
  -c "$SSH_CIPHER" \
  -p "$SLOWDNS_PORT" \
  "$SSH_USER@127.0.0.1"
