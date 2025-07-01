#!/bin/bash
set -e

CONFIG_FILE="./config.conf"
source "$CONFIG_FILE"

function start_slowdns() {
    echo "[*] Starting SlowDNS client..."
    ./slowdns-client -udp 53 -dns "$DNS_DOMAIN" -client -server "$DNS_SERVER" -listen 127.0.0.1:$SLOWDNS_PORT &
    echo $! > slowdns.pid
}

function stop_slowdns() {
    if [ -f slowdns.pid ]; then
        kill -9 $(cat slowdns.pid) && rm -f slowdns.pid
        echo "[*] SlowDNS client stopped."
    else
        echo "[!] SlowDNS client not running."
    fi
}

function ssh_connect() {
    sshpass -p "$SSH_PASSWORD" ssh -C -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o TCPKeepAlive=no -o ServerAliveInterval=30 -o CompressionLevel=9 -c "$SSH_CIPHER" -p "$SLOWDNS_PORT" "$SSH_USER@127.0.0.1"
}

function check_status() {
    if [ -f slowdns.pid ] && ps -p $(cat slowdns.pid) > /dev/null; then
        echo "[*] SlowDNS is running with PID $(cat slowdns.pid)."
    else
        echo "[!] SlowDNS is not running."
    fi
}

while true; do
    clear
    echo "=== SlowDNS Manager ==="
    echo "1. Start SlowDNS Client"
    echo "2. Stop SlowDNS Client"
    echo "3. SSH Connect"
    echo "4. Status"
    echo "5. Exit"
    read -p "Choose an option: " opt
    case $opt in
        1) start_slowdns ;;
        2) stop_slowdns ;;
        3) ssh_connect ;;
        4) check_status ;;
        5) exit 0 ;;
        *) echo "Invalid option." ; sleep 1 ;;
    esac
done
