from flask import Flask, redirect, url_for
import os, subprocess

app = Flask(__name__)

CONFIG_FILE = "./config.conf"
def load_config():
    config = {}
    with open(CONFIG_FILE) as f:
        for line in f:
            if '=' in line and not line.strip().startswith('#'):
                k, v = line.strip().split('=', 1)
                config[k] = v
    return config

@app.route('/')
def home():
    status = "Running" if os.path.exists("slowdns.pid") else "Stopped"
    return f"""
        <h2>SlowDNS Web Panel</h2>
        <p>Status: <b>{status}</b></p>
        <a href='/start'>Start</a> |
        <a href='/stop'>Stop</a> |
        <a href='/ssh'>SSH Connect</a>
    ""

@app.route('/start')
def start():
    cfg = load_config()
    subprocess.Popen(["./slowdns-client", "-udp", "53", "-dns", cfg["DNS_DOMAIN"], "-client", "-server", cfg["DNS_SERVER"], "-listen", f"127.0.0.1:{cfg["SLOWDNS_PORT"]}"])
    return redirect(url_for('home'))

@app.route('/stop')
def stop():
    if os.path.exists("slowdns.pid"):
        with open("slowdns.pid") as f:
            pid = f.read().strip()
        subprocess.run(["kill", "-9", pid])
        os.remove("slowdns.pid")
    return redirect(url_for('home'))

@app.route('/ssh')
def ssh():
    cfg = load_config()
    subprocess.Popen(["sshpass", "-p", cfg["SSH_PASSWORD"],
                      "ssh", "-C", "-o", "StrictHostKeyChecking=no",
                      "-o", "UserKnownHostsFile=/dev/null",
                      "-o", "TCPKeepAlive=no", "-o", "ServerAliveInterval=30",
                      "-o", "CompressionLevel=9", "-c", cfg["SSH_CIPHER"],
                      "-p", cfg["SLOWDNS_PORT"], f"{cfg["SSH_USER"]}@127.0.0.1"])
    return redirect(url_for('home'))
