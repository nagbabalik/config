# SlowDNS Manager + Web Panel
## Usage
1. Edit `config.conf` with your own server, domain, SSH credentials.
2. Make the script executable:
   ```bash
   chmod +x slowdns-manager.sh
   ./slowdns-manager.sh
   ```
3. To run the web panel:
   ```bash
   pip install -r requirements.txt
   python3 webpanel.py
   ```
Visit `http://127.0.0.1:8080` to control the client from browser.
