# Linux SystemScan

Infrastructure monitoring tool for Proxmox-based homelabs. Scans the local network, Proxmox hosts, VMs, LXC containers, Docker services, web servers, and databases — all results stored in MariaDB and displayed in a dark-themed web UI.

**Live at:** `http://192.168.178.89/linux_systemscan/`

---

## Features

### Infrastructure Scanning
- **Proxmox API** — hosts, VMs, LXC containers, storage pools, network interfaces
- **Docker** — scans all Proxmox guests and localhost via SSH
- **Home Assistant** — add-ons and system components via REST API
- **Network (nmap)** — full LAN host discovery with category, description, MAC, vendor

### Service & Web Scanning
- **Web-Interface Detection** — HTTP GET on all discovered web ports; collects page title, HTTP status, Server header, response time
- **SSL Certificates** — checks validity and expiry date for HTTPS endpoints
- **Database Detection** — nmap scan for MySQL (3306), PostgreSQL (5432), Redis (6379), MongoDB (27017), Elasticsearch (9200), InfluxDB (8086), CouchDB (5984)
- **Service Detection** — MQTT (1883), FTP (21), SMB (445), VNC (5900) with banner grabbing for version info

### Frontend
- Dark-themed single-page UI (PHP + vanilla JS)
- Dashboard with clickable stat cards
- Sections: Dashboard · Proxmox Hosts · VMs · LXC · Docker · Storage · Network · **Services** · Errors
- **Real-time log window** — opens automatically on scan start, polls every 1.5 s, auto-scroll
- **Cancel button** — stops running scan immediately
- Fuzzy search (Ctrl+K) across all data types
- Scan history modal with diff comparison
- Sortable tables, host filter sidebar, toast notifications

---

## Stack

| Layer | Technology |
|---|---|
| Web | PHP 8.2, Apache 2, vanilla JS |
| Scanner | Python 3.11 (venv) |
| Database | MariaDB 10.11 |
| Network | nmap, paramiko (SSH), requests |

---

## Setup

### Requirements
```
apt install nmap python3 python3-venv mariadb-server apache2
```

### Python venv
```bash
cd scanner/
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

### Database
```bash
sudo mysql << 'EOF'
CREATE DATABASE linux_systemscan CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'frank'@'localhost' IDENTIFIED BY 'yourpassword';
GRANT ALL PRIVILEGES ON linux_systemscan.* TO 'frank'@'localhost';
FLUSH PRIVILEGES;
EOF
```

Run the schema from `sql/schema.sql` (or trigger the first scan — tables are created automatically on first run if using the migration script).

### Config files
```bash
cp config.php.example config.php          # DB credentials + base URL
cp scanner/config.json.example scanner/config.json  # Proxmox hosts, SSH, HA token
```

**`config.php`**
```php
return [
    'db' => [
        'host'     => 'localhost',
        'name'     => 'linux_systemscan',
        'user'     => 'frank',
        'password' => 'yourpassword',
    ],
    'app' => [
        'title'    => 'Linux SystemScan',
        'base_url' => '/linux_systemscan',
    ],
];
```

**`scanner/config.json`** (relevant sections)
```json
{
  "database": { "host": "localhost", "name": "linux_systemscan", "user": "...", "password": "..." },
  "proxmox_hosts": [
    { "ip": "192.168.178.10", "port": 8006, "user": "root@pam", "password": "..." }
  ],
  "ssh_credentials": { "username": "root", "alt_username": "frank", "password": "...", "port": 22, "timeout": 10 },
  "homeassistant": [
    { "ip": "192.168.178.57", "port": 8123, "token": "...", "protocol": "http" }
  ],
  "local": { "nmap_subnet": "192.168.178.0/24" },
  "scan_options": { "scan_network": true, "scan_docker": true, "ssh_into_guests": true }
}
```

### Apache VHost
```apache
<VirtualHost *:80>
    DocumentRoot /var/www/html
    Alias /linux_systemscan /opt/linux_systemscan
    <Directory /opt/linux_systemscan>
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
```

Or symlink: `ln -s /opt/linux_systemscan /var/www/html/linux_systemscan`

### Cron (optional)
```bash
# /etc/cron.d/linux_systemscan
0 */6 * * * frank /opt/linux_systemscan/scan.sh
```

---

## Database Schema

| Table | Contents |
|---|---|
| `scan_runs` | Scan metadata (started, finished, counts, errors) |
| `proxmox_hosts` | Proxmox host metrics (CPU, RAM, disk, kernel, gateway) |
| `virtual_machines` | VMs per host |
| `lxc_containers` | LXC containers per host |
| `docker_containers` | Docker containers + HA add-ons |
| `storage_info` | Proxmox storage pools |
| `network_info` | Proxmox network interfaces |
| `network_hosts` | nmap LAN hosts (IP, hostname, category, MAC, vendor, web_url) |
| `network_topology` | Gateway, DNS, subnet per scan |
| `service_scan` | Web services + DB/service ports (title, status, SSL, banner) |
| `local_services` | systemd services on this host |
| `local_ports` | Open TCP ports on this host |
| `ssh_keys` | SSH public keys + purpose/targets |
| `apache_vhosts` | Apache VHost routes |
| `scan_errors` | Errors per scan run |

---

## File Structure

```
linux_systemscan/
├── index.php              # Single-page frontend
├── api.php                # REST API (dashboard, scan, trigger, cancel, log, status)
├── db.php                 # PDO DB connection
├── config.php             # DB + app config (gitignored)
├── config.php.example
├── scan.sh                # Convenience wrapper for cron
├── assets/
│   ├── app.js             # Frontend logic (vanilla JS)
│   ├── style.css          # Dark theme CSS
│   └── favicon.svg
└── scanner/
    ├── scan.py            # Main scanner (Proxmox API, SSH Docker, HA)
    ├── collect_local.py   # Local data: nmap, web details, service ports, systemd, SSH keys, Apache
    ├── start_scan.sh      # sudo wrapper (www-data → frank)
    ├── config.json        # Host/credentials config (gitignored)
    ├── config.json.example
    └── requirements.txt
```

---

## Trigger Scan via Web

The web UI triggers the scan directly as `www-data`. The scan log is written to `/tmp/systemscan_last.log` (world-writable). The scan can be cancelled via the UI; the PID is tracked in `/tmp/systemscan.pid`.

For cron-based execution, `scan.sh` runs the scanner as the `frank` user; output appends to `scanner/cron.log`.

---

## Known Hosts (Static IPs without DNS PTR)

Several hosts have static IPs with no DHCP/PTR records. These are covered by `HOST_META` in `collect_local.py`:

| IP | Device |
|---|---|
| .11 | Ollama AI Server (on .10) |
| .28 | Frigate NVR |
| .90 | Ollama AI Server (on .109) |
| .129 | Tapo Camera |
| .142 | Tapo Camera (Frigate) |

nmap uses `--dns-servers 192.168.178.106` (AdGuard Home) for forward lookups; PTR records are absent for these IPs.

---

## License

Private homelab project — not intended for public deployment without review of hardcoded credentials and network assumptions.
