#!/usr/bin/env python3
"""
collect_local.py – Sammelt lokale Daten von linkmanager:
  - nmap Netzwerk-Scan (alle Hosts im LAN)
  - nmap Web-Port-Scan (leitet web_url ab, speichert in DB)
  - Web-Details: HTTP GET, Titel, Status, Server, SSL-Zertifikat
  - Service-Ports: Datenbanken (MySQL, Redis, ...), MQTT, SMB, VNC
  - Systemd Services (systemctl)
  - Offene Ports (ss -tlnp)
  - SSH Keys + Deployment-Status
  - Apache VHosts
"""

import json
import os
import re
import socket
import ssl as ssl_module
import subprocess
import time
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

import requests as _req
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Statische Metadaten (Kategorie + Beschreibung) ─────────────────────────
HOST_META = {
    '192.168.178.1':   ('Infrastruktur', 'FritzBox Router · Gateway'),
    '192.168.178.3':   ('Infrastruktur', 'TP-Link Omada Controller OC200'),
    '192.168.178.4':   ('Infrastruktur', 'TP-Link Switch SG2008P'),
    '192.168.178.10':  ('Server',        'Proxmox Host – Geekom Mini-PC'),
    '192.168.178.11':  ('Server',        'Ollama AI Server'),
    '192.168.178.12':  ('Server',        'Open WebUI – Ollama Chat-Interface'),
    '192.168.178.23':  ('Server',        'Paperless-NGX QA'),
    '192.168.178.28':  ('Server',        'Frigate NVR – Kamera-Aufzeichnung'),
    '192.168.178.29':  ('Smart Home',    'Homematic CCU'),
    '192.168.178.32':  ('Server',        'Paperless-NGX Produktiv'),
    '192.168.178.42':  ('Server',        'Proxmox Host'),
    '192.168.178.44':  ('Energie',       'ESP32 Gaszähler'),
    '192.168.178.53':  ('Drucker',       'Bürodrucker'),
    '192.168.178.56':  ('Kamera',        'IP-Kamera'),
    '192.168.178.57':  ('Server',        'Home Assistant'),
    '192.168.178.67':  ('Energie',       'go-eCharger Wallbox'),
    '192.168.178.76':  ('Gerät',         'Samsung Galaxy A55 – Claudia'),
    '192.168.178.83':  ('Server',        'Paperless-NGX Test'),
    '192.168.178.89':  ('Server',        'linkmanager – DIESER HOST'),
    '192.168.178.90':  ('Server',        'Ollama AI Server'),
    '192.168.178.104': ('Server',        'GLM5 AI Dev Server'),
    '192.168.178.106': ('Infrastruktur', 'AdGuard Home DNS-Server'),
    '192.168.178.107': ('Drucker',       'Canon C500'),
    '192.168.178.109': ('Server',        'Proxmox Host 2'),
    '192.168.178.114': ('Kamera',        'IMOU Kamera – Hühnerstall'),
    '192.168.178.117': ('Drucker',       'Drucker'),
    '192.168.178.120': ('Drucker',       'Canon C310'),
    '192.168.178.129': ('Kamera',        'Tapo Kamera'),
    '192.168.178.132': ('Infrastruktur', 'TP-Link EAP225 Access Point Outdoor'),
    '192.168.178.135': ('Infrastruktur', 'TP-Link TL-WR902AC Router'),
    '192.168.178.142': ('Kamera',        'Tapo Kamera'),
    '192.168.178.143': ('Energie',       'Varta Batteriespeicher'),
    '192.168.178.150': ('Energie',       'EW11 RS485/Ethernet Adapter'),
    '192.168.178.153': ('Energie',       'Stromzähler'),
    '192.168.178.155': ('Shelly',        'Shelly Switch – Wintergarten Teich'),
    '192.168.178.158': ('Smart Home',    'Awtrix LED-Matrix'),
    '192.168.178.159': ('Kamera',        'NOMI IP-Kamera'),
    '192.168.178.161': ('Shelly',        'Shelly Plus 1 – Panikleuchte'),
    '192.168.178.166': ('Shelly',        'Shelly Steckdosenleiste – Wintergarten'),
    '192.168.178.167': ('Server',        'NAS'),
    '192.168.178.176': ('Kamera',        'Reolink Kamera'),
    '192.168.178.196': ('Energie',       'SMA Solar-Wechselrichter'),
    '192.168.178.200': ('Infrastruktur', 'FritzBox Repeater'),
}

SSH_KEY_PURPOSE = {
    'h2h_id_ed25519':            'Host-zu-Host LAN (alle 192.168.178.*)',
    'id_ed25519':                'GitHub + ai-glm5-dev',
    'id_ed25519_192_168_178_89': 'VSCode Remote → dieser Host',
    'id_ed25519_claude':         'Claude Stats',
}

SSH_KEY_TARGETS = {
    'h2h_id_ed25519': [
        '192.168.178.89 frank',
        '192.168.178.32 frank',
        '192.168.178.23 frank',
        '192.168.178.83 frank',
        '192.168.178.104 frank',
        '192.168.178.10 root',
        '192.168.178.42 root',
        '192.168.178.109 root',
    ],
    'id_ed25519': ['github.com', '192.168.178.104 frank'],
    'id_ed25519_192_168_178_89': ['192.168.178.89 frank (authorized_keys)'],
    'id_ed25519_claude': [],
}

# Priorisierte Web-Port-Liste: (port, schema)
# Erster offener Port gewinnt → web_url
WEB_PORTS = [
    (8006,  'https'),  # Proxmox
    (8123,  'http'),   # Home Assistant
    (5000,  'http'),   # Frigate / Synology DSM
    (3000,  'http'),   # Grafana / Node.js
    (1880,  'http'),   # Node-RED
    (9000,  'http'),   # diverse
    (8080,  'http'),   # Open WebUI / diverse
    (8443,  'https'),  # HTTPS-Alt
    (443,   'https'),  # Standard HTTPS
    (80,    'http'),   # Standard HTTP
]


# Service-Ports für Datenbanken, IoT und sonstige Dienste
SERVICE_PORTS = {
    21:    'ftp',
    3306:  'mysql',
    5432:  'postgres',
    6379:  'redis',
    27017: 'mongodb',
    1883:  'mqtt',
    9200:  'elasticsearch',
    5984:  'couchdb',
    8086:  'influxdb',
    445:   'smb',
    5900:  'vnc',
}


def _run(cmd, timeout=60):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip()


def _check_ssl_cert(ip, port, hostname=''):
    """Prüft SSL-Zertifikat und gibt {valid, expires, issuer} zurück."""
    result = {'valid': None, 'expires': '', 'issuer': ''}
    try:
        ctx = ssl_module.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_module.CERT_NONE
        with socket.create_connection((ip, port), timeout=5) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname or ip) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    result['valid'] = True
                    result['expires'] = cert.get('notAfter', '')
                    issuer_parts = dict(x[0] for x in cert.get('issuer', []))
                    result['issuer'] = (
                        issuer_parts.get('organizationName') or
                        issuer_parts.get('commonName', '')
                    )[:200]
                else:
                    result['valid'] = False
    except ssl_module.SSLError:
        result['valid'] = False
    except Exception:
        pass
    return result


def _grab_banner(ip, port, service_type, timeout=3):
    """Verbindet auf Port und liest ersten Banner (für DB/Service-Erkennung)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if service_type == 'redis':
                s.sendall(b'*1\r\n$4\r\nPING\r\n')
            elif service_type == 'elasticsearch':
                s.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
            data = s.recv(512)
            return data.decode('utf-8', errors='replace').strip()[:300]
    except Exception:
        return ''


# ── nmap Web-Port-Scan ───────────────────────────────────────────────────────
def scan_web_ports(ip_list, errors):
    """Scannt alle gefundenen Hosts auf Web-Ports, gibt {ip: web_url} zurück."""
    if not ip_list:
        return {}
    print(f"  [webports] Scanning {len(ip_list)} Hosts auf Web-Ports ...")
    port_str = ','.join(str(p) for p, _ in WEB_PORTS)
    web_map = {}
    try:
        result = subprocess.run(
            ['nmap', '-p', port_str, '--open', '-oX', '-'] + ip_list,
            capture_output=True, text=True, timeout=180
        )
        root = ET.fromstring(result.stdout)
        for h in root.findall('host'):
            ip = ''
            for addr in h.findall('address'):
                if addr.get('addrtype') == 'ipv4':
                    ip = addr.get('addr', '')
                    break
            if not ip:
                continue
            open_ports = set()
            ports_el = h.find('ports')
            if ports_el is not None:
                for p in ports_el.findall('port'):
                    state = p.find('state')
                    if state is not None and state.get('state') == 'open':
                        open_ports.add(int(p.get('portid', 0)))
            # Erste Priorität gewinnt
            for port, schema in WEB_PORTS:
                if port in open_ports:
                    if port in (80, 443):
                        web_map[ip] = f"{schema}://{ip}"
                    else:
                        web_map[ip] = f"{schema}://{ip}:{port}"
                    break
    except Exception as e:
        errors.append({'scan_id': None, 'host_ip': 'webports', 'component': 'web_ports',
                       'error_message': str(e), 'error_detail': traceback.format_exc()})
    print(f"    → {len(web_map)} Hosts mit Web-Interface")
    return web_map


# ── Web-Details (HTTP GET + SSL) ────────────────────────────────────────────
def scan_web_details(hosts, scan_id, errors):
    """HTTP/HTTPS GET auf jeden Host mit bekannter web_url – sammelt Titel, Status, SSL."""
    web_hosts = [
        (h['ip_address'], h.get('hostname', ''), h['web_url'])
        for h in hosts if h.get('web_url')
    ]
    if not web_hosts:
        return []

    print(f"  [webdetail] Scanning {len(web_hosts)} Web-Interfaces ...")
    services = []

    for ip, hostname, url in web_hosts:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        svc = {
            'scan_id': scan_id,
            'ip_address': ip,
            'hostname': hostname or '',
            'port': port,
            'service_type': parsed.scheme,  # 'http' oder 'https'
            'protocol': 'tcp',
            'status': 'open',
            'http_status': None,
            'http_title': '',
            'http_server': '',
            'http_powered_by': '',
            'ssl_valid': None,
            'ssl_expires': '',
            'ssl_issuer': '',
            'banner': '',
            'response_time_ms': None,
        }

        try:
            t0 = time.time()
            resp = _req.get(url, timeout=5, verify=False, allow_redirects=True,
                            headers={'User-Agent': 'SystemScan/1.0'})
            svc['response_time_ms'] = int((time.time() - t0) * 1000)
            svc['http_status'] = resp.status_code
            svc['http_server'] = (resp.headers.get('Server', '') or '')[:200]
            svc['http_powered_by'] = (resp.headers.get('X-Powered-By', '') or '')[:100]

            # HTML-Titel extrahieren
            m = re.search(r'<title[^>]*>(.*?)</title>',
                          resp.text[:8192], re.IGNORECASE | re.DOTALL)
            if m:
                svc['http_title'] = re.sub(r'\s+', ' ', m.group(1)).strip()[:400]

        except Exception as e:
            svc['status'] = 'error'
            svc['banner'] = str(e)[:300]

        # SSL-Zertifikat prüfen
        if parsed.scheme == 'https':
            ssl_info = _check_ssl_cert(ip, port, hostname)
            svc['ssl_valid'] = (1 if ssl_info['valid'] is True
                                else 0 if ssl_info['valid'] is False
                                else None)
            svc['ssl_expires'] = ssl_info['expires']
            svc['ssl_issuer'] = ssl_info['issuer']

        services.append(svc)
        ok_txt = f"HTTP {svc['http_status']}" if svc['http_status'] else svc['status']
        print(f"    {ip}:{port} ({parsed.scheme}) → {ok_txt}"
              + (f"  '{svc['http_title'][:40]}'" if svc['http_title'] else ''))

    reachable = sum(1 for s in services if s['status'] == 'open')
    print(f"    → {reachable}/{len(services)} Web-Services erreichbar")
    return services


# ── Netzwerk-Service-Ports (Datenbanken, IoT, ...) ──────────────────────────
def scan_network_services(hosts, scan_id, errors):
    """nmap auf Service-Ports + Banner-Grab für Datenbanken und andere Dienste."""
    if not hosts:
        return []

    ip_list = [h['ip_address'] for h in hosts]
    host_map = {h['ip_address']: h.get('hostname', '') for h in hosts}
    port_str = ','.join(str(p) for p in SERVICE_PORTS)

    print(f"  [netservices] Scanning {len(ip_list)} Hosts auf Service-Ports ({port_str}) ...")
    services = []

    try:
        result = subprocess.run(
            ['nmap', '-p', port_str, '--open', '-oX', '-'] + ip_list,
            capture_output=True, text=True, timeout=300
        )
        root = ET.fromstring(result.stdout)
        for h in root.findall('host'):
            ip = ''
            for addr in h.findall('address'):
                if addr.get('addrtype') == 'ipv4':
                    ip = addr.get('addr', '')
                    break
            if not ip:
                continue
            ports_el = h.find('ports')
            if not ports_el:
                continue
            for p_el in ports_el.findall('port'):
                state = p_el.find('state')
                if state is None or state.get('state') != 'open':
                    continue
                port = int(p_el.get('portid', 0))
                service_type = SERVICE_PORTS.get(port, f'port-{port}')
                banner = _grab_banner(ip, port, service_type)
                services.append({
                    'scan_id': scan_id,
                    'ip_address': ip,
                    'hostname': host_map.get(ip, ''),
                    'port': port,
                    'service_type': service_type,
                    'protocol': 'tcp',
                    'status': 'open',
                    'http_status': None,
                    'http_title': '',
                    'http_server': '',
                    'http_powered_by': '',
                    'ssl_valid': None,
                    'ssl_expires': '',
                    'ssl_issuer': '',
                    'banner': banner,
                    'response_time_ms': None,
                })
                print(f"    {ip}:{port} ({service_type})"
                      + (f" → {banner[:60]!r}" if banner else ''))
    except Exception as e:
        errors.append({
            'scan_id': scan_id, 'host_ip': 'netservices', 'component': 'network_services',
            'error_message': str(e), 'error_detail': traceback.format_exc()
        })

    print(f"    → {len(services)} Service-Ports offen")
    return services


# ── nmap Ping-Scan ───────────────────────────────────────────────────────────
def _shelly_desc(hostname):
    """Extrahiert lesbaren Namen aus Shelly-Hostnamen."""
    name = hostname.split('.')[0]
    name_l = name.lower()
    models = [
        ('shellyplusplugs', 'Shelly Plus Plug S'),
        ('shellyplus2pm',   'Shelly Plus 2PM'),
        ('shellyplus1pm',   'Shelly Plus 1PM'),
        ('shellyplus1',     'Shelly Plus 1'),
        ('shellydimmer2',   'Shelly Dimmer 2'),
        ('shellyplug-s',    'Shelly Plug S'),
        ('shellyplug',      'Shelly Plug'),
        ('shellyswitch',    'Shelly Switch'),
        ('shelly1pm',       'Shelly 1PM'),
        ('shelly1',         'Shelly 1'),
        ('shelly2',         'Shelly 2'),
    ]
    model_label = 'Shelly'
    rest = name_l
    for prefix, label in models:
        if name_l.startswith(prefix):
            model_label = label
            rest = name_l[len(prefix):].lstrip('-')
            break
    parts = rest.split('-') if rest else []
    # MAC-ähnliche Teile herausfiltern (6+ Hex-Zeichen)
    location = [p for p in parts if not re.match(r'^[0-9a-f]{6,}$', p)]
    if location:
        return f"{model_label} – {' '.join(p.capitalize() for p in location)}"
    return model_label


def scan_nmap(subnet, scan_id, errors):
    print(f"  [nmap] Scanning {subnet} ...")
    hosts = []
    try:
        result = subprocess.run(
            ['nmap', '-sn', '--dns-servers', '192.168.178.106', '-oX', '-', subnet],
            capture_output=True, text=True, timeout=120
        )
        root = ET.fromstring(result.stdout)
        for h in root.findall('host'):
            if h.find('status') is None or h.find('status').get('state') != 'up':
                continue
            ip = hostname = mac = vendor = ''
            for addr in h.findall('address'):
                t = addr.get('addrtype')
                if t == 'ipv4':
                    ip = addr.get('addr', '')
                elif t == 'mac':
                    mac = addr.get('addr', '')
                    vendor = addr.get('vendor', '')
            for hn in (h.find('hostnames') or []):
                hostname = hn.get('name', '')
                break
            if not ip:
                continue

            cat, desc = HOST_META.get(ip, (None, None))
            if cat is None:
                hn_l = hostname.lower()
                base = hn_l.split('.')[0]  # ohne .fritz.box
                if base.startswith('shelly'):
                    cat, desc = 'Shelly', _shelly_desc(hostname)
                elif 'frigate' in base:
                    cat, desc = 'Server', 'Frigate NVR – Kamera-Aufzeichnung'
                elif 'ollama' in base:
                    cat, desc = 'Server', f'Ollama AI Server – {base}'
                elif any(x in base for x in ('tapo',)):
                    cat, desc = 'Kamera', f'Tapo Kamera – {base}'
                elif any(x in base for x in ('drucker', 'c500', 'c310', 'c200', 'rtk')):
                    cat, desc = 'Drucker', hostname.split('.')[0]
                elif any(x in base for x in ('ipcam', 'imou', 'reolink', 'nomi')):
                    cat, desc = 'Kamera', hostname.split('.')[0]
                elif any(x in base for x in ('tablet', 'android', 'pixel', 'redmi', 'samsung', 'tab-s', 'a55')):
                    cat, desc = 'Gerät', f'Mobilgerät – {hostname.split(".")[0]}'
                elif 'roborock' in base:
                    cat, desc = 'Gerät', 'Roborock Saugroboter'
                elif 'amazon' in base:
                    cat, desc = 'Gerät', 'Amazon Echo/Fire'
                elif 'awtrix' in base:
                    cat, desc = 'Smart Home', 'Awtrix LED-Matrix'
                elif any(x in base for x in ('eap', 'tl-', 'sg200', 'oc200', 'adguard')):
                    cat, desc = 'Infrastruktur', hostname.split('.')[0]
                elif any(x in base for x in ('varta', 'sma', 'go-echarger', 'gasuhr', 'ew11', 'stromzaehler')):
                    cat, desc = 'Energie', hostname.split('.')[0]
                else:
                    cat, desc = 'Unbekannt', hostname.split('.')[0]

            hosts.append({
                'scan_id': scan_id, 'ip_address': ip, 'hostname': hostname,
                'status': 'up', 'category': cat, 'description': desc or '',
                'mac_address': mac, 'vendor': vendor,
                'web_url': '',  # wird nach Web-Port-Scan befüllt
            })
    except Exception as e:
        errors.append({'scan_id': scan_id, 'host_ip': subnet, 'component': 'nmap',
                       'error_message': str(e), 'error_detail': traceback.format_exc()})
    print(f"    → {len(hosts)} Hosts gefunden")

    # Web-Port-Scan für alle gefundenen IPs
    ip_list = [h['ip_address'] for h in hosts]
    web_map = scan_web_ports(ip_list, errors)
    for h in hosts:
        h['web_url'] = web_map.get(h['ip_address'], '')

    return hosts


# ── Systemd Services ────────────────────────────────────────────────────────
def scan_services(scan_id, errors):
    print("  [services] Scanning systemd services ...")
    services = []
    try:
        out = _run(['systemctl', 'list-units', '--type=service', '--state=running',
                    '--no-pager', '--no-legend', '--plain'])
        for line in out.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 4:
                continue
            name = parts[0].replace('.service', '')
            status = parts[2]
            description = parts[4] if len(parts) > 4 else ''
            services.append({
                'scan_id': scan_id, 'name': name,
                'status': status, 'description': description,
            })
    except Exception as e:
        errors.append({'scan_id': scan_id, 'host_ip': '127.0.0.1', 'component': 'services',
                       'error_message': str(e), 'error_detail': traceback.format_exc()})
    print(f"    → {len(services)} Services")
    return services


# ── Offene Ports ────────────────────────────────────────────────────────────
PORT_NAMES = {
    22: 'SSH', 25: 'SMTP (Postfix)', 80: 'HTTP (Apache)', 111: 'RPC',
    443: 'HTTPS', 3306: 'MariaDB', 5037: 'ADB', 5050: 'EPEVER Web',
    8000: 'Sensor-Editor Flask', 8100: 'Paperless-NGX Docker', 8123: 'Home Assistant',
}

def scan_ports(scan_id, errors):
    print("  [ports] Scanning open ports ...")
    ports = []
    try:
        out = _run(['ss', '-tlnp'])
        for line in out.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3]
            # parse bind:port
            if local.startswith('[::]:'):
                bind, port_str = '::', local.split(']:')[1]
            elif ':' in local:
                bind, port_str = local.rsplit(':', 1)
            else:
                continue
            try:
                port = int(port_str)
            except ValueError:
                continue
            accessibility = 'localhost' if bind in ('127.0.0.1', '::1') else 'extern'
            ports.append({
                'scan_id': scan_id, 'port': port, 'protocol': 'tcp',
                'bind_address': bind,
                'service_name': PORT_NAMES.get(port, ''),
                'accessibility': accessibility,
            })
    except Exception as e:
        errors.append({'scan_id': scan_id, 'host_ip': '127.0.0.1', 'component': 'ports',
                       'error_message': str(e), 'error_detail': traceback.format_exc()})
    print(f"    → {len(ports)} Ports")
    return ports


# ── SSH Keys ─────────────────────────────────────────────────────────────────
def scan_ssh_keys(scan_id, errors):
    print("  [ssh] Scanning SSH keys ...")
    keys = []
    ssh_dir = Path('/home/frank/.ssh')
    try:
        for pub_file in sorted(ssh_dir.glob('*.pub')):
            key_name = pub_file.stem
            pubkey = pub_file.read_text().strip()
            comment = pubkey.split()[-1] if pubkey else ''
            keys.append({
                'scan_id': scan_id,
                'key_file': key_name,
                'comment': comment,
                'pubkey': pubkey,
                'purpose': SSH_KEY_PURPOSE.get(key_name, ''),
                'targets': json.dumps(SSH_KEY_TARGETS.get(key_name, [])),
            })
    except Exception as e:
        errors.append({'scan_id': scan_id, 'host_ip': '127.0.0.1', 'component': 'ssh_keys',
                       'error_message': str(e), 'error_detail': traceback.format_exc()})
    print(f"    → {len(keys)} SSH Keys")
    return keys


# ── Apache VHosts ────────────────────────────────────────────────────────────
def scan_apache_vhosts(scan_id, errors):
    print("  [apache] Scanning VHosts ...")
    vhosts = []
    sites_enabled = Path('/etc/apache2/sites-enabled')
    try:
        for conf_file in sorted(sites_enabled.glob('*.conf')):
            content = conf_file.read_text()
            server_name = ''
            for m in re.finditer(r'ServerName\s+(\S+)', content):
                server_name = m.group(1)
            # Extract routes
            for m in re.finditer(
                r'(?:ProxyPass|WSGIScriptAlias|Alias)\s+(\S+)\s+(\S+)|'
                r'<Location\s+(\S+)>\s*(?:.*?)\s*ProxyPass\s+"?(\S+)"?',
                content, re.DOTALL
            ):
                route = m.group(1) or m.group(3) or ''
                target = m.group(2) or m.group(4) or ''
                if route and target:
                    vhosts.append({
                        'scan_id': scan_id,
                        'config_file': conf_file.name,
                        'server_name': server_name or '*:80',
                        'route': route,
                        'target': target,
                    })
    except Exception as e:
        errors.append({'scan_id': scan_id, 'host_ip': '127.0.0.1', 'component': 'apache',
                       'error_message': str(e), 'error_detail': traceback.format_exc()})
    print(f"    → {len(vhosts)} VHost-Routen")
    return vhosts


# ── Netzwerk-Topologie ───────────────────────────────────────────────────────
def scan_topology(scan_id, nmap_count, errors):
    """Sammelt Gateway, DNS, Subnet-Info von diesem Host."""
    print("  [topology] Collecting network topology ...")
    topology = {
        'scan_id': scan_id,
        'gateway_ip': '',
        'dns_server1': '',
        'dns_server2': '',
        'dns_domain': '',
        'subnet': '192.168.178.0/24',
        'nmap_hosts_found': nmap_count,
    }
    try:
        out = _run(['ip', 'route', 'show', 'default'])
        for line in out.splitlines():
            if 'default via' in line:
                parts = line.split()
                via_idx = parts.index('via')
                topology['gateway_ip'] = parts[via_idx + 1]
                break
    except Exception as e:
        errors.append({'scan_id': scan_id, 'host_ip': '127.0.0.1', 'component': 'topology',
                       'error_message': str(e), 'error_detail': traceback.format_exc()})
    try:
        resolv = Path('/etc/resolv.conf').read_text()
        dns_list = []
        for line in resolv.splitlines():
            stripped = line.strip()
            if stripped.startswith('nameserver'):
                parts = stripped.split()
                if len(parts) >= 2:
                    dns_list.append(parts[1])
            elif stripped.startswith('search') or stripped.startswith('domain'):
                parts = stripped.split(maxsplit=1)
                if len(parts) >= 2:
                    topology['dns_domain'] = parts[1]
        topology['dns_server1'] = dns_list[0] if len(dns_list) > 0 else ''
        topology['dns_server2'] = dns_list[1] if len(dns_list) > 1 else ''
    except Exception:
        pass
    print(f"    → Gateway: {topology['gateway_ip']}, DNS: {topology['dns_server1']}")
    return topology


# ── DB speichern ─────────────────────────────────────────────────────────────
def save_local_data(db, scan_id, nmap_hosts, services, ports, ssh_keys, vhosts, topology, service_scan=None):
    cursor = db.cursor()

    if nmap_hosts:
        cursor.executemany("""
            INSERT INTO network_hosts
            (scan_id, ip_address, hostname, status, category, description, mac_address, vendor, web_url)
            VALUES (%(scan_id)s,%(ip_address)s,%(hostname)s,%(status)s,
                    %(category)s,%(description)s,%(mac_address)s,%(vendor)s,%(web_url)s)
        """, nmap_hosts)

    if services:
        cursor.executemany("""
            INSERT INTO local_services (scan_id, name, status, description)
            VALUES (%(scan_id)s,%(name)s,%(status)s,%(description)s)
        """, services)

    if ports:
        cursor.executemany("""
            INSERT INTO local_ports (scan_id, port, protocol, bind_address, service_name, accessibility)
            VALUES (%(scan_id)s,%(port)s,%(protocol)s,%(bind_address)s,%(service_name)s,%(accessibility)s)
        """, ports)

    if ssh_keys:
        cursor.executemany("""
            INSERT INTO ssh_keys (scan_id, key_file, comment, pubkey, purpose, targets)
            VALUES (%(scan_id)s,%(key_file)s,%(comment)s,%(pubkey)s,%(purpose)s,%(targets)s)
        """, ssh_keys)

    if vhosts:
        cursor.executemany("""
            INSERT INTO apache_vhosts (scan_id, config_file, server_name, route, target)
            VALUES (%(scan_id)s,%(config_file)s,%(server_name)s,%(route)s,%(target)s)
        """, vhosts)

    if topology:
        cursor.execute("""
            INSERT INTO network_topology
            (scan_id, gateway_ip, dns_server1, dns_server2, dns_domain, subnet, nmap_hosts_found)
            VALUES (%(scan_id)s,%(gateway_ip)s,%(dns_server1)s,%(dns_server2)s,
                    %(dns_domain)s,%(subnet)s,%(nmap_hosts_found)s)
        """, topology)

    if service_scan:
        cursor.executemany("""
            INSERT INTO service_scan
            (scan_id, ip_address, hostname, port, service_type, protocol, status,
             http_status, http_title, http_server, http_powered_by,
             ssl_valid, ssl_expires, ssl_issuer, banner, response_time_ms)
            VALUES (%(scan_id)s,%(ip_address)s,%(hostname)s,%(port)s,%(service_type)s,
                    %(protocol)s,%(status)s,%(http_status)s,%(http_title)s,%(http_server)s,
                    %(http_powered_by)s,%(ssl_valid)s,%(ssl_expires)s,%(ssl_issuer)s,
                    %(banner)s,%(response_time_ms)s)
        """, service_scan)

    cursor.close()


def run_all(db, scan_id, config):
    errors = []
    subnet = config.get('nmap_subnet', '192.168.178.0/24')

    nmap_hosts   = scan_nmap(subnet, scan_id, errors)
    services     = scan_services(scan_id, errors)
    ports        = scan_ports(scan_id, errors)
    ssh_keys     = scan_ssh_keys(scan_id, errors)
    vhosts       = scan_apache_vhosts(scan_id, errors)
    topology     = scan_topology(scan_id, len(nmap_hosts), errors)
    web_details  = scan_web_details(nmap_hosts, scan_id, errors)
    net_services = scan_network_services(nmap_hosts, scan_id, errors)
    service_scan = web_details + net_services

    save_local_data(db, scan_id, nmap_hosts, services, ports, ssh_keys, vhosts, topology, service_scan)

    return errors
