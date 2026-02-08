#!/usr/bin/env python3
"""
Linux SystemScan - Infrastructure Scanner
Scans Proxmox hosts, VMs, LXC containers, Docker, and system info.
Stores results in MySQL database.
"""

import json
import sys
import os
import time
import traceback
from datetime import datetime

import requests
import paramiko
import mysql.connector
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for self-signed Proxmox certs
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, 'config.json')


def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)


def get_db_connection(config):
    db_cfg = config['database']
    return mysql.connector.connect(
        host=db_cfg['host'],
        database=db_cfg['name'],
        user=db_cfg['user'],
        password=db_cfg['password'],
        charset='utf8mb4',
        autocommit=True
    )


def proxmox_api(host_ip, port, ticket, endpoint):
    """Make authenticated Proxmox API call."""
    url = f"https://{host_ip}:{port}/api2/json{endpoint}"
    cookies = {'PVEAuthCookie': ticket}
    resp = requests.get(url, cookies=cookies, verify=False, timeout=15)
    resp.raise_for_status()
    return resp.json().get('data', {})


def proxmox_authenticate(host_ip, port, user, password):
    """Authenticate against Proxmox API and return ticket + CSRF token."""
    url = f"https://{host_ip}:{port}/api2/json/access/ticket"
    resp = requests.post(url, data={
        'username': user,
        'password': password
    }, verify=False, timeout=15)
    resp.raise_for_status()
    data = resp.json()['data']
    return data['ticket'], data['CSRFPreventionToken']


def ssh_exec(ip, username, password, command, port=22, timeout=10):
    """Execute command via SSH and return stdout."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=port, username=username, password=password,
                       timeout=timeout, look_for_keys=False, allow_agent=False)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode('utf-8', errors='replace').strip()
        return output
    finally:
        client.close()


def try_ssh_exec(ip, ssh_config, command, errors_list, scan_id, component="SSH"):
    """Try SSH execution with multiple user fallback, log error if it fails."""
    users_to_try = [ssh_config['username']]
    alt_user = ssh_config.get('alt_username')
    if alt_user and alt_user != ssh_config['username']:
        users_to_try.append(alt_user)

    last_error = None
    for user in users_to_try:
        try:
            return ssh_exec(
                ip, user, ssh_config['password'], command,
                ssh_config.get('port', 22), ssh_config.get('timeout', 10)
            )
        except Exception as e:
            last_error = e

    errors_list.append({
        'scan_id': scan_id,
        'host_ip': ip,
        'component': component,
        'error_message': f"SSH to {ip} failed (tried: {', '.join(users_to_try)}): {str(last_error)}",
        'error_detail': traceback.format_exc()
    })
    return None


def get_guest_ip_from_proxmox(host_ip, port, ticket, node_name, vmtype, vmid):
    """Try to get guest IP from Proxmox agent or network config."""
    try:
        if vmtype == 'qemu':
            # Try QEMU guest agent
            data = proxmox_api(host_ip, port, ticket,
                               f"/nodes/{node_name}/qemu/{vmid}/agent/network-get-interfaces")
            if isinstance(data, dict) and 'result' in data:
                for iface in data['result']:
                    if iface.get('name') == 'lo':
                        continue
                    for addr in iface.get('ip-addresses', []):
                        if addr.get('ip-address-type') == 'ipv4' and not addr['ip-address'].startswith('127.'):
                            return addr['ip-address']
        else:
            # LXC - try config
            data = proxmox_api(host_ip, port, ticket,
                               f"/nodes/{node_name}/lxc/{vmid}/config")
            # Check net0, net1, etc.
            for key, val in data.items():
                if key.startswith('net') and 'ip=' in str(val):
                    parts = str(val).split(',')
                    for p in parts:
                        if p.strip().startswith('ip='):
                            ip_val = p.strip().split('=')[1].split('/')[0]
                            if ip_val and ip_val != 'dhcp':
                                return ip_val
            # Try interfaces
            try:
                ifaces = proxmox_api(host_ip, port, ticket,
                                     f"/nodes/{node_name}/lxc/{vmid}/interfaces")
                if isinstance(ifaces, list):
                    for iface in ifaces:
                        if iface.get('name') == 'lo':
                            continue
                        inet = iface.get('inet', '')
                        if inet and not inet.startswith('127.'):
                            return inet.split('/')[0]
            except Exception:
                pass
    except Exception:
        pass
    return None


def scan_docker_on_host(ip, ssh_config, errors_list, scan_id):
    """SSH into a host and get Docker container information."""
    # First check if Docker is installed
    docker_check = try_ssh_exec(ip, ssh_config,
                                "which docker 2>/dev/null && docker info --format '{{.ServerVersion}}' 2>/dev/null || echo 'NO_DOCKER'",
                                errors_list, scan_id, "Docker")
    if not docker_check or 'NO_DOCKER' in docker_check:
        return []

    # Get container data as JSON
    docker_output = try_ssh_exec(ip, ssh_config,
                                 'docker ps -a --format \'{"id":"{{.ID}}","name":"{{.Names}}","image":"{{.Image}}","status":"{{.Status}}","state":"{{.State}}","ports":"{{.Ports}}","created":"{{.CreatedAt}}","networks":"{{.Networks}}","mounts":"{{.Mounts}}"}\' 2>/dev/null',
                                 errors_list, scan_id, "Docker")
    if not docker_output:
        return []

    containers = []
    hostname = try_ssh_exec(ip, ssh_config, "hostname", errors_list, scan_id, "Docker") or ip
    for line in docker_output.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        try:
            c = json.loads(line)
            containers.append({
                'host_ip': ip,
                'host_name': hostname,
                'container_id': c.get('id', ''),
                'name': c.get('name', ''),
                'image': c.get('image', ''),
                'status': c.get('status', ''),
                'state': c.get('state', ''),
                'ports': c.get('ports', ''),
                'created_at': c.get('created', ''),
                'networks': c.get('networks', ''),
                'mounts': c.get('mounts', ''),
            })
        except json.JSONDecodeError:
            errors_list.append({
                'scan_id': scan_id,
                'host_ip': ip,
                'component': 'Docker-Parse',
                'error_message': f"Failed to parse Docker JSON from {ip}",
                'error_detail': line
            })
    return containers


def scan_homeassistant(ha_cfg, scan_id, errors_list):
    """Scan Home Assistant via REST API for add-ons and system info."""
    ip = ha_cfg['ip']
    port = ha_cfg.get('port', 8123)
    token = ha_cfg['token']
    protocol = ha_cfg.get('protocol', 'http')
    base_url = f"{protocol}://{ip}:{port}"

    print(f"  Scanning Home Assistant on {ip}:{port}...")
    result = {'docker': [], 'ha_info': None}

    headers = {'Authorization': f'Bearer {token}'}

    # Get HA config
    try:
        resp = requests.get(f"{base_url}/api/config", headers=headers, timeout=15, verify=False)
        resp.raise_for_status()
        ha_config = resp.json()
    except Exception as e:
        errors_list.append({
            'scan_id': scan_id,
            'host_ip': ip,
            'component': 'HomeAssistant-API',
            'error_message': f"HA API config failed on {ip}: {str(e)}",
            'error_detail': traceback.format_exc()
        })
        return result

    # Get all states
    try:
        resp = requests.get(f"{base_url}/api/states", headers=headers, timeout=30, verify=False)
        resp.raise_for_status()
        states = resp.json()
    except Exception as e:
        errors_list.append({
            'scan_id': scan_id,
            'host_ip': ip,
            'component': 'HomeAssistant-States',
            'error_message': f"HA API states failed on {ip}: {str(e)}",
            'error_detail': traceback.format_exc()
        })
        return result

    # Extract add-ons from update entities
    ha_name = ha_config.get('location_name', 'Home Assistant')
    updates = [s for s in states if s['entity_id'].startswith('update.')]

    for u in updates:
        attrs = u.get('attributes', {})
        title = attrs.get('title')
        entity_id = u['entity_id']

        # Filter: only add-ons and HA system updates (skip device firmware)
        if not title:
            continue
        if '_firmware' in entity_id:
            continue
        if '_update' not in entity_id:
            continue

        installed_ver = attrs.get('installed_version', '?')
        latest_ver = attrs.get('latest_version', '?')
        has_update = u['state'] == 'on'
        state_str = 'update_available' if has_update else 'running'
        if u['state'] == 'unavailable':
            state_str = 'unavailable'

        status_detail = f"v{installed_ver}"
        if has_update and latest_ver:
            status_detail += f" -> {latest_ver}"

        result['docker'].append({
            'host_ip': ip,
            'host_name': f"{ha_name} (HAOS)",
            'container_id': entity_id,
            'name': title,
            'image': f"ha-addon/{entity_id.replace('update.', '').replace('_update', '')}",
            'status': status_detail,
            'state': state_str,
            'ports': '',
            'created_at': '',
            'networks': 'hassio',
            'mounts': '',
        })

    print(f"    Found {len(result['docker'])} add-ons/components")
    return result


def format_bytes(b):
    """Format bytes to human-readable."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def scan_proxmox_host(host_cfg, ssh_config, scan_id, errors_list, scan_options):
    """Scan a single Proxmox host and return all collected data."""
    ip = host_cfg['ip']
    port = host_cfg.get('port', 8006)
    result = {
        'host': None,
        'vms': [],
        'lxcs': [],
        'docker': [],
        'storage': [],
        'network': []
    }

    print(f"  Scanning Proxmox host {ip}...")

    # Authenticate
    try:
        ticket, csrf = proxmox_authenticate(ip, port, host_cfg['user'], host_cfg['password'])
    except Exception as e:
        errors_list.append({
            'scan_id': scan_id,
            'host_ip': ip,
            'component': 'Proxmox-Auth',
            'error_message': f"Authentication failed for {ip}: {str(e)}",
            'error_detail': traceback.format_exc()
        })
        return result

    # Get version
    try:
        version_data = proxmox_api(ip, port, ticket, '/version')
    except Exception:
        version_data = {}

    # Get nodes
    try:
        nodes = proxmox_api(ip, port, ticket, '/nodes')
    except Exception as e:
        errors_list.append({
            'scan_id': scan_id,
            'host_ip': ip,
            'component': 'Proxmox-Nodes',
            'error_message': f"Failed to get nodes from {ip}: {str(e)}",
            'error_detail': traceback.format_exc()
        })
        return result

    if not nodes:
        return result

    node = nodes[0] if isinstance(nodes, list) else nodes
    node_name = node.get('node', 'unknown')

    # Host info
    result['host'] = {
        'ip_address': ip,
        'hostname': node_name,
        'pve_version': version_data.get('version', 'unknown'),
        'node_name': node_name,
        'status': node.get('status', 'unknown'),
        'uptime_seconds': node.get('uptime', 0),
        'cpu_count': node.get('maxcpu', 0),
        'cpu_usage': node.get('cpu', 0),
        'mem_total': node.get('maxmem', 0),
        'mem_used': node.get('mem', 0),
        'disk_total': node.get('maxdisk', 0),
        'disk_used': node.get('disk', 0),
    }

    # Get kernel version via SSH
    kernel = try_ssh_exec(ip, ssh_config, "uname -r", errors_list, scan_id, "Proxmox-SSH")
    if kernel:
        result['host']['kernel_version'] = kernel

    # Get cluster resources
    try:
        resources = proxmox_api(ip, port, ticket, '/cluster/resources')
    except Exception as e:
        errors_list.append({
            'scan_id': scan_id,
            'host_ip': ip,
            'component': 'Proxmox-Resources',
            'error_message': f"Failed to get resources from {ip}: {str(e)}",
            'error_detail': traceback.format_exc()
        })
        resources = []

    # Process resources
    guest_ips = {}  # vmid -> ip for Docker scanning
    for res in resources:
        res_type = res.get('type', '')
        if res_type == 'qemu':
            vm_ip = get_guest_ip_from_proxmox(ip, port, ticket, node_name, 'qemu', res.get('vmid'))
            vm = {
                'host_ip': ip,
                'node_name': node_name,
                'vmid': res.get('vmid', 0),
                'name': res.get('name', ''),
                'status': res.get('status', ''),
                'tags': res.get('tags', ''),
                'is_template': 1 if res.get('template', 0) else 0,
                'cpu_count': res.get('maxcpu', 0),
                'cpu_usage': res.get('cpu', 0),
                'mem_total': res.get('maxmem', 0),
                'mem_used': res.get('mem', 0),
                'disk_total': res.get('maxdisk', 0),
                'disk_used': res.get('disk', 0),
                'disk_read': res.get('diskread', 0),
                'disk_write': res.get('diskwrite', 0),
                'net_in': res.get('netin', 0),
                'net_out': res.get('netout', 0),
                'uptime_seconds': res.get('uptime', 0),
                'ip_address': vm_ip,
            }
            result['vms'].append(vm)
            if vm_ip and res.get('status') == 'running':
                guest_ips[res.get('vmid')] = vm_ip

        elif res_type == 'lxc':
            lxc_ip = get_guest_ip_from_proxmox(ip, port, ticket, node_name, 'lxc', res.get('vmid'))
            lxc = {
                'host_ip': ip,
                'node_name': node_name,
                'vmid': res.get('vmid', 0),
                'name': res.get('name', ''),
                'status': res.get('status', ''),
                'cpu_count': res.get('maxcpu', 0),
                'cpu_usage': res.get('cpu', 0),
                'mem_total': res.get('maxmem', 0),
                'mem_used': res.get('mem', 0),
                'disk_total': res.get('maxdisk', 0),
                'disk_used': res.get('disk', 0),
                'disk_read': res.get('diskread', 0),
                'disk_write': res.get('diskwrite', 0),
                'net_in': res.get('netin', 0),
                'net_out': res.get('netout', 0),
                'uptime_seconds': res.get('uptime', 0),
                'ip_address': lxc_ip,
            }
            result['lxcs'].append(lxc)
            if lxc_ip and res.get('status') == 'running':
                guest_ips[res.get('vmid')] = lxc_ip

        elif res_type == 'storage':
            stor = {
                'host_ip': ip,
                'node_name': node_name,
                'storage_name': res.get('storage', ''),
                'storage_type': res.get('plugintype', ''),
                'content': res.get('content', ''),
                'total_bytes': res.get('maxdisk', 0),
                'used_bytes': res.get('disk', 0),
                'shared': 1 if res.get('shared', 0) else 0,
                'status': res.get('status', ''),
            }
            result['storage'].append(stor)

    # Scan network interfaces from Proxmox host
    if scan_options.get('scan_network', True):
        try:
            net_data = proxmox_api(ip, port, ticket, f"/nodes/{node_name}/network")
            if isinstance(net_data, list):
                for iface in net_data:
                    result['network'].append({
                        'host_ip': ip,
                        'host_name': node_name,
                        'interface_name': iface.get('iface', ''),
                        'ip_address': iface.get('address', iface.get('cidr', '')),
                        'type': iface.get('type', ''),
                        'active': 1 if iface.get('active', 0) else 0,
                        'bridge_ports': iface.get('bridge_ports', ''),
                    })
        except Exception as e:
            errors_list.append({
                'scan_id': scan_id,
                'host_ip': ip,
                'component': 'Network',
                'error_message': f"Failed to get network info from {ip}: {str(e)}",
                'error_detail': traceback.format_exc()
            })

    # Scan Docker on Proxmox host itself
    if scan_options.get('scan_docker', True):
        docker_containers = scan_docker_on_host(ip, ssh_config, errors_list, scan_id)
        result['docker'].extend(docker_containers)

        # Scan Docker on running guests
        skip_ips = scan_options.get('skip_docker_scan', [])
        if scan_options.get('ssh_into_guests', True):
            for vmid, guest_ip in guest_ips.items():
                if guest_ip in skip_ips:
                    label = scan_options.get('guest_labels', {}).get(guest_ip, 'uebersprungen')
                    print(f"    Skipping Docker scan on {guest_ip} (VMID {vmid}): {label}")
                    continue
                print(f"    Scanning Docker on guest {guest_ip} (VMID {vmid})...")
                guest_docker = scan_docker_on_host(guest_ip, ssh_config, errors_list, scan_id)
                result['docker'].extend(guest_docker)

    # Also scan Docker on localhost if this is the local machine
    return result


def save_to_database(db, scan_id, all_results, errors_list):
    """Save all scan results to the database."""
    cursor = db.cursor()

    total_vms = 0
    total_lxcs = 0
    total_docker = 0

    for result in all_results:
        host = result.get('host')
        if host:
            cursor.execute("""
                INSERT INTO proxmox_hosts
                (scan_id, ip_address, hostname, pve_version, node_name, status,
                 uptime_seconds, cpu_count, cpu_usage, mem_total, mem_used,
                 disk_total, disk_used, kernel_version)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (scan_id, host['ip_address'], host['hostname'], host['pve_version'],
                  host['node_name'], host['status'], host['uptime_seconds'],
                  host['cpu_count'], host['cpu_usage'], host['mem_total'],
                  host['mem_used'], host['disk_total'], host['disk_used'],
                  host.get('kernel_version', '')))

        for vm in result.get('vms', []):
            total_vms += 1
            cursor.execute("""
                INSERT INTO virtual_machines
                (scan_id, host_ip, node_name, vmid, name, status, tags, is_template,
                 cpu_count, cpu_usage, mem_total, mem_used, disk_total, disk_used,
                 disk_read, disk_write, net_in, net_out, uptime_seconds, ip_address)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (scan_id, vm['host_ip'], vm['node_name'], vm['vmid'], vm['name'],
                  vm['status'], vm['tags'], vm['is_template'], vm['cpu_count'],
                  vm['cpu_usage'], vm['mem_total'], vm['mem_used'], vm['disk_total'],
                  vm['disk_used'], vm['disk_read'], vm['disk_write'], vm['net_in'],
                  vm['net_out'], vm['uptime_seconds'], vm.get('ip_address')))

        for lxc in result.get('lxcs', []):
            total_lxcs += 1
            cursor.execute("""
                INSERT INTO lxc_containers
                (scan_id, host_ip, node_name, vmid, name, status,
                 cpu_count, cpu_usage, mem_total, mem_used, disk_total, disk_used,
                 disk_read, disk_write, net_in, net_out, uptime_seconds, ip_address)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (scan_id, lxc['host_ip'], lxc['node_name'], lxc['vmid'], lxc['name'],
                  lxc['status'], lxc['cpu_count'], lxc['cpu_usage'], lxc['mem_total'],
                  lxc['mem_used'], lxc['disk_total'], lxc['disk_used'], lxc['disk_read'],
                  lxc['disk_write'], lxc['net_in'], lxc['net_out'],
                  lxc['uptime_seconds'], lxc.get('ip_address')))

        for dc in result.get('docker', []):
            total_docker += 1
            cursor.execute("""
                INSERT INTO docker_containers
                (scan_id, host_ip, host_name, container_id, name, image, status,
                 state, ports, created_at, networks, mounts)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (scan_id, dc['host_ip'], dc['host_name'], dc['container_id'],
                  dc['name'], dc['image'], dc['status'], dc['state'],
                  dc['ports'], dc['created_at'], dc['networks'], dc.get('mounts', '')))

        for stor in result.get('storage', []):
            cursor.execute("""
                INSERT INTO storage_info
                (scan_id, host_ip, node_name, storage_name, storage_type,
                 content, total_bytes, used_bytes, shared, status)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (scan_id, stor['host_ip'], stor['node_name'], stor['storage_name'],
                  stor['storage_type'], stor['content'], stor['total_bytes'],
                  stor['used_bytes'], stor['shared'], stor['status']))

        for net in result.get('network', []):
            cursor.execute("""
                INSERT INTO network_info
                (scan_id, host_ip, host_name, interface_name, ip_address,
                 type, active, bridge_ports)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, (scan_id, net['host_ip'], net['host_name'], net['interface_name'],
                  net['ip_address'], net['type'], net['active'], net.get('bridge_ports', '')))

    # Save errors
    for err in errors_list:
        cursor.execute("""
            INSERT INTO scan_errors
            (scan_id, host_ip, component, error_message, error_detail)
            VALUES (%s,%s,%s,%s,%s)
        """, (err['scan_id'], err.get('host_ip'), err.get('component'),
              err['error_message'], err.get('error_detail', '')))

    cursor.close()
    return total_vms, total_lxcs, total_docker


def cleanup_old_scans(db, max_scans):
    """Remove old scan data, keeping only the most recent N scans."""
    cursor = db.cursor()
    cursor.execute("SELECT id FROM scan_runs ORDER BY id DESC LIMIT %s, 999999", (max_scans,))
    old_ids = [row[0] for row in cursor.fetchall()]
    if old_ids:
        placeholders = ','.join(['%s'] * len(old_ids))
        cursor.execute(f"DELETE FROM scan_runs WHERE id IN ({placeholders})", old_ids)
        print(f"  Cleaned up {len(old_ids)} old scan(s)")
    cursor.close()


def main():
    start_time = time.time()
    print("=" * 60)
    print(f"Linux SystemScan - Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    config = load_config()
    db = get_db_connection(config)
    cursor = db.cursor()

    # Create scan run
    cursor.execute(
        "INSERT INTO scan_runs (started_at, status) VALUES (NOW(), 'running')"
    )
    scan_id = cursor.lastrowid
    cursor.close()
    print(f"  Scan ID: {scan_id}")

    errors_list = []
    all_results = []
    ssh_config = config['ssh_credentials']
    scan_options = config.get('scan_options', {})
    scan_options['skip_docker_scan'] = config.get('skip_docker_scan', [])
    scan_options['guest_labels'] = config.get('guest_labels', {})

    # Scan each Proxmox host
    for host_cfg in config['proxmox_hosts']:
        try:
            result = scan_proxmox_host(host_cfg, ssh_config, scan_id, errors_list, scan_options)
            all_results.append(result)
        except Exception as e:
            errors_list.append({
                'scan_id': scan_id,
                'host_ip': host_cfg['ip'],
                'component': 'Proxmox-Scan',
                'error_message': f"Fatal error scanning {host_cfg['ip']}: {str(e)}",
                'error_detail': traceback.format_exc()
            })

    # Scan Home Assistant instances
    for ha_cfg in config.get('homeassistant', []):
        try:
            ha_result = scan_homeassistant(ha_cfg, scan_id, errors_list)
            all_results.append({
                'host': None, 'vms': [], 'lxcs': [],
                'docker': ha_result.get('docker', []),
                'storage': [], 'network': []
            })
        except Exception as e:
            errors_list.append({
                'scan_id': scan_id,
                'host_ip': ha_cfg.get('ip', '?'),
                'component': 'HomeAssistant',
                'error_message': f"HA scan failed: {str(e)}",
                'error_detail': traceback.format_exc()
            })

    # Also scan Docker on localhost (this container)
    print("  Scanning Docker on localhost...")
    try:
        import subprocess
        docker_check = subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'],
                                      capture_output=True, text=True, timeout=10)
        if docker_check.returncode == 0:
            docker_ps = subprocess.run(
                ['docker', 'ps', '-a', '--format',
                 '{"id":"{{.ID}}","name":"{{.Names}}","image":"{{.Image}}","status":"{{.Status}}","state":"{{.State}}","ports":"{{.Ports}}","created":"{{.CreatedAt}}","networks":"{{.Networks}}","mounts":"{{.Mounts}}"}'],
                capture_output=True, text=True, timeout=10
            )
            if docker_ps.stdout.strip():
                import socket
                hostname = socket.gethostname()
                local_ip = '192.168.178.89'
                for line in docker_ps.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            c = json.loads(line.strip())
                            # Check if this container is already captured from Proxmox host scan
                            all_results.append({
                                'host': None, 'vms': [], 'lxcs': [],
                                'docker': [{
                                    'host_ip': local_ip,
                                    'host_name': hostname,
                                    'container_id': c.get('id', ''),
                                    'name': c.get('name', ''),
                                    'image': c.get('image', ''),
                                    'status': c.get('status', ''),
                                    'state': c.get('state', ''),
                                    'ports': c.get('ports', ''),
                                    'created_at': c.get('created', ''),
                                    'networks': c.get('networks', ''),
                                    'mounts': c.get('mounts', ''),
                                }],
                                'storage': [], 'network': []
                            })
                        except json.JSONDecodeError:
                            pass
    except Exception as e:
        errors_list.append({
            'scan_id': scan_id,
            'host_ip': '127.0.0.1',
            'component': 'Docker-Local',
            'error_message': f"Local Docker scan failed: {str(e)}",
            'error_detail': traceback.format_exc()
        })

    # Save to database
    print("  Saving results to database...")
    total_vms, total_lxcs, total_docker = save_to_database(db, scan_id, all_results, errors_list)

    # Update scan run
    duration = int(time.time() - start_time)
    hosts_scanned = sum(1 for r in all_results if r.get('host'))
    cursor = db.cursor()
    cursor.execute("""
        UPDATE scan_runs SET
            finished_at = NOW(),
            status = 'completed',
            hosts_scanned = %s,
            vms_found = %s,
            lxc_found = %s,
            docker_found = %s,
            errors_count = %s,
            duration_seconds = %s
        WHERE id = %s
    """, (hosts_scanned, total_vms, total_lxcs, total_docker,
          len(errors_list), duration, scan_id))
    cursor.close()

    # Cleanup old scans
    max_scans = scan_options.get('max_old_scans', 50)
    cleanup_old_scans(db, max_scans)

    db.close()

    print(f"\n  Scan completed in {duration}s")
    print(f"  Hosts: {hosts_scanned} | VMs: {total_vms} | LXC: {total_lxcs} | Docker: {total_docker} | Errors: {len(errors_list)}")
    print("=" * 60)

    return 0 if not errors_list else 1


if __name__ == '__main__':
    sys.exit(main())
