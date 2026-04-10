<?php
header('Content-Type: application/json; charset=utf-8');
require __DIR__ . '/db.php';

$action = $_GET['action'] ?? '';

try {
    switch ($action) {

        /* ── Dashboard summary (latest scan) ── */
        case 'dashboard':
            $scan = $pdo->query("SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1")->fetch();
            if (!$scan) {
                echo json_encode(['success' => true, 'data' => null]);
                exit;
            }
            $sid = $scan['id'];

            $hosts = $pdo->prepare("SELECT * FROM proxmox_hosts WHERE scan_id = ?");
            $hosts->execute([$sid]);

            $vms = $pdo->prepare("SELECT * FROM virtual_machines WHERE scan_id = ? ORDER BY host_ip, vmid");
            $vms->execute([$sid]);

            $lxcs = $pdo->prepare("SELECT * FROM lxc_containers WHERE scan_id = ? ORDER BY host_ip, vmid");
            $lxcs->execute([$sid]);

            $docker = $pdo->prepare("SELECT * FROM docker_containers WHERE scan_id = ? ORDER BY host_ip, name");
            $docker->execute([$sid]);

            $storage = $pdo->prepare("SELECT * FROM storage_info WHERE scan_id = ? ORDER BY host_ip, storage_name");
            $storage->execute([$sid]);

            $network = $pdo->prepare("SELECT * FROM network_info WHERE scan_id = ? ORDER BY host_ip, interface_name");
            $network->execute([$sid]);

            $errors = $pdo->prepare("SELECT * FROM scan_errors WHERE scan_id = ? ORDER BY occurred_at DESC");
            $errors->execute([$sid]);

            $networkHosts = $pdo->prepare("SELECT * FROM network_hosts WHERE scan_id = ? ORDER BY INET_ATON(ip_address)");
            $networkHosts->execute([$sid]);

            $networkTopology = $pdo->prepare("SELECT * FROM network_topology WHERE scan_id = ? LIMIT 1");
            $networkTopology->execute([$sid]);

            $serviceScan = $pdo->prepare("SELECT * FROM service_scan WHERE scan_id = ? ORDER BY INET_ATON(ip_address), port");
            $serviceScan->execute([$sid]);

            echo json_encode([
                'success' => true,
                'data' => [
                    'scan' => $scan,
                    'hosts' => $hosts->fetchAll(),
                    'vms' => $vms->fetchAll(),
                    'lxcs' => $lxcs->fetchAll(),
                    'docker' => $docker->fetchAll(),
                    'storage' => $storage->fetchAll(),
                    'network' => $network->fetchAll(),
                    'errors' => $errors->fetchAll(),
                    'network_hosts' => $networkHosts->fetchAll(),
                    'network_topology' => $networkTopology->fetch() ?: null,
                    'service_scan' => $serviceScan->fetchAll(),
                ]
            ]);
            break;

        /* ── Scan history ── */
        case 'scans':
            $scans = $pdo->query("SELECT * FROM scan_runs ORDER BY id DESC LIMIT 50")->fetchAll();
            echo json_encode(['success' => true, 'data' => $scans]);
            break;

        /* ── Get specific scan ── */
        case 'scan':
            $id = (int)($_GET['id'] ?? 0);
            if (!$id) {
                echo json_encode(['error' => 'Missing scan ID']);
                exit;
            }
            $scan = $pdo->prepare("SELECT * FROM scan_runs WHERE id = ?");
            $scan->execute([$id]);
            $scan = $scan->fetch();
            if (!$scan) {
                echo json_encode(['error' => 'Scan not found']);
                exit;
            }

            $hosts = $pdo->prepare("SELECT * FROM proxmox_hosts WHERE scan_id = ?");
            $hosts->execute([$id]);
            $vms = $pdo->prepare("SELECT * FROM virtual_machines WHERE scan_id = ? ORDER BY host_ip, vmid");
            $vms->execute([$id]);
            $lxcs = $pdo->prepare("SELECT * FROM lxc_containers WHERE scan_id = ? ORDER BY host_ip, vmid");
            $lxcs->execute([$id]);
            $docker = $pdo->prepare("SELECT * FROM docker_containers WHERE scan_id = ? ORDER BY host_ip, name");
            $docker->execute([$id]);
            $storage = $pdo->prepare("SELECT * FROM storage_info WHERE scan_id = ? ORDER BY host_ip, storage_name");
            $storage->execute([$id]);
            $network = $pdo->prepare("SELECT * FROM network_info WHERE scan_id = ? ORDER BY host_ip, interface_name");
            $network->execute([$id]);
            $errors = $pdo->prepare("SELECT * FROM scan_errors WHERE scan_id = ? ORDER BY occurred_at DESC");
            $errors->execute([$id]);

            $networkHosts = $pdo->prepare("SELECT * FROM network_hosts WHERE scan_id = ? ORDER BY INET_ATON(ip_address)");
            $networkHosts->execute([$id]);

            $networkTopology = $pdo->prepare("SELECT * FROM network_topology WHERE scan_id = ? LIMIT 1");
            $networkTopology->execute([$id]);

            $serviceScan2 = $pdo->prepare("SELECT * FROM service_scan WHERE scan_id = ? ORDER BY INET_ATON(ip_address), port");
            $serviceScan2->execute([$id]);

            echo json_encode([
                'success' => true,
                'data' => [
                    'scan' => $scan,
                    'hosts' => $hosts->fetchAll(),
                    'vms' => $vms->fetchAll(),
                    'lxcs' => $lxcs->fetchAll(),
                    'docker' => $docker->fetchAll(),
                    'storage' => $storage->fetchAll(),
                    'network' => $network->fetchAll(),
                    'errors' => $errors->fetchAll(),
                    'network_hosts' => $networkHosts->fetchAll(),
                    'network_topology' => $networkTopology->fetch() ?: null,
                    'service_scan' => $serviceScan2->fetchAll(),
                ]
            ]);
            break;

        /* ── Trigger new scan ── */
        case 'trigger_scan':
            $scannerPath = __DIR__ . '/scanner/venv/bin/python';
            $scriptPath = __DIR__ . '/scanner/scan.py';
            $logPath = '/tmp/systemscan_last.log';
            $pidFile = '/tmp/systemscan.pid';
            // -u = unbuffered, PID in Datei für Cancel
            $cmd = "$scannerPath -u $scriptPath > $logPath 2>&1 & echo \$! > $pidFile";
            exec($cmd);
            echo json_encode(['success' => true, 'message' => 'Scan gestartet']);
            break;

        /* ── Cancel running scan ── */
        case 'cancel_scan':
            $pidFile = '/tmp/systemscan.pid';
            $killed = false;
            if (file_exists($pidFile)) {
                $pid = (int)trim(file_get_contents($pidFile));
                if ($pid > 0) {
                    exec("kill -- -$(ps -o pgid= -p $pid 2>/dev/null | tr -d ' ') 2>/dev/null");
                    exec("kill $pid 2>/dev/null");
                    exec("pkill -P $pid 2>/dev/null");
                    @unlink($pidFile);
                    $killed = true;
                }
            }
            // Scan-Run als abgebrochen markieren
            $pdo->exec("UPDATE scan_runs SET status='failed', finished_at=NOW() WHERE status='running'");
            file_put_contents('/tmp/systemscan_last.log', "\n\n[SCAN ABGEBROCHEN]\n", FILE_APPEND);
            echo json_encode(['success' => true, 'killed' => $killed]);
            break;

        /* ── Get scan log ── */
        case 'scan_log':
            $logPath = '/tmp/systemscan_last.log';
            $log = file_exists($logPath) ? file_get_contents($logPath) : 'Kein Log vorhanden';
            echo json_encode(['success' => true, 'data' => $log]);
            break;

        /* ── Scan status (running or not) ── */
        case 'scan_status':
            $scan = $pdo->query("SELECT id, status, started_at FROM scan_runs ORDER BY id DESC LIMIT 1")->fetch();
            echo json_encode([
                'success' => true,
                'running' => $scan && $scan['status'] === 'running',
                'scan_id' => $scan ? (int)$scan['id'] : null,
            ]);
            break;

        /* ── Comparison of two scans ── */
        case 'compare':
            $id1 = (int)($_GET['id1'] ?? 0);
            $id2 = (int)($_GET['id2'] ?? 0);
            if (!$id1 || !$id2) {
                echo json_encode(['error' => 'Two scan IDs required']);
                exit;
            }

            $getVms = function($id) use ($pdo) {
                $st = $pdo->prepare("SELECT vmid, name, status, host_ip FROM virtual_machines WHERE scan_id = ?");
                $st->execute([$id]);
                return $st->fetchAll();
            };
            $getLxcs = function($id) use ($pdo) {
                $st = $pdo->prepare("SELECT vmid, name, status, host_ip FROM lxc_containers WHERE scan_id = ?");
                $st->execute([$id]);
                return $st->fetchAll();
            };

            echo json_encode([
                'success' => true,
                'data' => [
                    'scan1_vms' => $getVms($id1),
                    'scan2_vms' => $getVms($id2),
                    'scan1_lxcs' => $getLxcs($id1),
                    'scan2_lxcs' => $getLxcs($id2),
                ]
            ]);
            break;

        default:
            echo json_encode(['error' => 'Unknown action: ' . $action]);
            break;
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}
