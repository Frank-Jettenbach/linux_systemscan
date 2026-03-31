(() => {
    'use strict';

    /* ── State ── */
    let data = null;
    let activeSection = 'overview';
    let filterHost = null;
    let searchQuery = '';

    /* ── DOM refs ── */
    const $ = s => document.querySelector(s);
    const $$ = s => document.querySelectorAll(s);
    const contentArea = $('#contentArea');
    const loading = $('#loading');
    const scanInfo = $('#scanInfo');
    const errorBadge = $('#errorBadge');
    const toast = $('#toast');
    const searchInput = $('#searchInput');
    const searchClear = $('#searchClear');
    const searchKbd = $('.search-kbd');

    /* ── Helpers ── */
    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
    }

    function formatUptime(seconds) {
        if (!seconds) return '-';
        const d = Math.floor(seconds / 86400);
        const h = Math.floor((seconds % 86400) / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        if (d > 0) return `${d}d ${h}h`;
        if (h > 0) return `${h}h ${m}m`;
        return `${m}m`;
    }

    function formatDate(dt) {
        if (!dt) return '-';
        const d = new Date(dt);
        return d.toLocaleDateString('de-DE') + ' ' + d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
    }

    function pct(used, total) {
        if (!total) return 0;
        return Math.round((used / total) * 100);
    }

    function progressColor(p) {
        if (p >= 90) return 'red';
        if (p >= 70) return 'yellow';
        return 'green';
    }

    function statusBadge(status) {
        const s = (status || '').toLowerCase();
        let cls = 'badge-stopped';
        if (s === 'running') cls = 'badge-running';
        else if (s === 'online') cls = 'badge-online';
        else if (s === 'paused') cls = 'badge-paused';
        else if (s === 'exited') cls = 'badge-exited';
        else if (s === 'created') cls = 'badge-created';
        else if (s === 'update_available') cls = 'badge-update_available';
        else if (s === 'unavailable') cls = 'badge-unavailable';
        return `<span class="badge ${cls}">${esc(status)}</span>`;
    }

    function esc(s) {
        if (s === null || s === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(s);
        return div.innerHTML;
    }

    function linkIp(ip, port) {
        if (!ip) return '-';
        const escaped = esc(ip);
        const proto = port === 8006 ? 'https' : 'http';
        const href = port ? `${proto}://${escaped}:${port}` : `http://${escaped}`;
        return `<a href="${href}" target="_blank" class="ip-link">${escaped}</a>`;
    }

    function autoLinkIps(text) {
        if (!text) return '-';
        const escaped = esc(text);
        return escaped.replace(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g,
            '<a href="http://$1" target="_blank" class="ip-link">$1</a>');
    }

    function showToast(msg, isError) {
        toast.textContent = msg;
        toast.className = 'toast show' + (isError ? ' error' : '');
        setTimeout(() => { toast.className = 'toast'; }, 3000);
    }

    /* ── Navigation helper ── */
    function navigateTo(section) {
        activeSection = section;
        searchQuery = '';
        searchInput.value = '';
        searchClear.style.display = 'none';
        if (searchKbd) searchKbd.style.display = '';
        $$('.nav-item').forEach(e => {
            e.classList.toggle('active', e.dataset.section === section);
        });
        renderSection();
    }

    /* ── Fuzzy Search ── */
    function levenshtein(a, b) {
        const m = a.length, n = b.length;
        const dp = Array.from({length: m + 1}, () => new Array(n + 1).fill(0));
        for (let i = 0; i <= m; i++) dp[i][0] = i;
        for (let j = 0; j <= n; j++) dp[0][j] = j;
        for (let i = 1; i <= m; i++) {
            for (let j = 1; j <= n; j++) {
                dp[i][j] = a[i-1] === b[j-1]
                    ? dp[i-1][j-1]
                    : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
            }
        }
        return dp[m][n];
    }

    function fuzzyScore(query, text) {
        if (!text) return 0;
        const q = query.toLowerCase();
        const t = text.toLowerCase();
        // Exact substring match
        if (t.includes(q)) return 100;
        // Word-level matching
        const words = q.split(/\s+/);
        let totalScore = 0;
        for (const w of words) {
            if (!w) continue;
            if (t.includes(w)) {
                totalScore += 80;
                continue;
            }
            // Levenshtein on individual tokens in text
            const tokens = t.split(/[\s\-_./]+/);
            let bestWord = 0;
            for (const tok of tokens) {
                if (!tok) continue;
                const dist = levenshtein(w, tok.substring(0, w.length + 2));
                const maxLen = Math.max(w.length, tok.length);
                const sim = maxLen > 0 ? (1 - dist / maxLen) : 0;
                if (sim >= 0.6) bestWord = Math.max(bestWord, sim * 60);
            }
            totalScore += bestWord;
        }
        return totalScore / words.filter(w => w).length;
    }

    function buildSearchIndex() {
        if (!data) return [];
        const items = [];

        // Hosts
        (data.hosts || []).forEach(h => {
            items.push({
                type: 'host', section: 'hosts', icon: '&#9881;',
                title: h.hostname,
                searchText: [h.hostname, h.ip_address, h.pve_version, h.node_name, h.kernel_version].join(' '),
                meta: `${h.ip_address} | PVE ${h.pve_version} | ${h.cpu_count} CPU | ${formatBytes(h.mem_total)} RAM`,
                status: h.status,
                data: h
            });
        });

        // VMs
        (data.vms || []).forEach(v => {
            items.push({
                type: 'vm', section: 'vms', icon: '&#128187;',
                title: `${v.name} (VMID ${v.vmid})`,
                searchText: [v.name, v.vmid, v.host_ip, v.ip_address, v.node_name, v.tags, v.status].join(' '),
                meta: `Host: ${v.host_ip} | ${formatBytes(v.mem_total)} RAM | ${v.cpu_count} CPU${v.ip_address ? ' | IP: ' + v.ip_address : ''}`,
                status: v.is_template == 1 ? 'template' : v.status,
                data: v
            });
        });

        // LXCs
        (data.lxcs || []).forEach(l => {
            items.push({
                type: 'lxc', section: 'lxc', icon: '&#128230;',
                title: `${l.name} (VMID ${l.vmid})`,
                searchText: [l.name, l.vmid, l.host_ip, l.ip_address, l.node_name, l.status].join(' '),
                meta: `Host: ${l.host_ip} | ${formatBytes(l.mem_total)} RAM${l.ip_address ? ' | IP: ' + l.ip_address : ''}`,
                status: l.status,
                data: l
            });
        });

        // Docker
        (data.docker || []).forEach(d => {
            items.push({
                type: 'docker', section: 'docker', icon: '&#128051;',
                title: d.name,
                searchText: [d.name, d.image, d.host_ip, d.host_name, d.ports, d.networks, d.state, d.status].join(' '),
                meta: `${d.host_name} (${d.host_ip}) | ${d.image}${d.ports ? ' | ' + d.ports : ''}`,
                status: d.state,
                data: d
            });
        });

        // Storage
        (data.storage || []).forEach(s => {
            const hostInfo = (data.hosts || []).find(h => h.ip_address === s.host_ip);
            items.push({
                type: 'storage', section: 'storage', icon: '&#128190;',
                title: s.storage_name,
                searchText: [s.storage_name, s.storage_type, s.content, s.host_ip, hostInfo?.hostname].join(' '),
                meta: `${hostInfo?.hostname || s.host_ip} | ${s.storage_type} | ${formatBytes(s.used_bytes)} / ${formatBytes(s.total_bytes)}`,
                status: s.status,
                data: s
            });
        });

        // Network
        (data.network || []).forEach(n => {
            items.push({
                type: 'network', section: 'network', icon: '&#127760;',
                title: n.interface_name,
                searchText: [n.interface_name, n.ip_address, n.host_ip, n.host_name, n.type, n.bridge_ports].join(' '),
                meta: `${n.host_name || n.host_ip} | ${n.type}${n.ip_address ? ' | ' + n.ip_address : ''}`,
                status: n.active == 1 ? 'online' : 'stopped',
                data: n
            });
        });

        // Network Hosts (nmap)
        (data.network_hosts || []).forEach(h => {
            items.push({
                type: 'network_host', section: 'network', icon: '&#128257;',
                title: h.hostname || h.ip_address,
                searchText: [h.ip_address, h.hostname, h.category, h.description, h.mac_address, h.vendor].join(' '),
                meta: `${h.ip_address}${h.hostname ? ' · ' + h.hostname : ''} | ${h.category || 'Unbekannt'}${h.description ? ' · ' + h.description : ''}`,
                status: h.status,
                data: h
            });
        });

        // Errors
        (data.errors || []).forEach(e => {
            items.push({
                type: 'error', section: 'errors', icon: '&#9888;',
                title: e.error_message,
                searchText: [e.error_message, e.host_ip, e.component, e.error_detail].join(' '),
                meta: `${e.host_ip || '?'} | ${e.component}`,
                status: 'error',
                data: e
            });
        });

        return items;
    }

    function performSearch(query) {
        const index = buildSearchIndex();
        const results = [];
        for (const item of index) {
            const score = fuzzyScore(query, item.searchText);
            if (score >= 30) {
                results.push({...item, score});
            }
        }
        results.sort((a, b) => b.score - a.score);
        return results;
    }

    function highlightMatch(text, query) {
        if (!text || !query) return esc(text);
        const escaped = esc(text);
        const words = query.toLowerCase().split(/\s+/).filter(w => w.length > 1);
        let result = escaped;
        for (const w of words) {
            const regex = new RegExp(`(${w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
            result = result.replace(regex, '<mark>$1</mark>');
        }
        return result;
    }

    function renderSearch(query) {
        const results = performSearch(query);

        // Group by type
        const groups = {};
        const typeLabels = {
            host: 'Proxmox Hosts', vm: 'Virtual Machines', lxc: 'LXC Container',
            docker: 'Docker / Add-ons', storage: 'Storage', network: 'Netzwerk',
            network_host: 'LAN-Hosts', error: 'Fehler'
        };
        for (const r of results) {
            if (!groups[r.type]) groups[r.type] = [];
            groups[r.type].push(r);
        }

        let html = `
        <div class="search-results-header">
            <h2 class="section-title">Suchergebnisse</h2>
            <span class="search-query">${esc(query)}</span>
            <span class="search-count">${results.length} Treffer</span>
        </div>`;

        if (results.length === 0) {
            html += `<div class="no-data">Keine Ergebnisse f&uuml;r &quot;${esc(query)}&quot; gefunden.</div>`;
            contentArea.innerHTML = html;
            return;
        }

        const typeOrder = ['host', 'vm', 'lxc', 'docker', 'storage', 'network', 'network_host', 'error'];
        for (const type of typeOrder) {
            const group = groups[type];
            if (!group || group.length === 0) continue;

            html += `<div class="search-result-group">
                <h3>${typeLabels[type] || type} (${group.length})</h3>`;

            for (const r of group) {
                html += `
                <div class="search-result-item" data-section="${r.section}" onclick="window._navigateTo('${r.section}')">
                    <div class="search-result-icon">${r.icon}</div>
                    <div class="search-result-body">
                        <div class="search-result-title">${highlightMatch(r.title, query)}</div>
                        <div class="search-result-meta">${highlightMatch(r.meta, query)}</div>
                    </div>
                    <div class="search-result-badge">${statusBadge(r.status)}</div>
                </div>`;
            }
            html += `</div>`;
        }

        contentArea.innerHTML = html;
    }

    // Expose for onclick
    window._navigateTo = function(section) {
        navigateTo(section);
    };

    /* ── API calls ── */
    async function api(action, params = {}) {
        const url = new URL(BASE_URL + '/api.php', window.location.origin);
        url.searchParams.set('action', action);
        for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
        const resp = await fetch(url);
        return resp.json();
    }

    async function loadDashboard() {
        loading.style.display = 'flex';
        contentArea.innerHTML = '';
        try {
            const result = await api('dashboard');
            if (result.success && result.data) {
                data = result.data;
                updateScanInfo();
                updateErrorBadge();
                buildHostFilter();
                renderSection();
            } else {
                contentArea.innerHTML = '<div class="no-data">Keine Scan-Daten vorhanden. Starte einen neuen Scan.</div>';
            }
        } catch (e) {
            contentArea.innerHTML = `<div class="no-data">Fehler beim Laden: ${esc(e.message)}</div>`;
        }
        loading.style.display = 'none';
    }

    function updateScanInfo() {
        if (!data || !data.scan) return;
        const s = data.scan;
        scanInfo.innerHTML = `Scan #${s.id} &middot; ${formatDate(s.finished_at)} &middot; ${s.duration_seconds}s`;
    }

    function updateErrorBadge() {
        const count = data?.errors?.length || 0;
        if (count > 0) {
            errorBadge.textContent = count;
            errorBadge.style.display = 'inline';
        } else {
            errorBadge.style.display = 'none';
        }
    }

    function buildHostFilter() {
        if (!data?.hosts) return;
        const list = $('#hostFilterList');
        const section = $('#hostFilter');
        if (data.hosts.length > 1) {
            section.style.display = 'block';
            let html = `<li class="filter-item ${!filterHost ? 'active' : ''}" data-host="">
                <span class="filter-dot" style="background:var(--accent)"></span> Alle Hosts
            </li>`;
            data.hosts.forEach(h => {
                html += `<li class="filter-item ${filterHost === h.ip_address ? 'active' : ''}" data-host="${esc(h.ip_address)}">
                    <span class="filter-dot"></span> ${esc(h.hostname)}
                    <span style="font-size:11px;color:var(--text-muted);margin-left:auto">${esc(h.ip_address)}</span>
                </li>`;
            });
            list.innerHTML = html;
            list.querySelectorAll('.filter-item').forEach(el => {
                el.addEventListener('click', () => {
                    filterHost = el.dataset.host || null;
                    list.querySelectorAll('.filter-item').forEach(e => e.classList.remove('active'));
                    el.classList.add('active');
                    renderSection();
                });
            });
        } else {
            section.style.display = 'none';
        }
    }

    function filterByHost(arr) {
        if (!filterHost) return arr;
        return arr.filter(item => item.host_ip === filterHost);
    }

    /* ── Render functions ── */
    function renderSection() {
        if (!data) return;
        if (searchQuery) {
            renderSearch(searchQuery);
            return;
        }
        switch (activeSection) {
            case 'overview': renderOverview(); break;
            case 'hosts': renderHosts(); break;
            case 'vms': renderVMs(); break;
            case 'lxc': renderLXCs(); break;
            case 'docker': renderDocker(); break;
            case 'storage': renderStorage(); break;
            case 'network': renderNetwork(); break;
            case 'errors': renderErrors(); break;
        }
    }

    function renderOverview() {
        const s = data.scan;
        const runningVMs = data.vms.filter(v => v.status === 'running').length;
        const stoppedVMs = data.vms.filter(v => v.status === 'stopped').length;
        const runningLXC = data.lxcs.filter(l => l.status === 'running').length;
        const stoppedLXC = data.lxcs.filter(l => l.status === 'stopped').length;
        const runningDocker = data.docker.filter(d => d.state === 'running').length;
        const stoppedDocker = data.docker.filter(d => d.state !== 'running').length;
        const storageCount = data.storage.length;
        const networkCount = data.network.length;

        let html = `
        <div class="section-header">
            <div>
                <h2 class="section-title">Dashboard</h2>
                <p class="section-subtitle">Infrastruktur-Uebersicht - Letzter Scan: ${formatDate(s.finished_at)}</p>
            </div>
        </div>

        <div class="dashboard-grid">
            <div class="stat-card clickable" data-goto="hosts">
                <div class="stat-label">Proxmox Hosts</div>
                <div class="stat-value accent">${s.hosts_scanned}</div>
                <div class="stat-sub">Alle online</div>
            </div>
            <div class="stat-card clickable" data-goto="vms">
                <div class="stat-label">Virtual Machines</div>
                <div class="stat-value">${s.vms_found}</div>
                <div class="stat-sub">${runningVMs} running, ${stoppedVMs} stopped</div>
            </div>
            <div class="stat-card clickable" data-goto="lxc">
                <div class="stat-label">LXC Container</div>
                <div class="stat-value">${s.lxc_found}</div>
                <div class="stat-sub">${runningLXC} running, ${stoppedLXC} stopped</div>
            </div>
            <div class="stat-card clickable" data-goto="docker">
                <div class="stat-label">Docker / Add-ons</div>
                <div class="stat-value">${s.docker_found}</div>
                <div class="stat-sub">${runningDocker} running, ${stoppedDocker} andere</div>
            </div>
            <div class="stat-card clickable" data-goto="storage">
                <div class="stat-label">Storage Pools</div>
                <div class="stat-value">${storageCount}</div>
                <div class="stat-sub">${data.storage.filter(x=>x.shared==1).length} shared</div>
            </div>
            <div class="stat-card clickable" data-goto="network">
                <div class="stat-label">LAN-Hosts</div>
                <div class="stat-value accent">${(data.network_hosts || []).length}</div>
                <div class="stat-sub">${(data.network || []).filter(x=>x.active==1).length} PVE-Interfaces aktiv</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Scan-Dauer</div>
                <div class="stat-value">${s.duration_seconds}s</div>
                <div class="stat-sub">Scan #${s.id}</div>
            </div>
            <div class="stat-card clickable" data-goto="errors">
                <div class="stat-label">Fehler</div>
                <div class="stat-value ${s.errors_count > 0 ? 'danger' : 'success'}">${s.errors_count}</div>
                <div class="stat-sub">${s.errors_count > 0 ? 'Fehler beim Scan' : 'Keine Fehler'}</div>
            </div>
        </div>`;

        // Host overview cards
        html += `<h3 style="margin-bottom:14px;font-size:16px;">Proxmox Hosts</h3><div class="host-grid">`;
        data.hosts.forEach(h => {
            const memPct = pct(h.mem_used, h.mem_total);
            const diskPct = pct(h.disk_used, h.disk_total);
            const cpuPct = Math.round((h.cpu_usage || 0) * 100);
            const hostVMs = data.vms.filter(v => v.host_ip === h.ip_address);
            const hostLXCs = data.lxcs.filter(l => l.host_ip === h.ip_address);
            html += `
            <div class="host-card">
                <div class="host-card-header">
                    <div>
                        <div class="host-name">${esc(h.hostname)}</div>
                        <div class="host-ip">${linkIp(h.ip_address, 8006)} &middot; PVE ${esc(h.pve_version)}</div>
                    </div>
                    ${statusBadge(h.status)}
                </div>
                <div class="host-meta">
                    <div class="meta-item">
                        <div class="meta-label">CPU (${h.cpu_count} Kerne)</div>
                        <div class="meta-value">${cpuPct}%</div>
                        <div class="progress-bar"><div class="progress-fill ${progressColor(cpuPct)}" style="width:${cpuPct}%"></div></div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">RAM</div>
                        <div class="meta-value">${formatBytes(h.mem_used)} / ${formatBytes(h.mem_total)}</div>
                        <div class="progress-bar"><div class="progress-fill ${progressColor(memPct)}" style="width:${memPct}%"></div></div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Disk</div>
                        <div class="meta-value">${formatBytes(h.disk_used)} / ${formatBytes(h.disk_total)}</div>
                        <div class="progress-bar"><div class="progress-fill ${progressColor(diskPct)}" style="width:${diskPct}%"></div></div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Uptime</div>
                        <div class="meta-value">${formatUptime(h.uptime_seconds)}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">VMs</div>
                        <div class="meta-value">${hostVMs.length} (${hostVMs.filter(v=>v.status==='running').length} aktiv)</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">LXC</div>
                        <div class="meta-value">${hostLXCs.length} (${hostLXCs.filter(l=>l.status==='running').length} aktiv)</div>
                    </div>
                </div>
            </div>`;
        });
        html += `</div>`;

        // Quick VM/LXC table for running guests
        const runningGuests = [
            ...data.vms.filter(v => v.status === 'running').map(v => ({...v, gtype: 'VM'})),
            ...data.lxcs.filter(l => l.status === 'running').map(l => ({...l, gtype: 'LXC'}))
        ];

        if (runningGuests.length) {
            html += `<h3 style="margin:20px 0 14px;font-size:16px;">Laufende Maschinen</h3>
            <div class="table-container"><table>
                <thead><tr><th>Typ</th><th>VMID</th><th>Name</th><th>Host</th><th>CPU</th><th>RAM</th><th>IP</th><th>Uptime</th></tr></thead>
                <tbody>`;
            runningGuests.forEach(g => {
                const memPct = pct(g.mem_used, g.mem_total);
                html += `<tr>
                    <td><span class="badge ${g.gtype === 'VM' ? 'badge-created' : 'badge-online'}">${g.gtype}</span></td>
                    <td class="mono">${g.vmid}</td>
                    <td class="name-col">${esc(g.name)}</td>
                    <td class="mono">${linkIp(g.host_ip, 8006)}</td>
                    <td>${Math.round((g.cpu_usage||0)*100)}% (${g.cpu_count}C)</td>
                    <td>${formatBytes(g.mem_used)} / ${formatBytes(g.mem_total)} (${memPct}%)</td>
                    <td class="mono">${linkIp(g.ip_address)}</td>
                    <td>${formatUptime(g.uptime_seconds)}</td>
                </tr>`;
            });
            html += `</tbody></table></div>`;
        }

        contentArea.innerHTML = html;

        // Bind clickable stat cards
        contentArea.querySelectorAll('.stat-card.clickable').forEach(card => {
            card.addEventListener('click', () => {
                navigateTo(card.dataset.goto);
            });
        });
    }

    function renderHosts() {
        let html = `<div class="section-header">
            <h2 class="section-title">Proxmox Hosts</h2>
        </div><div class="host-grid">`;

        data.hosts.forEach(h => {
            const memPct = pct(h.mem_used, h.mem_total);
            const diskPct = pct(h.disk_used, h.disk_total);
            const cpuPct = Math.round((h.cpu_usage || 0) * 100);
            html += `
            <div class="host-card">
                <div class="host-card-header">
                    <div>
                        <div class="host-name">${esc(h.hostname)}</div>
                        <div class="host-ip">${linkIp(h.ip_address, 8006)}</div>
                    </div>
                    ${statusBadge(h.status)}
                </div>
                <div class="host-meta">
                    <div class="meta-item">
                        <div class="meta-label">PVE Version</div>
                        <div class="meta-value">${esc(h.pve_version)}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Kernel</div>
                        <div class="meta-value">${esc(h.kernel_version) || '-'}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">CPU (${h.cpu_count} Kerne)</div>
                        <div class="meta-value">${cpuPct}%</div>
                        <div class="progress-bar"><div class="progress-fill ${progressColor(cpuPct)}" style="width:${cpuPct}%"></div></div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">RAM</div>
                        <div class="meta-value">${formatBytes(h.mem_used)} / ${formatBytes(h.mem_total)} (${memPct}%)</div>
                        <div class="progress-bar"><div class="progress-fill ${progressColor(memPct)}" style="width:${memPct}%"></div></div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Disk</div>
                        <div class="meta-value">${formatBytes(h.disk_used)} / ${formatBytes(h.disk_total)} (${diskPct}%)</div>
                        <div class="progress-bar"><div class="progress-fill ${progressColor(diskPct)}" style="width:${diskPct}%"></div></div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Uptime</div>
                        <div class="meta-value">${formatUptime(h.uptime_seconds)}</div>
                    </div>
                </div>
            </div>`;
        });
        html += `</div>`;
        contentArea.innerHTML = html;
    }

    function renderVMs() {
        const vms = filterByHost(data.vms);
        let html = `<div class="section-header">
            <div>
                <h2 class="section-title">Virtual Machines (QEMU)</h2>
                <p class="section-subtitle">${vms.length} VMs gefunden</p>
            </div>
        </div>
        <div class="table-container"><table>
            <thead><tr><th>VMID</th><th>Name</th><th>Host</th><th>Status</th><th>CPU</th><th>RAM</th><th>Disk</th><th>Netzwerk I/O</th><th>IP</th><th>Uptime</th></tr></thead>
            <tbody>`;
        vms.forEach(v => {
            const isTemplate = v.is_template == 1;
            html += `<tr>
                <td class="mono">${v.vmid}</td>
                <td class="name-col">${esc(v.name)} ${isTemplate ? '<span class="badge badge-template">Template</span>' : ''}</td>
                <td class="mono">${linkIp(v.host_ip, 8006)}</td>
                <td>${statusBadge(v.status)}</td>
                <td>${v.status === 'running' ? Math.round((v.cpu_usage||0)*100) + '% (' + v.cpu_count + 'C)' : v.cpu_count + 'C'}</td>
                <td>${formatBytes(v.mem_used)} / ${formatBytes(v.mem_total)}</td>
                <td>${formatBytes(v.disk_total)}</td>
                <td style="font-size:11px">&darr; ${formatBytes(v.net_in)} &uarr; ${formatBytes(v.net_out)}</td>
                <td class="mono">${linkIp(v.ip_address)}</td>
                <td>${formatUptime(v.uptime_seconds)}</td>
            </tr>`;
        });
        html += `</tbody></table></div>`;
        contentArea.innerHTML = html;
    }

    function renderLXCs() {
        const lxcs = filterByHost(data.lxcs);
        let html = `<div class="section-header">
            <div>
                <h2 class="section-title">LXC Container</h2>
                <p class="section-subtitle">${lxcs.length} Container gefunden</p>
            </div>
        </div>
        <div class="table-container"><table>
            <thead><tr><th>VMID</th><th>Name</th><th>Host</th><th>Status</th><th>CPU</th><th>RAM</th><th>Disk</th><th>Netzwerk I/O</th><th>IP</th><th>Uptime</th></tr></thead>
            <tbody>`;
        lxcs.forEach(l => {
            html += `<tr>
                <td class="mono">${l.vmid}</td>
                <td class="name-col">${esc(l.name)}</td>
                <td class="mono">${linkIp(l.host_ip, 8006)}</td>
                <td>${statusBadge(l.status)}</td>
                <td>${l.status === 'running' ? Math.round((l.cpu_usage||0)*100) + '% (' + l.cpu_count + 'C)' : l.cpu_count + 'C'}</td>
                <td>${formatBytes(l.mem_used)} / ${formatBytes(l.mem_total)}</td>
                <td>${formatBytes(l.disk_used)} / ${formatBytes(l.disk_total)}</td>
                <td style="font-size:11px">&darr; ${formatBytes(l.net_in)} &uarr; ${formatBytes(l.net_out)}</td>
                <td class="mono">${linkIp(l.ip_address)}</td>
                <td>${formatUptime(l.uptime_seconds)}</td>
            </tr>`;
        });
        html += `</tbody></table></div>`;
        contentArea.innerHTML = html;
    }

    function renderDocker() {
        const docker = filterByHost(data.docker);
        let html = `<div class="section-header">
            <div>
                <h2 class="section-title">Docker / Add-ons</h2>
                <p class="section-subtitle">${docker.length} Container gefunden</p>
            </div>
        </div>`;

        if (docker.length === 0) {
            html += '<div class="no-data">Keine Docker-Container gefunden.</div>';
            contentArea.innerHTML = html;
            return;
        }

        // Group by host
        const byHost = {};
        docker.forEach(d => {
            const key = d.host_ip;
            if (!byHost[key]) byHost[key] = { hostname: d.host_name, containers: [] };
            byHost[key].containers.push(d);
        });

        for (const [ip, group] of Object.entries(byHost)) {
            html += `<h3 style="margin:16px 0 10px;font-size:14px;color:var(--accent)">${esc(group.hostname)} (${linkIp(ip)})</h3>
            <div class="table-container"><table>
                <thead><tr><th>Name</th><th>Image</th><th>Status</th><th>Ports</th><th>Netzwerke</th><th>Erstellt</th></tr></thead>
                <tbody>`;
            group.containers.forEach(c => {
                html += `<tr>
                    <td class="name-col">${esc(c.name)}</td>
                    <td class="mono" style="font-size:11px">${esc(c.image)}</td>
                    <td>${statusBadge(c.state)}<br><span style="font-size:11px;color:var(--text-muted)">${esc(c.status)}</span></td>
                    <td class="mono" style="font-size:11px">${autoLinkIps(c.ports) || '-'}</td>
                    <td>${esc(c.networks)}</td>
                    <td style="font-size:11px">${esc(c.created_at)}</td>
                </tr>`;
            });
            html += `</tbody></table></div>`;
        }

        contentArea.innerHTML = html;
    }

    function renderStorage() {
        const storage = filterByHost(data.storage);
        const totalBytes = storage.reduce((a, s) => a + (s.total_bytes || 0), 0);
        const usedBytes = storage.reduce((a, s) => a + (s.used_bytes || 0), 0);
        const totalPct = pct(usedBytes, totalBytes);
        const sharedCount = storage.filter(s => s.shared == 1).length;

        let html = `<div class="section-header">
            <div>
                <h2 class="section-title">Storage</h2>
                <p class="section-subtitle">${storage.length} Speicher auf ${data.hosts.length} Hosts &middot; ${sharedCount} shared</p>
            </div>
        </div>

        <div class="dashboard-grid" style="margin-bottom:20px">
            <div class="stat-card">
                <div class="stat-label">Gesamt-Kapazit&auml;t</div>
                <div class="stat-value">${formatBytes(totalBytes)}</div>
                <div class="stat-sub">${formatBytes(usedBytes)} belegt (${totalPct}%)</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Frei verf&uuml;gbar</div>
                <div class="stat-value ${totalPct >= 90 ? 'danger' : 'success'}">${formatBytes(totalBytes - usedBytes)}</div>
                <div class="stat-sub">${100 - totalPct}% frei</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Speicher-Pools</div>
                <div class="stat-value accent">${storage.length}</div>
                <div class="stat-sub">${sharedCount} shared, ${storage.length - sharedCount} lokal</div>
            </div>
        </div>`;

        // Group by host
        const byHost = {};
        storage.forEach(s => {
            const key = s.host_ip;
            if (!byHost[key]) byHost[key] = [];
            byHost[key].push(s);
        });

        for (const [ip, stores] of Object.entries(byHost)) {
            const hostInfo = data.hosts.find(h => h.ip_address === ip);
            const hostTotal = stores.reduce((a, s) => a + (s.total_bytes || 0), 0);
            const hostUsed = stores.reduce((a, s) => a + (s.used_bytes || 0), 0);
            const hostPct = pct(hostUsed, hostTotal);

            html += `
            <div class="storage-host-group">
                <div class="storage-host-header">
                    <div class="storage-host-title">
                        <span class="storage-host-icon">&#9881;</span>
                        <span class="storage-host-name">${esc(hostInfo?.hostname || 'Unbekannt')}</span>
                        <span class="storage-host-ip">${linkIp(ip, 8006)}</span>
                        ${hostInfo?.node_name ? `<span class="storage-host-node">Node: ${esc(hostInfo.node_name)}</span>` : ''}
                    </div>
                    <div class="storage-host-summary">
                        <span>${formatBytes(hostUsed)} / ${formatBytes(hostTotal)}</span>
                        <span class="storage-host-pct ${hostPct >= 90 ? 'danger' : hostPct >= 70 ? 'warning' : ''}">${hostPct}% belegt</span>
                    </div>
                </div>
                <div class="progress-bar" style="height:4px;margin-bottom:12px">
                    <div class="progress-fill ${progressColor(hostPct)}" style="width:${hostPct}%"></div>
                </div>
                <div class="table-container"><table>
                    <thead><tr><th>Name</th><th>Typ</th><th>Inhalt</th><th>Belegt</th><th>Gesamt</th><th>Nutzung</th><th>Status</th><th>Shared</th></tr></thead>
                    <tbody>`;

            stores.forEach(s => {
                const usedPct = pct(s.used_bytes, s.total_bytes);
                const contentTags = (s.content || '').split(',').map(c => c.trim()).filter(c => c);
                html += `<tr>
                    <td class="name-col"><strong>${esc(s.storage_name)}</strong></td>
                    <td><span class="badge badge-type">${esc(s.storage_type)}</span></td>
                    <td class="storage-content">${contentTags.map(c => `<span class="content-tag">${esc(c)}</span>`).join(' ')}</td>
                    <td class="mono">${formatBytes(s.used_bytes)}</td>
                    <td class="mono">${formatBytes(s.total_bytes)}</td>
                    <td style="min-width:120px">
                        <div style="display:flex;align-items:center;gap:8px">
                            <div class="progress-bar" style="flex:1;height:6px">
                                <div class="progress-fill ${progressColor(usedPct)}" style="width:${usedPct}%"></div>
                            </div>
                            <span class="mono" style="font-size:11px;min-width:32px">${usedPct}%</span>
                        </div>
                    </td>
                    <td>${statusBadge(s.status)}</td>
                    <td>${s.shared == 1 ? '<span class="badge badge-created">shared</span>' : '<span style="color:var(--text-muted)">lokal</span>'}</td>
                </tr>`;
            });

            html += `</tbody></table></div></div>`;
        }

        contentArea.innerHTML = html;
    }

    let _netSort = { col: 'ip_num', dir: 'asc' };
    let _netCatFilter = '';
    let _netSearch = '';

    function ipToNum(ip) {
        if (!ip) return 0;
        return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
    }

    function renderNetwork() {
        const network = data.network || [];
        const netHosts = data.network_hosts || [];
        const topo = data.network_topology || null;

        // Topology summary cards
        const gatewayIp = topo?.gateway_ip || '';
        const dns1 = topo?.dns_server1 || '';
        const dns2 = topo?.dns_server2 || '';
        const subnet = topo?.subnet || '192.168.178.0/24';
        const nmapCount = topo?.nmap_hosts_found || netHosts.length;

        // Gateway info from HOST_META (if known)
        const gatewayMeta = netHosts.find(h => h.ip_address === gatewayIp);
        const dns1Meta = netHosts.find(h => h.ip_address === dns1);

        let html = `<div class="section-header">
            <div>
                <h2 class="section-title">Netzwerk</h2>
                <p class="section-subtitle">Topologie &middot; ${nmapCount} Hosts im LAN &middot; ${network.filter(x=>x.active==1).length} PVE-Interfaces</p>
            </div>
        </div>

        <div class="dashboard-grid" style="margin-bottom:24px">
            <div class="stat-card">
                <div class="stat-label">Gateway / Router</div>
                <div class="stat-value accent" style="font-size:18px;font-family:monospace">${gatewayIp ? linkIp(gatewayIp) : '-'}</div>
                <div class="stat-sub">${esc(gatewayMeta?.description || '')}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">DNS Server</div>
                <div class="stat-value accent" style="font-size:18px;font-family:monospace">${dns1 ? esc(dns1) : '-'}</div>
                <div class="stat-sub">${dns2 ? 'Fallback: ' + esc(dns2) : ''}&nbsp;</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Subnetz</div>
                <div class="stat-value" style="font-size:18px;font-family:monospace">${esc(subnet)}</div>
                <div class="stat-sub">${esc(topo?.dns_domain || '')}&nbsp;</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Hosts Online</div>
                <div class="stat-value success">${nmapCount}</div>
                <div class="stat-sub">nmap-Scan · ${subnet}</div>
            </div>
        </div>`;

        // Category filter
        const cats = [...new Set(netHosts.map(h => h.category || 'Unbekannt'))].sort();
        const catCounts = {};
        netHosts.forEach(h => { const c = h.category || 'Unbekannt'; catCounts[c] = (catCounts[c]||0)+1; });

        html += `<div class="section-header" style="margin-bottom:12px">
            <h3 class="section-title" style="font-size:16px">LAN-Hosts (${netHosts.length})</h3>
        </div>
        <div class="net-filter-bar" id="netFilterBar">
            <button class="net-cat-btn ${!_netCatFilter ? 'active' : ''}" data-cat="">Alle (${netHosts.length})</button>`;
        for (const cat of cats) {
            html += `<button class="net-cat-btn ${_netCatFilter === cat ? 'active' : ''}" data-cat="${esc(cat)}">${esc(cat)} (${catCounts[cat]})</button>`;
        }
        html += `</div>
        <div style="margin-bottom:12px">
            <input type="text" class="net-search-input" id="netSearchInput" placeholder="IP, Hostname, Beschreibung suchen..." value="${esc(_netSearch)}">
        </div>`;

        // Build sorted/filtered host list
        let hosts = [...netHosts];
        if (_netCatFilter) hosts = hosts.filter(h => (h.category || 'Unbekannt') === _netCatFilter);
        if (_netSearch) {
            const q = _netSearch.toLowerCase();
            hosts = hosts.filter(h =>
                (h.ip_address||'').includes(q) ||
                (h.hostname||'').toLowerCase().includes(q) ||
                (h.description||'').toLowerCase().includes(q) ||
                (h.category||'').toLowerCase().includes(q) ||
                (h.mac_address||'').toLowerCase().includes(q) ||
                (h.vendor||'').toLowerCase().includes(q)
            );
        }

        // Sort
        hosts.sort((a, b) => {
            let va, vb;
            if (_netSort.col === 'ip_num') {
                va = ipToNum(a.ip_address);
                vb = ipToNum(b.ip_address);
            } else if (_netSort.col === 'hostname') {
                va = (a.hostname||'').toLowerCase();
                vb = (b.hostname||'').toLowerCase();
            } else if (_netSort.col === 'category') {
                va = (a.category||'').toLowerCase();
                vb = (b.category||'').toLowerCase();
            } else if (_netSort.col === 'description') {
                va = (a.description||'').toLowerCase();
                vb = (b.description||'').toLowerCase();
            } else if (_netSort.col === 'vendor') {
                va = (a.vendor||'').toLowerCase();
                vb = (b.vendor||'').toLowerCase();
            } else {
                va = vb = 0;
            }
            if (va < vb) return _netSort.dir === 'asc' ? -1 : 1;
            if (va > vb) return _netSort.dir === 'asc' ? 1 : -1;
            return 0;
        });

        function sortTh(col, label) {
            const arrow = _netSort.col === col ? (_netSort.dir === 'asc' ? ' &#9650;' : ' &#9660;') : ' <span style="opacity:0.3">&#9650;</span>';
            return `<th class="sortable-th" data-col="${col}" style="cursor:pointer;user-select:none">${label}${arrow}</th>`;
        }

        const catColors = {
            'Server': 'var(--accent)', 'Infrastruktur': 'var(--purple)',
            'Energie': 'var(--warning)', 'Smart Home': 'var(--success)',
            'Kamera': '#f97316', 'Gerät': 'var(--text-secondary)',
            'Shelly': '#84cc16', 'Drucker': '#ec4899', 'Unbekannt': 'var(--text-muted)'
        };

        html += `<div class="table-container" style="margin-bottom:28px"><table id="netHostsTable">
            <thead><tr>
                ${sortTh('ip_num','IP-Adresse')}
                ${sortTh('hostname','Hostname')}
                ${sortTh('category','Kategorie')}
                ${sortTh('description','Beschreibung')}
                <th>MAC-Adresse</th>
                ${sortTh('vendor','Hersteller')}
            </tr></thead>
            <tbody>`;

        if (hosts.length === 0) {
            html += `<tr><td colspan="6" class="no-data" style="padding:24px">Keine Hosts gefunden.</td></tr>`;
        }
        hosts.forEach(h => {
            const catColor = catColors[h.category] || 'var(--text-muted)';
            html += `<tr>
                <td class="mono">${linkIp(h.ip_address)}</td>
                <td class="mono" style="font-size:12px">${esc(h.hostname) || '-'}</td>
                <td><span style="color:${catColor};font-weight:500;font-size:12px">${esc(h.category||'Unbekannt')}</span></td>
                <td style="font-size:13px;color:var(--text-secondary)">${esc(h.description) || '-'}</td>
                <td class="mono" style="font-size:11px;color:var(--text-muted)">${esc(h.mac_address) || '-'}</td>
                <td style="font-size:12px;color:var(--text-muted)">${esc(h.vendor) || '-'}</td>
            </tr>`;
        });
        html += `</tbody></table></div>`;

        // Proxmox interfaces section
        if (network.length > 0) {
            html += `<div class="section-header" style="margin-bottom:12px">
                <h3 class="section-title" style="font-size:16px">Proxmox Netzwerk-Interfaces</h3>
            </div>`;

            // Group by host
            const byHost = {};
            network.forEach(n => {
                if (!byHost[n.host_ip]) byHost[n.host_ip] = [];
                byHost[n.host_ip].push(n);
            });

            for (const [ip, ifaces] of Object.entries(byHost)) {
                const hostInfo = (data.hosts||[]).find(h => h.ip_address === ip);
                const activeCount = ifaces.filter(i => i.active == 1).length;
                html += `<div style="margin-bottom:8px;display:flex;align-items:center;gap:10px">
                    <span style="font-size:14px;font-weight:600;color:var(--accent)">${esc(hostInfo?.hostname || ip)}</span>
                    <span style="font-size:12px;color:var(--text-muted)">${linkIp(ip, 8006)}</span>
                    ${hostInfo?.gateway ? `<span style="font-size:12px;color:var(--text-secondary)">GW: <code>${esc(hostInfo.gateway)}</code></span>` : ''}
                    ${hostInfo?.dns_servers ? `<span style="font-size:12px;color:var(--text-secondary)">DNS: <code>${esc(hostInfo.dns_servers)}</code></span>` : ''}
                </div>
                <div class="table-container" style="margin-bottom:20px"><table>
                    <thead><tr><th>Interface</th><th>Typ</th><th>IP / CIDR</th><th>Netmask</th><th>Gateway</th><th>MAC</th><th>MTU</th><th>Aktiv</th><th>Bridge Ports</th></tr></thead>
                    <tbody>`;
                ifaces.forEach(n => {
                    const displayIp = n.cidr || n.ip_address || '-';
                    html += `<tr>
                        <td class="name-col">${esc(n.interface_name)}</td>
                        <td><span class="badge badge-type" style="font-size:10px">${esc(n.type)}</span></td>
                        <td class="mono" style="font-size:12px">${displayIp !== '-' ? esc(displayIp) : '-'}</td>
                        <td class="mono" style="font-size:11px;color:var(--text-muted)">${esc(n.netmask) || '-'}</td>
                        <td class="mono" style="font-size:11px">${n.gateway ? linkIp(n.gateway) : '-'}</td>
                        <td class="mono" style="font-size:11px;color:var(--text-muted)">${esc(n.mac_address) || '-'}</td>
                        <td class="mono" style="font-size:11px">${n.mtu || '-'}</td>
                        <td>${n.active == 1 ? '<span class="badge badge-running">Ja</span>' : '<span class="badge badge-stopped">Nein</span>'}</td>
                        <td class="mono" style="font-size:11px;color:var(--text-muted)">${esc(n.bridge_ports) || '-'}</td>
                    </tr>`;
                });
                html += `</tbody></table></div>`;
            }
        }

        contentArea.innerHTML = html;

        // Bind sort headers
        contentArea.querySelectorAll('.sortable-th').forEach(th => {
            th.addEventListener('click', () => {
                const col = th.dataset.col;
                if (_netSort.col === col) {
                    _netSort.dir = _netSort.dir === 'asc' ? 'desc' : 'asc';
                } else {
                    _netSort.col = col;
                    _netSort.dir = 'asc';
                }
                renderNetwork();
            });
        });

        // Bind category filter buttons
        contentArea.querySelectorAll('.net-cat-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                _netCatFilter = btn.dataset.cat;
                renderNetwork();
            });
        });

        // Bind search input
        const searchEl = contentArea.querySelector('#netSearchInput');
        if (searchEl) {
            searchEl.addEventListener('input', e => {
                _netSearch = e.target.value;
                renderNetwork();
            });
            // Focus without scrolling
            searchEl.focus({ preventScroll: true });
        }
    }

    function renderErrors() {
        const errors = data.errors || [];
        let html = `<div class="section-header">
            <div>
                <h2 class="section-title">Scan-Fehler</h2>
                <p class="section-subtitle">${errors.length} Fehler beim letzten Scan</p>
            </div>
        </div>`;

        if (errors.length === 0) {
            html += '<div class="no-data" style="color:var(--success)">Keine Fehler beim letzten Scan.</div>';
            contentArea.innerHTML = html;
            return;
        }

        html += '<div class="error-list">';
        errors.forEach((e, i) => {
            html += `
            <div class="error-card" id="err-${i}">
                <div class="error-host">${linkIp(e.host_ip) || 'Unbekannt'}
                    <span class="error-component">${esc(e.component)}</span>
                </div>
                <div class="error-msg">${esc(e.error_message)}</div>
                ${e.error_detail ? `<button class="error-toggle" onclick="document.getElementById('err-${i}').classList.toggle('expanded')">Details anzeigen</button>
                <div class="error-detail">${esc(e.error_detail)}</div>` : ''}
            </div>`;
        });
        html += '</div>';
        contentArea.innerHTML = html;
    }

    /* ── History Modal ── */
    async function showHistory() {
        const modal = $('#historyModal');
        const body = $('#historyBody');
        modal.style.display = 'flex';
        body.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

        try {
            const result = await api('scans');
            if (!result.success || !result.data?.length) {
                body.innerHTML = '<div class="no-data">Keine Scans vorhanden.</div>';
                return;
            }
            let html = `<div class="table-container"><table>
                <thead><tr><th>#</th><th>Gestartet</th><th>Dauer</th><th>Hosts</th><th>VMs</th><th>LXC</th><th>Docker</th><th>Fehler</th><th>Aktion</th></tr></thead>
                <tbody>`;
            result.data.forEach(s => {
                html += `<tr>
                    <td>${s.id}</td>
                    <td>${formatDate(s.started_at)}</td>
                    <td>${s.duration_seconds || '-'}s</td>
                    <td>${s.hosts_scanned}</td>
                    <td>${s.vms_found}</td>
                    <td>${s.lxc_found}</td>
                    <td>${s.docker_found}</td>
                    <td>${s.errors_count > 0 ? `<span style="color:var(--danger)">${s.errors_count}</span>` : '0'}</td>
                    <td><button class="btn btn-sm" onclick="window._loadScan(${s.id})">Laden</button></td>
                </tr>`;
            });
            html += `</tbody></table></div>`;
            body.innerHTML = html;
        } catch (e) {
            body.innerHTML = `<div class="no-data">Fehler: ${esc(e.message)}</div>`;
        }
    }

    window._loadScan = async function(id) {
        $('#historyModal').style.display = 'none';
        loading.style.display = 'flex';
        contentArea.innerHTML = '';
        try {
            const result = await api('scan', { id });
            if (result.success && result.data) {
                data = result.data;
                updateScanInfo();
                updateErrorBadge();
                renderSection();
            }
        } catch (e) {
            showToast('Fehler beim Laden des Scans', true);
        }
        loading.style.display = 'none';
    };

    /* ── Trigger Scan ── */
    async function triggerScan() {
        try {
            const result = await api('trigger_scan');
            if (result.success) {
                showToast('Scan gestartet! Seite wird in 25s aktualisiert...');
                $('#btnRescan').disabled = true;
                $('#btnRescan').textContent = '\u23F3 Scan laeuft...';
                setTimeout(() => {
                    loadDashboard();
                    $('#btnRescan').disabled = false;
                    $('#btnRescan').innerHTML = '&#8635; Scan starten';
                }, 25000);
            }
        } catch (e) {
            showToast('Fehler: ' + e.message, true);
        }
    }

    /* ── Event Listeners ── */
    // Sidebar navigation
    $$('.nav-item[data-section]').forEach(el => {
        el.addEventListener('click', () => {
            navigateTo(el.dataset.section);
        });
    });

    // Search
    let searchTimeout;
    searchInput.addEventListener('input', () => {
        clearTimeout(searchTimeout);
        const val = searchInput.value.trim();

        if (val) {
            searchClear.style.display = '';
            if (searchKbd) searchKbd.style.display = 'none';
        } else {
            searchClear.style.display = 'none';
            if (searchKbd) searchKbd.style.display = '';
        }

        searchTimeout = setTimeout(() => {
            searchQuery = val;
            if (val.length >= 2) {
                // Deselect sidebar
                $$('.nav-item').forEach(e => e.classList.remove('active'));
                renderSection();
            } else if (val.length === 0) {
                // Restore active section
                $$('.nav-item').forEach(e => {
                    e.classList.toggle('active', e.dataset.section === activeSection);
                });
                renderSection();
            }
        }, 200);
    });

    searchClear.addEventListener('click', () => {
        searchInput.value = '';
        searchQuery = '';
        searchClear.style.display = 'none';
        if (searchKbd) searchKbd.style.display = '';
        $$('.nav-item').forEach(e => {
            e.classList.toggle('active', e.dataset.section === activeSection);
        });
        renderSection();
        searchInput.focus();
    });

    // Buttons
    $('#btnRescan').addEventListener('click', triggerScan);
    $('#btnHistory').addEventListener('click', showHistory);
    $('#closeHistory').addEventListener('click', () => { $('#historyModal').style.display = 'none'; });

    // Close modal on overlay click
    $('#historyModal').addEventListener('click', (e) => {
        if (e.target === e.currentTarget) e.currentTarget.style.display = 'none';
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            $('#historyModal').style.display = 'none';
            if (searchQuery) {
                searchInput.value = '';
                searchClear.style.display = 'none';
                if (searchKbd) searchKbd.style.display = '';
                searchQuery = '';
                $$('.nav-item').forEach(el => {
                    el.classList.toggle('active', el.dataset.section === activeSection);
                });
                renderSection();
            }
        }
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            searchInput.focus();
            searchInput.select();
        }
    });

    /* ── Init ── */
    loadDashboard();

})();
