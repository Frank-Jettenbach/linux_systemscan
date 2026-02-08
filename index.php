<?php $config = require __DIR__ . '/config.php'; $app = $config['app']; ?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($app['title']) ?></title>
    <link rel="icon" type="image/svg+xml" href="assets/favicon.svg">
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>

<nav class="top-nav">
    <div class="nav-left">
        <span class="nav-logo">&#9881;</span>
        <h1 class="nav-title"><?= htmlspecialchars($app['title']) ?></h1>
    </div>
    <div class="nav-center">
        <div class="search-wrapper" id="searchWrapper">
            <span class="search-icon">&#128269;</span>
            <input type="text" id="searchInput" class="search-input" placeholder="Suche nach VMs, Container, IPs, Images... (Ctrl+K)" autocomplete="off">
            <kbd class="search-kbd">Ctrl+K</kbd>
            <button class="search-clear" id="searchClear" style="display:none">&times;</button>
        </div>
    </div>
    <div class="nav-right">
        <span class="scan-info" id="scanInfo"></span>
        <button class="btn btn-accent" id="btnRescan" title="Neuen Scan starten">&#8635; Scan starten</button>
        <button class="btn btn-secondary" id="btnHistory" title="Scan-Verlauf">&#128197; Verlauf</button>
    </div>
</nav>

<aside class="sidebar" id="sidebar">
    <div class="sidebar-section">
        <h3 class="sidebar-heading">Navigation</h3>
        <ul class="sidebar-nav" id="sidebarNav">
            <li class="nav-item active" data-section="overview">
                <span class="nav-icon">&#9635;</span> Dashboard
            </li>
            <li class="nav-item" data-section="hosts">
                <span class="nav-icon">&#9881;</span> Proxmox Hosts
            </li>
            <li class="nav-item" data-section="vms">
                <span class="nav-icon">&#128187;</span> Virtual Machines
            </li>
            <li class="nav-item" data-section="lxc">
                <span class="nav-icon">&#128230;</span> LXC Container
            </li>
            <li class="nav-item" data-section="docker">
                <span class="nav-icon">&#128051;</span> Docker
            </li>
            <li class="nav-item" data-section="storage">
                <span class="nav-icon">&#128190;</span> Storage
            </li>
            <li class="nav-item" data-section="network">
                <span class="nav-icon">&#127760;</span> Netzwerk
            </li>
            <li class="nav-item" data-section="errors">
                <span class="nav-icon">&#9888;</span> Fehler
                <span class="error-badge" id="errorBadge" style="display:none">0</span>
            </li>
        </ul>
    </div>
    <div class="sidebar-section" id="hostFilter" style="display:none">
        <h3 class="sidebar-heading">Host-Filter</h3>
        <ul class="sidebar-nav" id="hostFilterList"></ul>
    </div>
</aside>

<main class="main-content" id="mainContent">
    <div class="loading" id="loading">
        <div class="spinner"></div>
        <span>Lade Daten...</span>
    </div>
    <div id="contentArea"></div>
</main>

<!-- Scan History Modal -->
<div class="modal-overlay" id="historyModal" style="display:none">
    <div class="modal">
        <div class="modal-header">
            <h2>Scan-Verlauf</h2>
            <button class="modal-close" id="closeHistory">&times;</button>
        </div>
        <div class="modal-body" id="historyBody">
        </div>
    </div>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<script>
    const BASE_URL = '<?= htmlspecialchars($app['base_url']) ?>';
</script>
<script src="assets/app.js"></script>
</body>
</html>
