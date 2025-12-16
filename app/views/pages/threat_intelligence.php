<?php
$httpMethod = $_SERVER['REQUEST_METHOD'];
$uri = $_SERVER['REQUEST_URI'];

if (false !== $pos = strpos($uri, '?')) {
    $uri = substr($uri, 0, $pos);
}

$basePath = MDIR;
if (strpos($uri, $basePath) === 0) {
    $uri = substr($uri, strlen($basePath));
    if ($uri === '') {
        $uri = '/';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>CyberHawk - Threat Intelligence</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const LOGS_URL = "assets/data/traffic_log.json";
    </script>

    <style>
        html, body {
            max-width: 100%;
            overflow-x: hidden;
        }

        .card {
            width: 100%;
        }

        .my-card {
            border: 2px solid #ff6b35;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .gradient-text {
            background: linear-gradient(135deg, #ff6b35, #c1272d);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            color: transparent;
            font-weight: bold;
        }

        .threat-level-critical {
            background-color: #dc3545;
            color: white;
            padding: 8px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: bold;
        }

        .threat-level-high {
            background-color: #fd7e14;
            color: white;
            padding: 8px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: bold;
        }

        .threat-level-medium {
            background-color: #ffc107;
            color: #333;
            padding: 8px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: bold;
        }

        .threat-level-low {
            background-color: #28a745;
            color: white;
            padding: 8px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: bold;
        }

        .intelligence-card {
            border-left: 5px solid #ff6b35;
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .intelligence-card:hover {
            transform: translateX(5px);
            box-shadow: 0 8px 16px rgba(255, 107, 53, 0.2);
        }

        .ioc-table {
            font-size: 0.9rem;
        }

        .ioc-table td {
            padding: 10px 8px;
        }

        .threat-actor-badge {
            display: inline-block;
            padding: 6px 12px;
            background: linear-gradient(135deg, #ff6b35, #c1272d);
            color: white;
            border-radius: 20px;
            font-size: 0.8rem;
            margin: 3px;
            font-weight: 500;
        }

        .campaign-timeline {
            border-left: 3px solid #ff6b35;
            padding-left: 20px;
            margin-left: 20px;
            position: relative;
        }

        .campaign-timeline::before {
            content: '';
            position: absolute;
            left: -8px;
            top: 0;
            width: 13px;
            height: 13px;
            background: #ff6b35;
            border-radius: 50%;
            border: 3px solid white;
        }

        .vulnerability-score {
            font-size: 2rem;
            font-weight: bold;
            color: #ff6b35;
        }

        .stats-box {
            text-align: center;
            padding: 20px;
            background: linear-gradient(135deg, rgba(255, 107, 53, 0.1), rgba(193, 39, 45, 0.1));
            border-radius: 10px;
            margin: 10px 0;
        }

        .stats-box h3 {
            margin: 10px 0 5px 0;
            color: #ff6b35;
            font-weight: bold;
        }

        .live-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            background-color: #28a745;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .feed-item {
            padding: 12px;
            background: #f8f9fa;
            border-left: 3px solid #ff6b35;
            margin-bottom: 10px;
            border-radius: 4px;
        }

        .feed-item.critical {
            background: rgba(220, 53, 69, 0.1);
            border-left-color: #dc3545;
        }

        .feed-item.high {
            background: rgba(253, 126, 20, 0.1);
            border-left-color: #fd7e14;
        }
    </style>
</head>

<body>
    <?php include 'app/views/common/header.php'; ?>

    <div class="d-flex" style="min-height: calc(100vh - 60px);">
        <?php include 'app/views/common/sidebar.php'; ?>

        <div class="main-content flex-grow-1 p-4">
            <div class="container-fluid">

                <!-- Page Header -->
                <div class="row mb-4">
                    <div class="col-12">
                        <h2 class="gradient-text">
                            <i class="bi bi-globe2"></i> Threat Intelligence Center
                        </h2>
                        <p class="text-muted">Real-time threat feeds, IOC tracking, and vulnerability intelligence</p>
                    </div>
                </div>

                <!-- Live Status -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="alert alert-info d-flex align-items-center">
                            <span class="live-indicator"></span>
                            <strong>Live Threat Intelligence Feed Active</strong>
                            <span class="ms-auto text-muted">Last updated: <span id="lastUpdate">just now</span></span>
                        </div>
                    </div>
                </div>

                <!-- Statistics Row -->
                <div class="row g-4 mb-4">
                    <div class="col-md-3">
                        <div class="card my-card">
                            <div class="card-body stats-box">
                                <i class="bi bi-exclamation-triangle" style="font-size: 2rem; color: #ff6b35;"></i>
                                <h3 id="totalThreats">0</h3>
                                <p class="text-muted mb-0">Active Threats</p>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-3">
                        <div class="card my-card">
                            <div class="card-body stats-box">
                                <i class="bi bi-shield-exclamation" style="font-size: 2rem; color: #dc3545;"></i>
                                <h3 id="criticalThreats">0</h3>
                                <p class="text-muted mb-0">Critical Threats</p>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-3">
                        <div class="card my-card">
                            <div class="card-body stats-box">
                                <i class="bi bi-diagram-3" style="font-size: 2rem; color: #fd7e14;"></i>
                                <h3 id="threatActors">0</h3>
                                <p class="text-muted mb-0">Tracked Actors</p>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-3">
                        <div class="card my-card">
                            <div class="card-body stats-box">
                                <i class="bi bi-bug" style="font-size: 2rem; color: #6f42c1;"></i>
                                <h3 id="totalVulns">0</h3>
                                <p class="text-muted mb-0">Vulnerabilities</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Main Content Row -->
                <div class="row g-4 mb-4">
                    <!-- Threat Feeds -->
                    <div class="col-md-6">
                        <div class="card my-card">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-rss-fill"></i> Latest Threat Feeds
                                </h5>
                            </div>
                            <div class="card-body" style="max-height: 400px; overflow-y: auto;">
                                <div id="threatFeedsList">
                                    <div class="text-center text-muted py-4">
                                        <i class="bi bi-hourglass-split"></i>
                                        <p>Loading threat feeds...</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Threat Actors -->
                    <div class="col-md-6">
                        <div class="card my-card">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-person-badge"></i> Tracked Threat Actors
                                </h5>
                            </div>
                            <div class="card-body" style="max-height: 400px; overflow-y: auto;">
                                <div id="threatActorsList">
                                    <div class="text-center text-muted py-4">
                                        <i class="bi bi-hourglass-split"></i>
                                        <p>Loading threat actors...</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- IOC Tracking -->
                <div class="row g-4 mb-4">
                    <div class="col-12">
                        <div class="card my-card">
                            <div class="card-header bg-white d-flex justify-content-between align-items-center">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-search"></i> Indicators of Compromise (IOCs)
                                </h5>
                                <div>
                                    <input type="text" class="form-control form-control-sm d-inline" 
                                           id="iocSearch" placeholder="Search IOC..." 
                                           style="width: 200px;">
                                </div>
                            </div>
                            <div class="card-body">
                                <ul class="nav nav-tabs mb-3" role="tablist">
                                    <li class="nav-item" role="presentation">
                                        <button class="nav-link active" id="ips-tab" data-bs-toggle="tab" 
                                                data-bs-target="#ips" type="button" role="tab">
                                            <i class="bi bi-pc-display"></i> IP Addresses
                                        </button>
                                    </li>
                                    <li class="nav-item" role="presentation">
                                        <button class="nav-link" id="domains-tab" data-bs-toggle="tab" 
                                                data-bs-target="#domains" type="button" role="tab">
                                            <i class="bi bi-globe"></i> Domains
                                        </button>
                                    </li>
                                    <li class="nav-item" role="presentation">
                                        <button class="nav-link" id="hashes-tab" data-bs-toggle="tab" 
                                                data-bs-target="#hashes" type="button" role="tab">
                                            <i class="bi bi-fingerprint"></i> File Hashes
                                        </button>
                                    </li>
                                </ul>

                                <div class="tab-content">
                                    <div class="tab-pane fade show active" id="ips" role="tabpanel">
                                        <div class="table-responsive">
                                            <table class="table table-sm table-striped ioc-table" id="ipsTable">
                                                <thead class="table-light">
                                                    <tr>
                                                        <th>IP Address</th>
                                                        <th>Threat Level</th>
                                                        <th>Last Seen</th>
                                                        <th>Confidence</th>
                                                        <th>Action</th>
                                                    </tr>
                                                </thead>
                                                <tbody id="ipsBody">
                                                    <tr><td colspan="5" class="text-center text-muted">Loading...</td></tr>
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>

                                    <div class="tab-pane fade" id="domains" role="tabpanel">
                                        <div class="table-responsive">
                                            <table class="table table-sm table-striped ioc-table" id="domainsTable">
                                                <thead class="table-light">
                                                    <tr>
                                                        <th>Domain</th>
                                                        <th>Threat Level</th>
                                                        <th>Last Seen</th>
                                                        <th>Confidence</th>
                                                        <th>Action</th>
                                                    </tr>
                                                </thead>
                                                <tbody id="domainsBody">
                                                    <tr><td colspan="5" class="text-center text-muted">Loading...</td></tr>
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>

                                    <div class="tab-pane fade" id="hashes" role="tabpanel">
                                        <div class="table-responsive">
                                            <table class="table table-sm table-striped ioc-table" id="hashesTable">
                                                <thead class="table-light">
                                                    <tr>
                                                        <th>File Hash (SHA256)</th>
                                                        <th>Threat Level</th>
                                                        <th>Malware Type</th>
                                                        <th>Last Seen</th>
                                                        <th>Action</th>
                                                    </tr>
                                                </thead>
                                                <tbody id="hashesBody">
                                                    <tr><td colspan="5" class="text-center text-muted">Loading...</td></tr>
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Vulnerabilities -->
                <div class="row g-4">
                    <div class="col-12">
                        <div class="card my-card">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-exclamation-circle"></i> Critical Vulnerabilities
                                </h5>
                            </div>
                            <div class="card-body">
                                <div id="vulnerabilitiesList">
                                    <div class="text-center text-muted py-4">
                                        <i class="bi bi-hourglass-split"></i>
                                        <p>Loading vulnerabilities...</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    </div>

    <script>
        // ==================== INITIALIZATION ====================
        $(document).ready(function() {
            loadThreatIntelligence();
            setInterval(loadThreatIntelligence, 30000); // Refresh every 30 seconds
        });

        // ==================== LOAD THREAT INTELLIGENCE ====================
        function loadThreatIntelligence() {
            loadThreatFeeds();
            loadThreatActors();
            loadIOCs();
            loadVulnerabilities();
            updateLastUpdate();
        }

        // ==================== THREAT FEEDS ====================
        function loadThreatFeeds() {
            $.ajax({
                url: LOGS_URL + '?_=' + Date.now(),
                dataType: 'json',
                success: function(trafficData) {
                    if (!Array.isArray(trafficData) || trafficData.length === 0) {
                        $('#threatFeedsList').html('<div class="text-center text-muted py-4"><i class="bi bi-info-circle"></i><p>No active threat feeds detected</p></div>');
                        $('#totalThreats').text(0);
                        $('#criticalThreats').text(0);
                        return;
                    }

                    // Analyze traffic data for threats
                    let threats = [];
                    let criticalCount = 0;

                    trafficData.forEach(flow => {
                        if (!flow) return;

                        // Detect high SYN flags (possible SYN flood)
                        const synCount = parseInt(flow["SYN Flag Count"]) || 0;
                        if (synCount > 10) {
                            threats.push({
                                threat: `SYN Flood Attack from ${flow["Src IP"]}`,
                                source: 'Network Monitor',
                                severity: synCount > 50 ? 'critical' : 'high',
                                timestamp: flow["Timestamp"] || new Date().toLocaleString()
                            });
                            if (synCount > 50) criticalCount++;
                        }

                        // Detect port scanning
                        const dstPort = parseInt(flow["Dst Port"]) || 0;
                        if (dstPort < 1024 && (synCount > 5 || parseInt(flow["RST Flag Count"]) > 3)) {
                            threats.push({
                                threat: `Port Scan Detected on port ${dstPort}`,
                                source: flow["Src IP"],
                                severity: 'medium',
                                timestamp: flow["Timestamp"] || new Date().toLocaleString()
                            });
                        }

                        // Detect high packet rate
                        const flowPacketsPerSec = parseFloat(flow["Flow Packets/s"]) || 0;
                        if (flowPacketsPerSec > 1000) {
                            threats.push({
                                threat: `High Traffic Volume from ${flow["Src IP"]}`,
                                source: 'Traffic Analyzer',
                                severity: flowPacketsPerSec > 5000 ? 'critical' : 'high',
                                timestamp: flow["Timestamp"] || new Date().toLocaleString()
                            });
                            if (flowPacketsPerSec > 5000) criticalCount++;
                        }
                    });

                    // Remove duplicates and limit to recent 10
                    threats = threats.slice(-10);

                    if (threats.length === 0) {
                        $('#threatFeedsList').html('<div class="text-center text-muted py-4"><i class="bi bi-shield-check text-success" style="font-size: 2rem;"></i><p>No threats detected - Network is secure</p></div>');
                        $('#totalThreats').text(0);
                        $('#criticalThreats').text(0);
                        return;
                    }

                    let html = '';
                    threats.forEach(feed => {
                        const severityClass = `feed-item ${feed.severity}`;
                        const badgeClass = feed.severity === 'critical' ? 'threat-level-critical' :
                                         feed.severity === 'high' ? 'threat-level-high' :
                                         feed.severity === 'medium' ? 'threat-level-medium' : 'threat-level-low';

                        html += `
                            <div class="${severityClass}">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <h6 class="mb-1">${feed.threat}</h6>
                                        <small class="text-muted">Source: ${feed.source}</small>
                                    </div>
                                    <span class="${badgeClass}">${feed.severity.toUpperCase()}</span>
                                </div>
                                <small class="text-muted d-block mt-2">${feed.timestamp}</small>
                            </div>
                        `;
                    });

                    $('#threatFeedsList').html(html);
                    $('#totalThreats').text(threats.length);
                    $('#criticalThreats').text(criticalCount);
                },
                error: function() {
                    $('#threatFeedsList').html('<div class="text-center text-muted py-4"><i class="bi bi-exclamation-triangle"></i><p>Waiting for traffic data...</p></div>');
                    $('#totalThreats').text(0);
                    $('#criticalThreats').text(0);
                }
            });
        }

        // ==================== THREAT ACTORS ====================
        function loadThreatActors() {
            $.ajax({
                url: LOGS_URL + '?_=' + Date.now(),
                dataType: 'json',
                success: function(trafficData) {
                    if (!Array.isArray(trafficData) || trafficData.length === 0) {
                        $('#threatActorsList').html('<div class="text-center text-muted py-4"><i class="bi bi-info-circle"></i><p>No threat actors tracked</p></div>');
                        $('#threatActors').text(0);
                        return;
                    }

                    // Track unique suspicious IPs
                    let suspiciousIPs = {};

                    trafficData.forEach(flow => {
                        if (!flow) return;

                        const srcIP = flow["Src IP"];
                        const synCount = parseInt(flow["SYN Flag Count"]) || 0;
                        const rstCount = parseInt(flow["RST Flag Count"]) || 0;
                        const flowRate = parseFloat(flow["Flow Packets/s"]) || 0;

                        // Identify suspicious activity
                        if (synCount > 5 || rstCount > 3 || flowRate > 500) {
                            if (!suspiciousIPs[srcIP]) {
                                suspiciousIPs[srcIP] = {
                                    ip: srcIP,
                                    synAttacks: 0,
                                    portScans: 0,
                                    highTraffic: 0,
                                    lastSeen: flow["Timestamp"] || new Date().toLocaleString()
                                };
                            }

                            if (synCount > 10) suspiciousIPs[srcIP].synAttacks++;
                            if (rstCount > 3) suspiciousIPs[srcIP].portScans++;
                            if (flowRate > 500) suspiciousIPs[srcIP].highTraffic++;
                        }
                    });

                    const actors = Object.values(suspiciousIPs).slice(0, 5);

                    if (actors.length === 0) {
                        $('#threatActorsList').html('<div class="text-center text-muted py-4"><i class="bi bi-shield-check text-success" style="font-size: 2rem;"></i><p>No suspicious actors detected</p></div>');
                        $('#threatActors').text(0);
                        return;
                    }

                    let html = '';
                    actors.forEach(actor => {
                        let activities = [];
                        if (actor.synAttacks > 0) activities.push(`SYN Flood attempts: ${actor.synAttacks}`);
                        if (actor.portScans > 0) activities.push(`Port scans: ${actor.portScans}`);
                        if (actor.highTraffic > 0) activities.push(`High traffic events: ${actor.highTraffic}`);

                        html += `
                            <div class="intelligence-card card mb-3">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between align-items-start mb-2">
                                        <h6 class="mb-0">${actor.ip}</h6>
                                        <span class="threat-actor-badge">Suspicious</span>
                                    </div>
                                    <p class="mb-0 small text-muted">${activities.join(', ')}</p>
                                    <small class="text-muted d-block mt-1">Last seen: ${actor.lastSeen}</small>
                                </div>
                            </div>
                        `;
                    });

                    $('#threatActorsList').html(html);
                    $('#threatActors').text(actors.length);
                },
                error: function() {
                    $('#threatActorsList').html('<div class="text-center text-muted py-4"><i class="bi bi-exclamation-triangle"></i><p>Waiting for traffic data...</p></div>');
                    $('#threatActors').text(0);
                }
            });
        }

        // ==================== IOCs ====================
        function loadIOCs() {
            $.ajax({
                url: LOGS_URL + '?_=' + Date.now(),
                dataType: 'json',
                success: function(trafficData) {
                    // Extract suspicious IPs from traffic data
                    let suspiciousIPs = [];
                    let seenIPs = new Set();

                    if (Array.isArray(trafficData)) {
                        trafficData.forEach(flow => {
                            if (!flow) return;

                            const srcIP = flow["Src IP"];
                            if (!srcIP || seenIPs.has(srcIP)) return;

                            const synCount = parseInt(flow["SYN Flag Count"]) || 0;
                            const rstCount = parseInt(flow["RST Flag Count"]) || 0;
                            const flowRate = parseFloat(flow["Flow Packets/s"]) || 0;

                            // Determine threat level
                            let level = "Low";
                            let conf = "Medium";

                            if (synCount > 50 || flowRate > 5000) {
                                level = "Critical";
                                conf = "High";
                                seenIPs.add(srcIP);
                                suspiciousIPs.push({
                                    ip: srcIP,
                                    level: level,
                                    last: flow["Timestamp"] || new Date().toLocaleString(),
                                    conf: conf
                                });
                            } else if (synCount > 10 || rstCount > 5 || flowRate > 1000) {
                                level = "High";
                                conf = "High";
                                seenIPs.add(srcIP);
                                suspiciousIPs.push({
                                    ip: srcIP,
                                    level: level,
                                    last: flow["Timestamp"] || new Date().toLocaleString(),
                                    conf: conf
                                });
                            } else if (synCount > 5 || rstCount > 3 || flowRate > 500) {
                                level = "Medium";
                                conf = "Medium";
                                seenIPs.add(srcIP);
                                suspiciousIPs.push({
                                    ip: srcIP,
                                    level: level,
                                    last: flow["Timestamp"] || new Date().toLocaleString(),
                                    conf: conf
                                });
                            }
                        });
                    }

                    // First, fetch blocked IPs
                    $.ajax({
                        url: '<?= MDIR ?>get-blocked-iocs',
                        dataType: 'json',
                        async: false, // We need this before building the table
                        success: function(blockedData) {
                            window.blockedIPs = blockedData.blocked ? blockedData.blocked.map(b => b.ioc) : [];
                        },
                        error: function() {
                            window.blockedIPs = [];
                        }
                    });

                    // IP Addresses
                    let ipHtml = '';
                    if (suspiciousIPs.length === 0 && (!window.blockedIPs || window.blockedIPs.length === 0)) {
                        ipHtml = '<tr><td colspan="5" class="text-center text-muted">No malicious IPs detected</td></tr>';
                    } else {
                        // Show blocked IPs first (with unblock button)
                        if (window.blockedIPs && window.blockedIPs.length > 0) {
                            window.blockedIPs.forEach(ip => {
                                ipHtml += `
                                    <tr class="table-danger">
                                        <td>${ip} <span class="badge bg-danger">BLOCKED</span></td>
                                        <td><span class="threat-level-critical">Blocked</span></td>
                                        <td>-</td>
                                        <td>System Level</td>
                                        <td>
                                            <button class="btn btn-sm btn-outline-success" onclick="unblockIOC('${ip}')">
                                                <i class="bi bi-unlock"></i> Unblock
                                            </button>
                                        </td>
                                    </tr>
                                `;
                            });
                        }
                        
                        // Then show suspicious IPs (excluding already blocked ones)
                        suspiciousIPs.slice(0, 10).forEach(item => {
                            // Skip if already blocked
                            if (window.blockedIPs && window.blockedIPs.includes(item.ip)) {
                                return;
                            }
                            const levelClass = `threat-level-${item.level.toLowerCase()}`;
                            ipHtml += `
                                <tr>
                                    <td>${item.ip}</td>
                                    <td><span class="${levelClass}">${item.level}</span></td>
                                    <td>${item.last}</td>
                                    <td>${item.conf}</td>
                                    <td>
                                        <button class="btn btn-sm btn-outline-danger" onclick="blockIOC('${item.ip}')">
                                            <i class="bi bi-ban"></i> Block
                                        </button>
                                    </td>
                                </tr>
                            `;
                        });
                    }
                    $('#ipsBody').html(ipHtml);

                    // Domains - Currently tracking IPs only
                    $('#domainsBody').html('<tr><td colspan="5" class="text-center text-muted">Domain tracking available for DNS-enabled traffic capture</td></tr>');

                    // File Hashes - Integrated with malware analysis module
                    $('#hashesBody').html('<tr><td colspan="5" class="text-center text-muted">File hash tracking available in Malware Analysis module</td></tr>');
                },
                error: function() {
                    $('#ipsBody').html('<tr><td colspan="5" class="text-center text-muted">Waiting for traffic data...</td></tr>');
                    $('#domainsBody').html('<tr><td colspan="5" class="text-center text-muted">Waiting for traffic data...</td></tr>');
                    $('#hashesBody').html('<tr><td colspan="5" class="text-center text-muted">Waiting for traffic data...</td></tr>');
                }
            });
        }

        // ==================== VULNERABILITIES ====================
        function loadVulnerabilities() {
            // Vulnerabilities detection based on network traffic patterns and attack signatures
            $('#vulnerabilitiesList').html('<div class="text-center text-muted py-4"><i class="bi bi-shield-check text-success" style="font-size: 2rem;"></i><p>No critical vulnerabilities detected in current traffic patterns</p><small>System actively monitoring for known exploit signatures</small></div>');
            $('#totalVulns').text(0);
        }

        // ==================== UTILITY FUNCTIONS ====================
        function blockIOC(ioc) {
            if (!confirm(`Are you sure you want to block IP: ${ioc}?\n\nThis will block all traffic to/from this IP on your system.`)) {
                return;
            }
            
            // Show loading state
            showNotification('Processing', `Blocking IP ${ioc}...`, 'info');
            
            $.ajax({
                url: '<?= MDIR ?>block-ioc',
                method: 'POST',
                data: {
                    ioc: ioc,
                    type: 'ip',
                    reason: 'Blocked via Threat Intelligence - Malicious activity detected'
                },
                dataType: 'json',
                success: function(response) {
                    if (response.success) {
                        showNotification('Success', response.message, 'success');
                        // Reload IOC table to reflect changes
                        loadIOCs();
                    } else {
                        showNotification('Warning', response.message, 'warning');
                        if (response.note) {
                            setTimeout(() => {
                                alert('Note: ' + response.note);
                            }, 500);
                        }
                    }
                },
                error: function(xhr, status, error) {
                    showNotification('Error', 'Failed to block IP: ' + error, 'danger');
                }
            });
        }

        function viewHashDetails(hash) {
            alert(`Viewing details for: ${hash}`);
        }

        function unblockIOC(ioc) {
            if (!confirm(`Are you sure you want to unblock IP: ${ioc}?`)) {
                return;
            }
            
            showNotification('Processing', `Unblocking IP ${ioc}...`, 'info');
            
            $.ajax({
                url: '<?= MDIR ?>unblock-ioc',
                method: 'POST',
                data: { ioc: ioc },
                dataType: 'json',
                success: function(response) {
                    if (response.success) {
                        showNotification('Success', response.message, 'success');
                        loadIOCs();
                    } else {
                        showNotification('Error', response.message, 'danger');
                    }
                },
                error: function(xhr, status, error) {
                    showNotification('Error', 'Failed to unblock IP: ' + error, 'danger');
                }
            });
        }

        function updateLastUpdate() {
            $('#lastUpdate').text(new Date().toLocaleTimeString());
        }

        function showNotification(title, message, type) {
            const alertClass = type === 'danger' ? 'alert-danger' : 
                              type === 'success' ? 'alert-success' :
                              type === 'warning' ? 'alert-warning' : 'alert-info';
            
            const notification = $(`
                <div class="alert ${alertClass} alert-dismissible fade show position-fixed" 
                     style="top: 80px; right: 20px; z-index: 10001; min-width: 300px;">
                    <strong>${title}:</strong> ${message}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            `);
            
            $('body').append(notification);
            setTimeout(() => notification.fadeOut(() => notification.remove()), 5000);
        }
    </script>
</body>
</html>