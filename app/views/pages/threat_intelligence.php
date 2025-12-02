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
            const threatFeeds = [
                {
                    id: 1,
                    source: 'MISP Feed',
                    threat: 'Distributed DoS Campaign',
                    severity: 'critical',
                    timestamp: new Date(Date.now() - 5*60000).toLocaleString()
                },
                {
                    id: 2,
                    source: 'VirusTotal',
                    threat: 'New Ransomware Variant (Lockbit 3.0)',
                    severity: 'critical',
                    timestamp: new Date(Date.now() - 15*60000).toLocaleString()
                },
                {
                    id: 3,
                    source: 'Shodan',
                    threat: 'Exposed Database Servers (SQLi)',
                    severity: 'high',
                    timestamp: new Date(Date.now() - 30*60000).toLocaleString()
                },
                {
                    id: 4,
                    source: 'ThreatFox',
                    threat: 'Phishing Campaign - Microsoft Spoofing',
                    severity: 'high',
                    timestamp: new Date(Date.now() - 45*60000).toLocaleString()
                },
                {
                    id: 5,
                    source: 'MalwareBazaar',
                    threat: 'Trojan.Emotet C2 Infrastructure',
                    severity: 'critical',
                    timestamp: new Date(Date.now() - 60*60000).toLocaleString()
                }
            ];

            let html = '';
            threatFeeds.forEach(feed => {
                const severityClass = `feed-item ${feed.severity}`;
                const badgeClass = feed.severity === 'critical' ? 'threat-level-critical' : 'threat-level-high';
                
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
            $('#totalThreats').text(threatFeeds.length);
            $('#criticalThreats').text(threatFeeds.filter(f => f.severity === 'critical').length);
        }

        // ==================== THREAT ACTORS ====================
        function loadThreatActors() {
            const threatActors = [
                { name: 'Lazarus Group', country: 'North Korea', activity: 'Ransomware, Crypto Theft' },
                { name: 'APT28 (Fancy Bear)', country: 'Russia', activity: 'Nation-State Attacks' },
                { name: 'Emotet', country: 'Unknown', activity: 'Banking Trojan Distribution' },
                { name: 'DarkSide', country: 'Eastern Europe', activity: 'Ransomware' },
                { name: 'Conti', country: 'Russia', activity: 'Enterprise Ransomware' }
            ];

            let html = '';
            threatActors.forEach(actor => {
                html += `
                    <div class="intelligence-card card mb-3">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-start mb-2">
                                <h6 class="mb-0">${actor.name}</h6>
                                <span class="threat-actor-badge">${actor.country}</span>
                            </div>
                            <p class="mb-0 small text-muted">${actor.activity}</p>
                        </div>
                    </div>
                `;
            });

            $('#threatActorsList').html(html);
            $('#threatActors').text(threatActors.length);
        }

        // ==================== IOCs ====================
        function loadIOCs() {
            // IP Addresses
            const ips = [
                { ip: '192.168.1.100', level: 'Critical', last: '2 minutes ago', conf: '99%' },
                { ip: '10.0.0.50', level: 'High', last: '15 minutes ago', conf: '95%' },
                { ip: '172.16.0.1', level: 'Medium', last: '1 hour ago', conf: '85%' },
                { ip: '8.8.8.8', level: 'Low', last: '3 hours ago', conf: '70%' }
            ];

            let ipHtml = '';
            ips.forEach(item => {
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
            $('#ipsBody').html(ipHtml);

            // Domains
            const domains = [
                { domain: 'malicious-c2.com', level: 'Critical', last: '5 minutes ago', conf: '98%' },
                { domain: 'phishing-site.ru', level: 'High', last: '30 minutes ago', conf: '96%' }
            ];

            let domainHtml = '';
            domains.forEach(item => {
                const levelClass = `threat-level-${item.level.toLowerCase()}`;
                domainHtml += `
                    <tr>
                        <td>${item.domain}</td>
                        <td><span class="${levelClass}">${item.level}</span></td>
                        <td>${item.last}</td>
                        <td>${item.conf}</td>
                        <td>
                            <button class="btn btn-sm btn-outline-danger" onclick="blockIOC('${item.domain}')">
                                <i class="bi bi-ban"></i> Block
                            </button>
                        </td>
                    </tr>
                `;
            });
            $('#domainsBody').html(domainHtml);

            // File Hashes
            const hashes = [
                { hash: 'a1b2c3d4e5f6...', level: 'Critical', type: 'Ransomware', last: '10 minutes ago' },
                { hash: 'f6e5d4c3b2a1...', level: 'High', type: 'Trojan', last: '2 hours ago' }
            ];

            let hashHtml = '';
            hashes.forEach(item => {
                const levelClass = `threat-level-${item.level.toLowerCase()}`;
                hashHtml += `
                    <tr>
                        <td><code>${item.hash}</code></td>
                        <td><span class="${levelClass}">${item.level}</span></td>
                        <td>${item.type}</td>
                        <td>${item.last}</td>
                        <td>
                            <button class="btn btn-sm btn-outline-primary" onclick="viewHashDetails('${item.hash}')">
                                <i class="bi bi-eye"></i>
                            </button>
                        </td>
                    </tr>
                `;
            });
            $('#hashesBody').html(hashHtml);
        }

        // ==================== VULNERABILITIES ====================
        function loadVulnerabilities() {
            const vulnerabilities = [
                {
                    id: 'CVE-2024-1086',
                    title: 'Linux Kernel Privilege Escalation',
                    score: 9.8,
                    affected: 'Linux 6.0 - 6.7',
                    status: 'Actively Exploited'
                },
                {
                    id: 'CVE-2024-0567',
                    title: 'Windows Remote Code Execution',
                    score: 9.6,
                    affected: 'Windows Server 2019-2022',
                    status: 'Patches Available'
                },
                {
                    id: 'CVE-2023-44487',
                    title: 'HTTP/2 Rapid Reset Attack',
                    score: 7.5,
                    affected: 'Multiple HTTP/2 Implementations',
                    status: 'Patched'
                }
            ];

            let html = '';
            vulnerabilities.forEach(vuln => {
                const scoreColor = vuln.score >= 9 ? '#dc3545' : vuln.score >= 7 ? '#fd7e14' : '#ffc107';
                html += `
                    <div class="card mb-3">
                        <div class="card-body">
                            <div class="row align-items-center">
                                <div class="col-md-6">
                                    <h6 class="mb-1">${vuln.id}</h6>
                                    <p class="mb-2">${vuln.title}</p>
                                    <small class="text-muted">Affected: ${vuln.affected}</small>
                                </div>
                                <div class="col-md-3">
                                    <div style="text-align: center;">
                                        <div class="vulnerability-score" style="color: ${scoreColor};">${vuln.score}</div>
                                        <small class="text-muted">CVSS Score</small>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <span class="badge ${vuln.status === 'Actively Exploited' ? 'bg-danger' : vuln.status === 'Patches Available' ? 'bg-warning' : 'bg-success'}">
                                        ${vuln.status}
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            });

            $('#vulnerabilitiesList').html(html);
            $('#totalVulns').text(vulnerabilities.length);
        }

        // ==================== UTILITY FUNCTIONS ====================
        function blockIOC(ioc) {
            alert(`Blocking IOC: ${ioc}`);
            showNotification('Success', `IOC ${ioc} has been blocked`, 'success');
        }

        function viewHashDetails(hash) {
            alert(`Viewing details for: ${hash}`);
        }

        function updateLastUpdate() {
            $('#lastUpdate').text(new Date().toLocaleTimeString());
        }

        function showNotification(title, message, type) {
            const alertClass = type === 'danger' ? 'alert-danger' : 
                              type === 'success' ? 'alert-success' : 'alert-info';
            
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