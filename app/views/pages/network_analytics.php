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
    <title>CyberHawk - Network Analytics</title>
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
            border: 2px solid #17a2b8;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .gradient-text {
            background: linear-gradient(135deg, #17a2b8, #0c5460);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            color: transparent;
            font-weight: bold;
        }

        .chart-container {
            position: relative;
            height: 300px;
            margin-bottom: 20px;
        }

        .metric-box {
            text-align: center;
            padding: 20px;
            background: linear-gradient(135deg, rgba(23, 162, 184, 0.1), rgba(12, 84, 96, 0.1));
            border-radius: 10px;
            margin: 10px 0;
        }

        .metric-box h3 {
            margin: 10px 0 5px 0;
            color: #17a2b8;
            font-weight: bold;
        }

        .metric-number {
            font-size: 2.5rem;
            font-weight: bold;
            color: #17a2b8;
        }

        .flow-card {
            border-left: 4px solid #17a2b8;
            transition: all 0.3s ease;
        }

        .flow-card:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 15px rgba(23, 162, 184, 0.2);
        }

        .bandwidth-bar {
            height: 8px;
            background: linear-gradient(90deg, #17a2b8, #0c5460);
            border-radius: 4px;
            margin: 5px 0;
        }

        .protocol-badge {
            display: inline-block;
            padding: 6px 12px;
            background: linear-gradient(135deg, #17a2b8, #0c5460);
            color: white;
            border-radius: 20px;
            font-size: 0.8rem;
            margin: 3px;
            font-weight: 500;
        }

        .packet-timeline {
            position: relative;
            padding: 20px 0;
        }

        .packet-item {
            padding: 12px;
            margin-bottom: 10px;
            background: #f8f9fa;
            border-left: 3px solid #17a2b8;
            border-radius: 4px;
            font-size: 0.9rem;
        }

        .packet-item.spike {
            background: rgba(23, 162, 184, 0.1);
            border-left-color: #dc3545;
        }

        .geo-map {
            width: 100%;
            height: 300px;
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #6c757d;
        }

        .connection-flow {
            display: flex;
            align-items: center;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 6px;
            margin-bottom: 10px;
            font-size: 0.85rem;
        }

        .connection-flow .arrow {
            color: #17a2b8;
            margin: 0 10px;
            font-weight: bold;
        }

        .bandwidth-usage {
            display: flex;
            align-items: center;
            margin-bottom: 12px;
        }

        .bandwidth-label {
            min-width: 100px;
            font-weight: 500;
        }

        .bandwidth-bar-container {
            flex: 1;
            height: 20px;
            background: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
        }

        .bandwidth-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #17a2b8, #0c5460);
        }

        .bandwidth-value {
            min-width: 60px;
            text-align: right;
            margin-left: 10px;
            font-weight: 500;
        }

        .latency-indicator {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
        }

        .latency-good {
            background-color: #d4edda;
            color: #155724;
        }

        .latency-warning {
            background-color: #fff3cd;
            color: #856404;
        }

        .latency-critical {
            background-color: #f8d7da;
            color: #721c24;
        }

        .filter-section {
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
        }

        .live-counter {
            font-size: 0.8rem;
            padding: 6px 12px;
            background: #28a745;
            color: white;
            border-radius: 20px;
            font-weight: bold;
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
                            <i class="bi bi-graph-up-arrow"></i> Network Analytics
                        </h2>
                        <p class="text-muted">Deep insights into network traffic, bandwidth usage, and performance metrics</p>
                    </div>
                </div>

                <!-- Key Metrics -->
                <div class="row g-4 mb-4">
                    <div class="col-md-3">
                        <div class="card my-card">
                            <div class="card-body metric-box">
                                <i class="bi bi-lightning-fill" style="font-size: 2rem; color: #17a2b8;"></i>
                                <h3 id="totalPackets">0</h3>
                                <p class="text-muted mb-0">Total Packets</p>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-3">
                        <div class="card my-card">
                            <div class="card-body metric-box">
                                <i class="bi bi-diagram-2" style="font-size: 2rem; color: #17a2b8;"></i>
                                <h3 id="activeFlows">0</h3>
                                <p class="text-muted mb-0">Active Connections</p>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-3">
                        <div class="card my-card">
                            <div class="card-body metric-box">
                                <i class="bi bi-cloud-download" style="font-size: 2rem; color: #17a2b8;"></i>
                                <h3 id="totalBandwidth">0 MB</h3>
                                <p class="text-muted mb-0">Total Bandwidth</p>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-3">
                        <div class="card my-card">
                            <div class="card-body metric-box">
                                <i class="bi bi-speedometer2" style="font-size: 2rem; color: #17a2b8;"></i>
                                <h3 id="avgLatency">0 ms</h3>
                                <p class="text-muted mb-0">Avg Latency</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Charts Row -->
                <div class="row g-4 mb-4">
                    <!-- Bandwidth Over Time -->
                    <div class="col-md-6">
                        <div class="card my-card">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-graph-up"></i> Bandwidth Usage (Last 24h)
                                </h5>
                            </div>
                            <div class="card-body">
                                <div class="chart-container">
                                    <canvas id="bandwidthChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Protocol Distribution -->
                    <div class="col-md-6">
                        <div class="card my-card">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-pie-chart"></i> Protocol Distribution
                                </h5>
                            </div>
                            <div class="card-body">
                                <div class="chart-container">
                                    <canvas id="protocolChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Traffic Analysis -->
                <div class="row g-4 mb-4">
                    <!-- Top Talkers -->
                    <div class="col-md-6">
                        <div class="card my-card">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-broadcast"></i> Top Source IPs
                                </h5>
                            </div>
                            <div class="card-body">
                                <div id="topTalkersList">
                                    <p class="text-muted text-center">Loading...</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Bandwidth Distribution -->
                    <div class="col-md-6">
                        <div class="card my-card">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-diagram-3"></i> Bandwidth by Protocol
                                </h5>
                            </div>
                            <div class="card-body">
                                <div id="bandwidthByProtocol"></div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Connection Analysis -->
                <div class="row g-4 mb-4">
                    <!-- Active Connections -->
                    <div class="col-md-6">
                        <div class="card my-card">
                            <div class="card-header bg-white d-flex justify-content-between align-items-center">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-link-45deg"></i> Active Connections
                                </h5>
                                <span class="live-counter" id="connCounter">0 Live</span>
                            </div>
                            <div class="card-body" style="max-height: 400px; overflow-y: auto;">
                                <div id="activeConnectionsList">
                                    <p class="text-muted text-center">Loading connections...</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Network Performance -->
                    <div class="col-md-6">
                        <div class="card my-card">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-activity"></i> Network Health
                                </h5>
                            </div>
                            <div class="card-body">
                                <div id="healthMetrics">
                                    <p class="text-muted text-center">Loading metrics...</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Real-time Activity -->
                <div class="row g-4">
                    <div class="col-12">
                        <div class="card my-card">
                            <div class="card-header bg-white">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-activity"></i> Real-time Packet Monitoring
                                </h5>
                            </div>
                            <div class="card-body">
                                <div class="filter-section">
                                    <div class="row">
                                        <div class="col-md-3">
                                            <label class="form-label">Protocol Filter</label>
                                            <select class="form-select form-select-sm" id="protocolFilter" onchange="filterPackets()">
                                                <option value="">All Protocols</option>
                                                <option value="TCP">TCP</option>
                                                <option value="UDP">UDP</option>
                                                <option value="ICMP">ICMP</option>
                                            </select>
                                        </div>
                                        <div class="col-md-3">
                                            <label class="form-label">Time Range</label>
                                            <select class="form-select form-select-sm" onchange="loadPacketActivity()">
                                                <option>Last 5 minutes</option>
                                                <option>Last 15 minutes</option>
                                                <option>Last hour</option>
                                            </select>
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label">Search IP</label>
                                            <input type="text" class="form-control form-control-sm" 
                                                   id="ipSearch" placeholder="e.g., 192.168.1.1" onkeyup="filterPackets()">
                                        </div>
                                    </div>
                                </div>

                                <div id="packetActivityList" style="max-height: 400px; overflow-y: auto;">
                                    <p class="text-muted text-center">Loading packet data...</p>
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
            loadNetworkAnalytics();
            setInterval(loadNetworkAnalytics, 5000); // Refresh every 5 seconds
        });

        // ==================== MAIN LOAD FUNCTION ====================
        function loadNetworkAnalytics() {
            loadMetrics();
            loadBandwidthChart();
            loadProtocolChart();
            loadTopTalkers();
            loadBandwidthByProtocol();
            loadActiveConnections();
            loadHealthMetrics();
            loadPacketActivity();
        }

        // ==================== METRICS ====================
        function loadMetrics() {
            const metrics = {
                totalPackets: 152847,
                activeFlows: 42,
                totalBandwidth: 1250.5,
                avgLatency: 12.3
            };

            $('#totalPackets').text(metrics.totalPackets.toLocaleString());
            $('#activeFlows').text(metrics.activeFlows);
            $('#totalBandwidth').text(metrics.totalBandwidth.toFixed(1) + ' MB');
            $('#avgLatency').text(metrics.avgLatency.toFixed(1) + ' ms');
            $('#connCounter').text(metrics.activeFlows + ' Live');
        }

        // ==================== BANDWIDTH CHART ====================
        let bandwidthChart = null;
        function loadBandwidthChart() {
            const ctx = document.getElementById('bandwidthChart');
            if (!ctx) return;

            const data = {
                labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '23:59'],
                datasets: [{
                    label: 'Upload (MB)',
                    data: [100, 150, 200, 250, 300, 280, 180],
                    borderColor: '#17a2b8',
                    backgroundColor: 'rgba(23, 162, 184, 0.1)',
                    tension: 0.4,
                    fill: true
                }, {
                    label: 'Download (MB)',
                    data: [200, 280, 350, 420, 380, 290, 220],
                    borderColor: '#0c5460',
                    backgroundColor: 'rgba(12, 84, 96, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            };

            if (bandwidthChart) bandwidthChart.destroy();
            bandwidthChart = new Chart(ctx, {
                type: 'line',
                data: data,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: true } },
                    scales: { y: { beginAtZero: true } }
                }
            });
        }

        // ==================== PROTOCOL CHART ====================
        let protocolChart = null;
        function loadProtocolChart() {
            const ctx = document.getElementById('protocolChart');
            if (!ctx) return;

            const data = {
                labels: ['TCP', 'UDP', 'ICMP', 'Other'],
                datasets: [{
                    data: [55, 30, 10, 5],
                    backgroundColor: ['#17a2b8', '#0c5460', '#20c997', '#6c757d']
                }]
            };

            if (protocolChart) protocolChart.destroy();
            protocolChart = new Chart(ctx, {
                type: 'doughnut',
                data: data,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'right' } }
                }
            });
        }

        // ==================== TOP TALKERS ====================
        function loadTopTalkers() {
            const talkers = [
                { ip: '192.168.1.100', packets: 45000, bytes: 5200000, % : 28 },
                { ip: '10.0.0.50', packets: 32000, bytes: 3100000, % : 20 },
                { ip: '172.16.0.1', packets: 28000, bytes: 2800000, % : 18 },
                { ip: '8.8.8.8', packets: 22000, bytes: 2100000, % : 14 },
                { ip: '1.1.1.1', packets: 18000, bytes: 1700000, % : 12 }
            ];

            let html = '';
            talkers.forEach(talker => {
                html += `
                    <div class="flow-card card mb-2">
                        <div class="card-body p-3">
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <strong>${talker.ip}</strong>
                                <span class="protocol-badge">${talker.packets.toLocaleString()} packets</span>
                            </div>
                            <div class="bandwidth-bar" style="width: ${talker['%']}%"></div>
                            <small class="text-muted">Data: ${(talker.bytes / 1000000).toFixed(1)} MB (${talker['%']}%)</small>
                        </div>
                    </div>
                `;
            });

            $('#topTalkersList').html(html);
        }

        // ==================== BANDWIDTH BY PROTOCOL ====================
        function loadBandwidthByProtocol() {
            const protocols = [
                { name: 'TCP', bandwidth: 850, color: '#17a2b8' },
                { name: 'UDP', bandwidth: 320, color: '#0c5460' },
                { name: 'ICMP', bandwidth: 65, color: '#20c997' },
                { name: 'Other', bandwidth: 15, color: '#6c757d' }
            ];

            let html = '';
            protocols.forEach(proto => {
                const percentage = (proto.bandwidth / 1250) * 100;
                html += `
                    <div class="bandwidth-usage">
                        <div class="bandwidth-label">${proto.name}</div>
                        <div class="bandwidth-bar-container">
                            <div class="bandwidth-bar-fill" style="width: ${percentage}%; background: ${proto.color};"></div>
                        </div>
                        <div class="bandwidth-value">${proto.bandwidth} MB</div>
                    </div>
                `;
            });

            $('#bandwidthByProtocol').html(html);
        }

        // ==================== ACTIVE CONNECTIONS ====================
        function loadActiveConnections() {
            const connections = [
                { src: '192.168.1.100:54321', dst: '8.8.8.8:443', proto: 'TCP', packets: 450, status: 'Active' },
                { src: '10.0.0.50:5353', dst: '224.0.0.251:5353', proto: 'UDP', packets: 125, status: 'Active' },
                { src: '172.16.0.1:22', dst: '203.0.113.45:55000', proto: 'TCP', packets: 89, status: 'Active' },
                { src: '192.168.1.101:3000', dst: '192.168.1.50:80', proto: 'TCP', packets: 234, status: 'Active' }
            ];

            let html = '';
            connections.forEach(conn => {
                html += `
                    <div class="connection-flow">
                        <span>${conn.src}</span>
                        <span class="arrow">→</span>
                        <span>${conn.dst}</span>
                        <span class="ms-auto">
                            <span class="protocol-badge">${conn.proto}</span>
                            <span class="badge bg-success">${conn.packets}</span>
                        </span>
                    </div>
                `;
            });

            $('#activeConnectionsList').html(html);
        }

        // ==================== HEALTH METRICS ====================
        function loadHealthMetrics() {
            const metrics = [
                { label: 'Packet Loss', value: '0.02%', status: 'good' },
                { label: 'Jitter', value: '1.2 ms', status: 'good' },
                { label: 'DNS Resolution', value: '12 ms', status: 'good' },
                { label: 'TCP Retransmission', value: '0.1%', status: 'good' }
            ];

            let html = '';
            metrics.forEach(metric => {
                const indicatorClass = `latency-${metric.status}`;
                html += `
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <span>${metric.label}</span>
                        <span class="latency-indicator ${indicatorClass}">${metric.value}</span>
                    </div>
                `;
            });

            $('#healthMetrics').html(html);
        }

        // ==================== PACKET ACTIVITY ====================
        function loadPacketActivity() {
            const packets = [
                { time: new Date(Date.now() - 0*1000).toLocaleTimeString(), src: '192.168.1.100', dst: '8.8.8.8', proto: 'TCP', size: 1500, type: 'normal' },
                { time: new Date(Date.now() - 2*1000).toLocaleTimeString(), src: '10.0.0.50', dst: '224.0.0.251', proto: 'UDP', size: 256, type: 'normal' },
                { time: new Date(Date.now() - 5*1000).toLocaleTimeString(), src: '172.16.0.1', dst: '203.0.113.45', proto: 'TCP', size: 5000, type: 'spike' },
                { time: new Date(Date.now() - 8*1000).toLocaleTimeString(), src: '192.168.1.101', dst: '192.168.1.50', proto: 'TCP', size: 1024, type: 'normal' }
            ];

            let html = '';
            packets.forEach(pkt => {
                const itemClass = pkt.type === 'spike' ? 'packet-item spike' : 'packet-item';
                html += `
                    <div class="${itemClass}">
                        <div class="d-flex justify-content-between mb-1">
                            <strong>${pkt.time}</strong>
                            <span class="protocol-badge">${pkt.proto}</span>
                        </div>
                        <small class="d-block">${pkt.src} → ${pkt.dst}</small>
                        <small class="text-muted">Size: ${pkt.size} bytes</small>
                    </div>
                `;
            });

            $('#packetActivityList').html(html);
        }

        // ==================== FILTER FUNCTIONS ====================
        function filterPackets() {
            loadPacketActivity();
        }
    </script>
</body>
</html>