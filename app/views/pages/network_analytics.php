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
            $.ajax({
                url: LOGS_URL + '?_=' + Date.now(),
                dataType: 'json',
                success: function(trafficData) {
                    if (!Array.isArray(trafficData) || trafficData.length === 0) {
                        $('#totalPackets').text('0');
                        $('#activeFlows').text('0');
                        $('#totalBandwidth').text('0 MB');
                        $('#avgLatency').text('0 ms');
                        $('#connCounter').text('0 Live');
                        return;
                    }

                    // Calculate metrics from traffic data
                    let totalPackets = 0;
                    let totalBytes = 0;
                    let totalDuration = 0;
                    let flowCount = trafficData.length;

                    trafficData.forEach(flow => {
                        if (!flow) return;
                        totalPackets += (parseInt(flow["Total Fwd Packets"]) || 0) + (parseInt(flow["Total Backward Packets"]) || 0);
                        totalBytes += parseFloat(flow["Flow Bytes/s"]) || 0;
                        totalDuration += parseFloat(flow["Flow Duration"]) || 0;
                    });

                    const totalBandwidthMB = totalBytes / 1000000;
                    const avgLatency = totalDuration > 0 ? (totalDuration / flowCount) : 0;

                    $('#totalPackets').text(totalPackets.toLocaleString());
                    $('#activeFlows').text(flowCount);
                    $('#totalBandwidth').text(totalBandwidthMB.toFixed(1) + ' MB');
                    $('#avgLatency').text(avgLatency.toFixed(1) + ' ms');
                    $('#connCounter').text(flowCount + ' Live');
                },
                error: function() {
                    $('#totalPackets').text('0');
                    $('#activeFlows').text('0');
                    $('#totalBandwidth').text('0 MB');
                    $('#avgLatency').text('0 ms');
                    $('#connCounter').text('0 Live');
                }
            });
        }

        // ==================== BANDWIDTH CHART ====================
        let bandwidthChart = null;
        let bandwidthHistory = { upload: [], download: [], labels: [] };

        function loadBandwidthChart() {
            const ctx = document.getElementById('bandwidthChart');
            if (!ctx) return;

            $.ajax({
                url: LOGS_URL + '?_=' + Date.now(),
                dataType: 'json',
                success: function(trafficData) {
                    // Calculate current upload/download from traffic data
                    let totalFwd = 0;
                    let totalBwd = 0;

                    if (Array.isArray(trafficData)) {
                        trafficData.forEach(flow => {
                            if (!flow) return;
                            totalFwd += parseFloat(flow["Total Fwd Packets"]) || 0;
                            totalBwd += parseFloat(flow["Total Backward Packets"]) || 0;
                        });
                    }

                    const uploadMB = (totalFwd / 1000).toFixed(1);
                    const downloadMB = (totalBwd / 1000).toFixed(1);

                    // Add to history (keep last 20 points)
                    bandwidthHistory.upload.push(parseFloat(uploadMB));
                    bandwidthHistory.download.push(parseFloat(downloadMB));
                    bandwidthHistory.labels.push(new Date().toLocaleTimeString());

                    if (bandwidthHistory.upload.length > 20) {
                        bandwidthHistory.upload.shift();
                        bandwidthHistory.download.shift();
                        bandwidthHistory.labels.shift();
                    }

                    const data = {
                        labels: bandwidthHistory.labels,
                        datasets: [{
                            label: 'Forward (KB)',
                            data: bandwidthHistory.upload,
                            borderColor: '#17a2b8',
                            backgroundColor: 'rgba(23, 162, 184, 0.1)',
                            tension: 0.4,
                            fill: true
                        }, {
                            label: 'Backward (KB)',
                            data: bandwidthHistory.download,
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
                },
                error: function() {
                    const data = {
                        labels: ['No data'],
                        datasets: [{
                            label: 'Forward (KB)',
                            data: [0],
                            borderColor: '#17a2b8',
                            backgroundColor: 'rgba(23, 162, 184, 0.1)'
                        }, {
                            label: 'Backward (KB)',
                            data: [0],
                            borderColor: '#0c5460',
                            backgroundColor: 'rgba(12, 84, 96, 0.1)'
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
            });
        }

        // ==================== PROTOCOL CHART ====================
        let protocolChart = null;
        function loadProtocolChart() {
            const ctx = document.getElementById('protocolChart');
            if (!ctx) return;

            $.ajax({
                url: LOGS_URL + '?_=' + Date.now(),
                dataType: 'json',
                success: function(trafficData) {
                    let protocolCounts = { TCP: 0, UDP: 0, ICMP: 0, Other: 0 };

                    if (Array.isArray(trafficData)) {
                        trafficData.forEach(flow => {
                            if (!flow) return;
                            const proto = parseInt(flow["Protocol"]);
                            if (proto === 6) protocolCounts.TCP++;
                            else if (proto === 17) protocolCounts.UDP++;
                            else if (proto === 1) protocolCounts.ICMP++;
                            else protocolCounts.Other++;
                        });
                    }

                    const data = {
                        labels: ['TCP', 'UDP', 'ICMP', 'Other'],
                        datasets: [{
                            data: [
                                protocolCounts.TCP,
                                protocolCounts.UDP,
                                protocolCounts.ICMP,
                                protocolCounts.Other
                            ],
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
                },
                error: function() {
                    const data = {
                        labels: ['No Data'],
                        datasets: [{
                            data: [1],
                            backgroundColor: ['#e9ecef']
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
            });
        }

        // ==================== TOP TALKERS ====================
        function loadTopTalkers() {
            $.ajax({
                url: LOGS_URL + '?_=' + Date.now(),
                dataType: 'json',
                success: function(trafficData) {
                    if (!Array.isArray(trafficData) || trafficData.length === 0) {
                        $('#topTalkersList').html('<p class="text-muted text-center">No network traffic detected</p>');
                        return;
                    }

                    // Aggregate data by source IP
                    let ipData = {};
                    trafficData.forEach(flow => {
                        if (!flow) return;
                        const srcIP = flow["Src IP"];
                        if (!srcIP) return;

                        if (!ipData[srcIP]) {
                            ipData[srcIP] = { packets: 0, bytes: 0 };
                        }
                        ipData[srcIP].packets += (parseInt(flow["Total Fwd Packets"]) || 0);
                        ipData[srcIP].bytes += (parseFloat(flow["Flow Bytes/s"]) || 0);
                    });

                    // Convert to array and sort
                    let talkers = Object.entries(ipData).map(([ip, data]) => ({
                        ip: ip,
                        packets: data.packets,
                        bytes: data.bytes
                    })).sort((a, b) => b.packets - a.packets).slice(0, 5);

                    // Calculate percentages
                    const maxPackets = talkers.length > 0 ? talkers[0].packets : 1;
                    talkers.forEach(t => {
                        t.percent = (t.packets / maxPackets) * 100;
                    });

                    let html = '';
                    talkers.forEach(talker => {
                        html += `
                            <div class="flow-card card mb-2">
                                <div class="card-body p-3">
                                    <div class="d-flex justify-content-between align-items-center mb-2">
                                        <strong>${talker.ip}</strong>
                                        <span class="protocol-badge">${talker.packets.toLocaleString()} packets</span>
                                    </div>
                                    <div class="bandwidth-bar" style="width: ${talker.percent}%"></div>
                                    <small class="text-muted">Data: ${(talker.bytes / 1000000).toFixed(1)} MB (${talker.percent.toFixed(1)}%)</small>
                                </div>
                            </div>
                        `;
                    });

                    $('#topTalkersList').html(html);
                },
                error: function() {
                    $('#topTalkersList').html('<p class="text-muted text-center">Waiting for traffic data...</p>');
                }
            });
        }

        // ==================== BANDWIDTH BY PROTOCOL ====================
        function loadBandwidthByProtocol() {
            $.ajax({
                url: LOGS_URL + '?_=' + Date.now(),
                dataType: 'json',
                success: function(trafficData) {
                    let protocolBandwidth = { TCP: 0, UDP: 0, ICMP: 0, Other: 0 };

                    if (Array.isArray(trafficData)) {
                        trafficData.forEach(flow => {
                            if (!flow) return;
                            const proto = parseInt(flow["Protocol"]);
                            const bytes = parseFloat(flow["Flow Bytes/s"]) || 0;

                            if (proto === 6) protocolBandwidth.TCP += bytes;
                            else if (proto === 17) protocolBandwidth.UDP += bytes;
                            else if (proto === 1) protocolBandwidth.ICMP += bytes;
                            else protocolBandwidth.Other += bytes;
                        });
                    }

                    let protocols = [
                        { name: 'TCP', bandwidth: (protocolBandwidth.TCP / 1000000).toFixed(1), color: '#17a2b8' },
                        { name: 'UDP', bandwidth: (protocolBandwidth.UDP / 1000000).toFixed(1), color: '#0c5460' },
                        { name: 'ICMP', bandwidth: (protocolBandwidth.ICMP / 1000000).toFixed(1), color: '#20c997' },
                        { name: 'Other', bandwidth: (protocolBandwidth.Other / 1000000).toFixed(1), color: '#6c757d' }
                    ];

                    let totalBandwidth = protocols.reduce((sum, p) => sum + parseFloat(p.bandwidth), 0);
                    if (totalBandwidth === 0) totalBandwidth = 1;

                    let html = '';
                    protocols.forEach(proto => {
                        const percentage = (parseFloat(proto.bandwidth) / totalBandwidth) * 100;
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
                },
                error: function() {
                    $('#bandwidthByProtocol').html('<p class="text-muted text-center">Waiting for traffic data...</p>');
                }
            });
        }

        // ==================== ACTIVE CONNECTIONS ====================
        function loadActiveConnections() {
            $.ajax({
                url: LOGS_URL + '?_=' + Date.now(),
                dataType: 'json',
                success: function(trafficData) {
                    if (!Array.isArray(trafficData) || trafficData.length === 0) {
                        $('#activeConnectionsList').html('<p class="text-muted text-center">No active connections</p>');
                        return;
                    }

                    let html = '';
                    trafficData.slice(-10).reverse().forEach(flow => {
                        if (!flow) return;
                        const proto = parseInt(flow["Protocol"]) === 6 ? 'TCP' :
                                     parseInt(flow["Protocol"]) === 17 ? 'UDP' :
                                     parseInt(flow["Protocol"]) === 1 ? 'ICMP' : 'Other';
                        const packets = (parseInt(flow["Total Fwd Packets"]) || 0) + (parseInt(flow["Total Backward Packets"]) || 0);

                        html += `
                            <div class="connection-flow">
                                <span>${flow["Src IP"] || 'N/A'}:${flow["Src Port"] || '?'}</span>
                                <span class="arrow">→</span>
                                <span>${flow["Dst IP"] || 'N/A'}:${flow["Dst Port"] || '?'}</span>
                                <span class="ms-auto">
                                    <span class="protocol-badge">${proto}</span>
                                    <span class="badge bg-success">${packets}</span>
                                </span>
                            </div>
                        `;
                    });

                    $('#activeConnectionsList').html(html);
                },
                error: function() {
                    $('#activeConnectionsList').html('<p class="text-muted text-center">Waiting for traffic data...</p>');
                }
            });
        }

        // ==================== HEALTH METRICS ====================
        function loadHealthMetrics() {
            $.ajax({
                url: LOGS_URL + '?_=' + Date.now(),
                dataType: 'json',
                success: function(trafficData) {
                    if (!Array.isArray(trafficData) || trafficData.length === 0) {
                        $('#healthMetrics').html('<p class="text-muted text-center">No health metrics available</p>');
                        return;
                    }

                    // Calculate health metrics
                    let totalDuration = 0;
                    let totalFlowRate = 0;
                    let highRateCount = 0;

                    trafficData.forEach(flow => {
                        if (!flow) return;
                        totalDuration += parseFloat(flow["Flow Duration"]) || 0;
                        const flowRate = parseFloat(flow["Flow Packets/s"]) || 0;
                        totalFlowRate += flowRate;
                        if (flowRate > 1000) highRateCount++;
                    });

                    const avgLatency = trafficData.length > 0 ? (totalDuration / trafficData.length) : 0;
                    const avgFlowRate = trafficData.length > 0 ? (totalFlowRate / trafficData.length) : 0;
                    const packetLoss = (highRateCount / trafficData.length) * 100;

                    const latencyStatus = avgLatency < 50 ? 'good' : avgLatency < 150 ? 'warning' : 'critical';
                    const throughputStatus = avgFlowRate > 100 ? 'good' : avgFlowRate > 10 ? 'warning' : 'critical';
                    const lossStatus = packetLoss < 5 ? 'good' : packetLoss < 20 ? 'warning' : 'critical';

                    let html = `
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <span>Average Latency</span>
                            <span class="latency-indicator latency-${latencyStatus}">${avgLatency.toFixed(1)} ms</span>
                        </div>
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <span>Throughput</span>
                            <span class="latency-indicator latency-${throughputStatus}">${avgFlowRate.toFixed(1)} pkt/s</span>
                        </div>
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <span>High Traffic Flows</span>
                            <span class="latency-indicator latency-${lossStatus}">${packetLoss.toFixed(1)}%</span>
                        </div>
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <span>Total Flows</span>
                            <span class="latency-indicator latency-good">${trafficData.length}</span>
                        </div>
                    `;

                    $('#healthMetrics').html(html);
                },
                error: function() {
                    $('#healthMetrics').html('<p class="text-muted text-center">Waiting for traffic data...</p>');
                }
            });
        }

        // ==================== PACKET ACTIVITY ====================
        function loadPacketActivity() {
            $.ajax({
                url: LOGS_URL + '?_=' + Date.now(),
                dataType: 'json',
                success: function(trafficData) {
                    if (!Array.isArray(trafficData) || trafficData.length === 0) {
                        $('#packetActivityList').html('<p class="text-muted text-center">No packet activity detected</p>');
                        return;
                    }

                    let html = '';
                    trafficData.slice(-15).reverse().forEach(flow => {
                        if (!flow) return;

                        const proto = parseInt(flow["Protocol"]) === 6 ? 'TCP' :
                                     parseInt(flow["Protocol"]) === 17 ? 'UDP' :
                                     parseInt(flow["Protocol"]) === 1 ? 'ICMP' : 'Other';
                        const flowRate = parseFloat(flow["Flow Packets/s"]) || 0;
                        const itemClass = flowRate > 1000 ? 'packet-item spike' : 'packet-item';
                        const totalPackets = (parseInt(flow["Total Fwd Packets"]) || 0) + (parseInt(flow["Total Backward Packets"]) || 0);
                        const bytes = parseFloat(flow["Flow Bytes/s"]) || 0;

                        html += `
                            <div class="${itemClass}">
                                <div class="d-flex justify-content-between mb-1">
                                    <strong>${flow["Timestamp"] || 'N/A'}</strong>
                                    <span class="protocol-badge">${proto}</span>
                                </div>
                                <small class="d-block">${flow["Src IP"] || 'N/A'}:${flow["Src Port"] || '?'} → ${flow["Dst IP"] || 'N/A'}:${flow["Dst Port"] || '?'}</small>
                                <small class="text-muted">Packets: ${totalPackets} | Bytes: ${bytes.toFixed(0)}/s</small>
                            </div>
                        `;
                    });

                    $('#packetActivityList').html(html);
                },
                error: function() {
                    $('#packetActivityList').html('<p class="text-muted text-center">Waiting for traffic data...</p>');
                }
            });
        }

        // ==================== FILTER FUNCTIONS ====================
        function filterPackets() {
            loadPacketActivity();
        }
    </script>
</body>
</html>