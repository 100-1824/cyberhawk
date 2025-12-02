<?php
$httpMethod = $_SERVER['REQUEST_METHOD'];
$uri = $_SERVER['REQUEST_URI'];

// Remove query string (?foo=bar) from URI
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
    <title>CyberHawk Network Dashboard</title>
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

        .table-responsive {
            overflow-x: auto;
        }

        #confirmClearModal .modal-header {
            background: linear-gradient(135deg, #0a74da, #061a40);
            color: #fff;
        }

        #confirmClearModal .modal-footer {
            background: white;
        }

        .my-card {
            border: 2px solid #0a74da;
        }

        .gradient-text {
            background: linear-gradient(135deg, #0a74da, #061a40);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            color: transparent;
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

        .threat-indicator {
            max-width: 150px;
            max-height: 150px;
        }

        .security-score {
            font-size: 2rem;
            font-weight: bold;
            color: #28a745;
        }

        .attack-type-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            margin: 2px;
        }

        .threat-low {
            background-color: #28a745;
            color: white;
        }

        .threat-medium {
            background-color: #ffc107;
            color: black;
        }

        .threat-high {
            background-color: #dc3545;
            color: white;
        }

        .attack-entry {
            padding: 8px;
            margin-bottom: 8px;
            background-color: #f8f9fa;
            border-left: 3px solid #dc3545;
            border-radius: 4px;
            font-size: 0.85rem;
        }

        .attack-timeline {
            max-height: 200px;
            overflow-y: auto;
        }

        .right-border {
            border-right: 1px solid #dee2e6;
        }

        .equal-height-row .card {
            height: 100%;
        }
    </style>
</head>

<body>
    <?php include 'app/views/common/header.php'; ?>

    <div class="d-flex" style="min-height: calc(100vh - 60px);">
        <?php include 'app/views/common/sidebar.php'; ?>

        <div class="main-content flex-grow-1 p-4">
            <div class="container-fluid">

                <!-- Clear Modal -->
                <div class="modal fade" id="confirmClearModal" tabindex="-1" aria-labelledby="confirmClearModalLabel"
                    aria-hidden="true">
                    <div class="modal-dialog modal-dialog-centered">
                        <div class="modal-content">
                            <div class="modal-header bg-warning text-dark">
                                <h5 class="modal-title" id="confirmClearModalLabel">Confirm Clear Logs</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"
                                    aria-label="Close"></button>
                            </div>
                            <div class="modal-body">
                                Are you sure you want to clear all traffic logs? This action cannot be undone.
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-danger" id="confirmClearBtn">Clear</button>
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Top Row -->
                <div class="row g-4 mt-4">
                    <!-- Real-Time Threat Analysis Card -->
                    <div class="col-md-6 d-flex">
                        <div class="card flex-fill border border-2 border-primary" style="height: 400px;">
                            <!-- Header with Live Indicator -->
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="card-title mb-0 gradient-text">
                                    <span class="live-indicator"></span> Real-Time Threat Analysis
                                </h5>
                                <div>
                                    <span class="badge bg-success" id="modelStatus">Model Active</span>
                                    <span class="badge bg-info" id="packetRate">0 pkt/s</span>
                                </div>
                            </div>

                            <!-- Body with Charts -->
                            <div class="card-body">
                                <div class="row h-100">
                                    <!-- Left: Threat Level Gauge -->
                                    <div class="col-4 d-flex flex-column justify-content-center align-items-center">
                                        <h6 class="text-center mb-2">Threat Level</h6>
                                        <canvas id="threatGauge" class="threat-indicator"></canvas>
                                        <div class="mt-2 text-center">
                                            <div class="security-score" id="securityScore">85</div>
                                            <small class="text-muted">Security Score</small>
                                        </div>
                                    </div>

                                    <!-- Middle: Attack Distribution -->
                                    <div class="col-4">
                                        <h6 class="text-center mb-2 mt-4">Attack Types Detected</h6>
                                        <canvas id="attackPieChart" style="max-height: 180px; width: 100%;"></canvas>
                                        <div class="text-center mt-2" id="attackBadges">
                                            <!-- Dynamic badges will appear here -->
                                        </div>
                                    </div>

                                    <!-- Right: Real-time Activity -->
                                    <div class="col-4">
                                        <h6 class="text-center mb-2">Network Activity (5 min)</h6>
                                        <div style="height: 200px; width: 100%;">
                                            <canvas id="activityChart" style="max-height: 200px; width: 100%;"></canvas>
                                        </div>
                                        <div class="mt-2 text-center">
                                            <small class="text-muted">
                                                <span id="suspiciousFlows">0</span> Suspicious Flows
                                            </small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- CLI Card -->
                    <div class="col-md-6 d-flex">
                        <div class="card flex-fill" style="height: 400px; display: flex; flex-direction: column;">
                            <div class="card-header my-card d-flex justify-content-between align-items-center">
                                <h5 class="card-title mb-0 gradient-text">CLI</h5>
                            </div>

                            <!-- Logs container fills remaining space, scrolls internally -->
                            <div id="logContainer" class="my-card"
                                style="flex-grow: 1; overflow-y: auto; background:linear-gradient(135deg, #0a74da, #061a40); color: #0f0; font-family: monospace; padding: 10px; white-space: pre-wrap;">
                                [INFO] System initialized...<br />
                            </div>

                            <!-- Buttons container fixed height -->
                            <div class="d-flex justify-content-around align-items-center my-card"
                                style="height: 80px; padding: 10px; background: #f8f9fa;">
                                <button type="button" id="startLogsBtn" class="btn btn-primary" onclick="startLogs()">
                                    <i class="bi bi-arrow-clockwise me-2"></i>Start Logs
                                </button>
                                <!-- <button type="button" id="startModelBtn" class="btn btn-success" onclick="startModel()">
                                    <i class="bi bi-play me-2"></i>Start Model
                                </button> -->
                                <button id="stopLogsBtn" type="button" class="btn btn-danger" onclick="stopLogs()">
                                    <i class="bi bi-stop-circle me-2"></i>Stop Logs
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Advanced Security Metrics -->
                <div class="col-12 mt-4">
                    <div class="card w-100">
                        <div class="card-header d-flex justify-content-between align-items-center my-card">
                            <h5 class="card-title mb-0 gradient-text">Advanced Security Metrics</h5>
                        </div>
                        <div class="card-body my-card">
                            <div class="row">
                                <!-- Protocol Distribution -->
                                <div class="col-md-3 right-border">
                                    <h6 class="text-center">Protocol Distribution</h6>
                                    <canvas id="protocolChart"></canvas>
                                </div>

                                <!-- Top Talkers -->
                                <div class="col-md-3 right-border">
                                    <h6 class="text-center">Top Source IPs</h6>
                                    <div id="topTalkers" class="small">
                                        <!-- Dynamic list -->
                                    </div>
                                </div>

                                <!-- Attack Timeline -->
                                <div class="col-md-3 right-border">
                                    <h6 class="text-center">Recent Attacks</h6>
                                    <div id="attackTimeline" style="max-height: 200px; overflow-y: auto;" class="attack-timeline">
                                        <!-- Dynamic timeline -->
                                    </div>
                                </div>

                                <!-- Port Analysis -->
                                <div class="col-md-3">
                                    <h6 class="text-center">Port Scan Activity</h6>
                                    <canvas id="portScanChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Live Traffic Logs -->
                <div class="col-12 mt-4">
                    <div class="card w-100">
                        <div class="card-header d-flex justify-content-between align-items-center my-card">
                            <h5 class="card-title mb-0 gradient-text">Live Traffic Logs</h5>
                            <button id="clearLogsBtn" class="btn btn-sm btn-outline-danger" title="Clear Logs"
                                onclick="clearTrafficLogs()">
                                <i class="bi bi-trash"></i>
                            </button>
                        </div>
                        <div class="card-body my-card">
                            <input type="text" id="searchInput" class="form-control mb-3"
                                placeholder="Search by IP or protocol..." />

                            <div class="table-responsive" style="overflow-x: auto; max-height: 300px;">
                                <div id="messageBox"
                                    style="display: none; padding: 10px; margin-bottom: 15px; border-radius: 5px;">
                                </div>

                                <table class="table table-striped table-hover" id="logsTable">
                                    <thead class="table-dark text-center">
                                        <tr>
                                            <th>Timestamp</th>
                                            <th>Source IP</th>
                                            <th>Source Port</th>
                                            <th>Destination IP</th>
                                            <th>Destination Port</th>
                                            <th>Protocol</th>
                                            <th>Flow Duration</th>
                                            <th>Total Fwd Packets</th>
                                            <th>Total Bwd Packets</th>
                                            <th>Flow Bytes/s</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <!-- Dynamic Rows from JS -->
                                    </tbody>
                                </table>
                            </div>

                            <div class="mt-3 gap-2">
                                <div id="logsLoadingSpinner" class="mt-3 d-none text-center">
                                    <div class="spinner-border text-primary" role="status">
                                        <span class="visually-hidden">Loading...</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Live Alerts -->
                <div class="col-12 mt-4">
                    <div class="card w-100">
                        <div class="card-header my-card d-flex justify-content-between align-items-center">
                            <h5 class="card-title mb-0 gradient-text">Live Alerts</h5>
                            <button class="btn btn-sm btn-outline-secondary refresh-btn" title="Refresh"
                                onclick="refreshAlerts()">
                                <i class="bi bi-arrow-clockwise"></i>
                            </button>
                        </div>
                        <div class="card-body my-card">
                            <div class="table-responsive" style="overflow-x: auto;">
                                <table class="table table-bordered table-striped table-sm mb-0">
                                    <thead class="table-light text-center">
                                        <tr>
                                            <th>Timestamp</th>
                                            <th>Source IP</th>
                                            <th>Source Port</th>
                                            <th>Destination IP</th>
                                            <th>Destination Port</th>
                                            <th>Protocol</th>
                                            <th>Flow Duration</th>
                                            <th>Total Fwd Packets</th>
                                            <th>Total Bwd Packets</th>
                                            <th>Flow Bytes/s</th>
                                        </tr>
                                    </thead>
                                    <tbody id="alerts_table">
                                        <tr>
                                            <td colspan="10" class="text-center">No alerts currently.</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Model Status -->
                <div class="col-md-12 mt-4">
                    <div class="card position-relative">
                        <div class="card-header my-card">
                            <h5 class="card-title mb-0 gradient-text">Model Performance</h5>
                        </div>
                        <div class="card-body my-card">
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="alert alert-success" role="alert">
                                        <h6 class="alert-heading">Active Model: <strong>Deep Neural Network (TensorFlow)</strong></h6>
                                        <hr>
                                        <p class="mb-1">Training Dataset: <strong>CICIDS2022 Improved</strong></p>
                                        <p class="mb-0">Architecture: <strong>4 Dense Layers with Dropout</strong></p>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="card bg-light">
                                        <div class="card-body">
                                            <h6 class="card-title">Performance Metrics</h6>
                                            <ul class="list-unstyled mb-0">
                                                <li><strong>Test Accuracy:</strong> <span class="badge bg-success">97.73%</span></li>
                                                <li><strong>F1-Score:</strong> <span class="badge bg-success">97.20%</span></li>
                                                <li><strong>Precision:</strong> <span class="badge bg-info">96.89%</span></li>
                                                <li><strong>Recall:</strong> <span class="badge bg-info">97.52%</span></li>
                                            </ul>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="row mt-3">
                                <div class="col-12">
                                    <div class="card bg-light">
                                        <div class="card-body">
                                            <h6 class="card-title">Attack Detection Capabilities</h6>
                                            <div class="row">
                                                <div class="col-md-6">
                                                    <p class="mb-1"><i class="bi bi-check-circle text-success"></i> <strong>DoS/DDoS:</strong> Near-perfect detection (99%+)</p>
                                                    <p class="mb-1"><i class="bi bi-check-circle text-success"></i> <strong>Port Scan:</strong> High accuracy (98%+)</p>
                                                    <p class="mb-1"><i class="bi bi-check-circle text-success"></i> <strong>Brute Force:</strong> Excellent detection (97%+)</p>
                                                    <p class="mb-1"><i class="bi bi-check-circle text-success"></i> <strong>Botnet:</strong> Strong performance (96%+)</p>
                                                </div>
                                                <div class="col-md-6">
                                                    <p class="mb-1"><i class="bi bi-check-circle text-success"></i> <strong>Infiltration:</strong> Good detection (95%+)</p>
                                                    <p class="mb-1"><i class="bi bi-info-circle text-warning"></i> <strong>XSS Attacks:</strong> Moderate detection (85%)</p>
                                                    <p class="mb-1"><i class="bi bi-info-circle text-warning"></i> <strong>Web Brute Force:</strong> Lower accuracy (80%)</p>
                                                    <!-- <p class="mb-0"><small class="text-muted">*Web attack detection limitations documented</small></p> -->
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    </div>

</body>
<script>
      const CONFIG = {
        UPDATE_INTERVAL: 3000, // 3 seconds
        LOGS_CHECK_TIMEOUT: 15000, // 15 seconds
        ALERT_CHECK_INTERVAL: 3000, // 3 seconds
        MAX_TIMELINE_ENTRIES: 5,
        MAX_TOP_TALKERS: 5,
        SUSPICIOUS_THRESHOLDS: {
            SYN_FLAG: 5,
            RST_FLAG: 3,
            PACKETS_PER_SEC: 1000,
            BYTES_PER_SEC: 1000000
        }
    };

    // Global interval holders to prevent memory leaks
    let intervals = {
        dashboardMetrics: null,
        alertsCheck: null,
        logsCheck: null,
        systemStatus: null
    };

    // Chart instances
    let charts = {
        threatGauge: null,
        attackPie: null,
        activity: null,
        protocol: null,
        portScan: null
    };

    // Initialize on document ready
    $(document).ready(function() {
        initializeCharts();
        startDashboardUpdates();
        setupSearchFilter();

        // Initialize log container
        const logContainer = document.getElementById('logContainer');
        if (logContainer) {
            logContainer.textContent = "[INFO] System initialized...\n[INFO] Waiting for data...\n";
        }
    });

    // Clean up intervals on page unload
    $(window).on('beforeunload', function() {
        Object.values(intervals).forEach(interval => {
            if (interval) clearInterval(interval);
        });
    });

    // Initialize all charts
    function initializeCharts() {
        initThreatGauge();
        initAttackPieChart();
        initActivityChart();
        initProtocolChart();
        initPortScanChart();
    }

    // Start all dashboard updates
    function startDashboardUpdates() {
        // Clear existing intervals
        stopDashboardUpdates();

        // Initial load
        updateDashboardMetrics();
        loadLogs();
        loadAlerts();

        // Set up periodic updates
        intervals.dashboardMetrics = setInterval(updateDashboardMetrics, CONFIG.UPDATE_INTERVAL);
        intervals.logsCheck = setInterval(loadLogs, CONFIG.UPDATE_INTERVAL);
        intervals.alertsCheck = setInterval(loadAlerts, CONFIG.ALERT_CHECK_INTERVAL);
    }

    // Stop all dashboard updates
    function stopDashboardUpdates() {
        Object.keys(intervals).forEach(key => {
            if (intervals[key]) {
                clearInterval(intervals[key]);
                intervals[key] = null;
            }
        });
    }

    // Threat Level Gauge (Semi-circle)
    function initThreatGauge() {
        const ctx = document.getElementById('threatGauge');
        if (!ctx) return;

        charts.threatGauge = new Chart(ctx.getContext('2d'), {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [25, 25, 25, 25],
                    backgroundColor: ['#28a745', '#ffc107', '#fd7e14', '#dc3545'],
                    borderWidth: 0
                }]
            },
            options: {
                rotation: -90,
                circumference: 180,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        enabled: false
                    }
                },
                cutout: '70%'
            }
        });
    }

    // Attack Distribution Pie Chart
    function initAttackPieChart() {
        const ctx = document.getElementById('attackPieChart');
        if (!ctx) return;

        charts.attackPie = new Chart(ctx.getContext('2d'), {
            type: 'pie',
            data: {
                labels: ['DDoS', 'Port Scan', 'SQL Injection', 'Brute Force', 'Normal'],
                datasets: [{
                    data: [0, 0, 0, 0, 100],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#6f42c1', '#28a745']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }

    // Real-time Activity Line Chart
    function initActivityChart() {
        const ctx = document.getElementById('activityChart');
        if (!ctx) return;

        charts.activity = new Chart(ctx.getContext('2d'), {
            type: 'line',
            data: {
                labels: Array(20).fill(''),
                datasets: [{
                    label: 'Normal',
                    data: Array(20).fill(0),
                    borderColor: '#28a745',
                    backgroundColor: 'rgba(40, 167, 69, 0.1)',
                    tension: 0.4,
                    borderWidth: 2
                }, {
                    label: 'Suspicious',
                    data: Array(20).fill(0),
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.4,
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    },
                    x: {
                        display: false
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                },
                animation: {
                    duration: 0 // Disable animation for smoother updates
                }
            }
        });
    }

    // Protocol Distribution Bar Chart
    function initProtocolChart() {
        const ctx = document.getElementById('protocolChart');
        if (!ctx) return;

        charts.protocol = new Chart(ctx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#0a74da', '#17a2b8', '#28a745', '#6c757d']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    // Port Scan Detection Chart
    function initPortScanChart() {
        const ctx = document.getElementById('portScanChart');
        if (!ctx) return;

        charts.portScan = new Chart(ctx.getContext('2d'), {
            type: 'radar',
            data: {
                labels: ['22', '80', '443', '3306', '8080', '3389'],
                datasets: [{
                    label: 'Scan Attempts',
                    data: [0, 0, 0, 0, 0, 0],
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.2)'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    r: {
                        beginAtZero: true,
                        max: 50
                    }
                }
            }
        });
    }

    // Update dashboard with real data
    function updateDashboardMetrics() {
        $.ajax({
            url: LOGS_URL + '?_=' + Date.now(),
            dataType: 'json',
            success: function(data) {
                if (!Array.isArray(data)) {
                    console.warn("Invalid data format:", data);
                    return;
                }

                processMetricsData(data);
            },
            error: function(xhr, status, error) {
                console.error("Error fetching metrics:", error);
            }
        });
    }

    // Process metrics data and update charts
    function processMetricsData(data) {
        // Initialize counters
        let metrics = {
            protocols: {
                tcp: 0,
                udp: 0,
                icmp: 0,
                other: 0
            },
            flags: {
                syn: 0,
                fin: 0,
                rst: 0
            },
            suspicious: 0,
            sourceIPs: {},
            destPorts: {},
            totalPackets: data.length
        };

        // Process each flow
        data.forEach(flow => {
            if (!flow) return;

            // Protocol distribution
            const proto = parseInt(flow["Protocol"]);
            if (proto === 6) metrics.protocols.tcp++;
            else if (proto === 17) metrics.protocols.udp++;
            else if (proto === 1) metrics.protocols.icmp++;
            else metrics.protocols.other++;

            // Flag analysis
            metrics.flags.syn += parseInt(flow["SYN Flag Count"]) || 0;
            metrics.flags.fin += parseInt(flow["FIN Flag Count"]) || 0;
            metrics.flags.rst += parseInt(flow["RST Flag Count"]) || 0;

            // Track source IPs
            const srcIP = flow["Src IP"];
            if (srcIP) {
                metrics.sourceIPs[srcIP] = (metrics.sourceIPs[srcIP] || 0) + 1;
            }

            // Track destination ports
            const dstPort = flow["Dst Port"];
            if (dstPort) {
                metrics.destPorts[dstPort] = (metrics.destPorts[dstPort] || 0) + 1;
            }

            // Anomaly detection
            if (isSuspiciousFlow(flow)) {
                metrics.suspicious++;
            }
        });

        updateAllCharts(metrics);
        updateDashboardUI(metrics);
    }

    // Check if flow is suspicious
    function isSuspiciousFlow(flow) {
        return (
            parseInt(flow["SYN Flag Count"]) > CONFIG.SUSPICIOUS_THRESHOLDS.SYN_FLAG ||
            parseInt(flow["RST Flag Count"]) > CONFIG.SUSPICIOUS_THRESHOLDS.RST_FLAG ||
            parseFloat(flow["Flow Packets/s"]) > CONFIG.SUSPICIOUS_THRESHOLDS.PACKETS_PER_SEC ||
            parseFloat(flow["Flow Bytes/s"]) > CONFIG.SUSPICIOUS_THRESHOLDS.BYTES_PER_SEC
        );
    }

    // Update all charts with new data
    function updateAllCharts(metrics) {
        // Update Protocol Chart
        if (charts.protocol) {
            charts.protocol.data.datasets[0].data = [
                metrics.protocols.tcp,
                metrics.protocols.udp,
                metrics.protocols.icmp,
                metrics.protocols.other
            ];
            charts.protocol.update('none');
        }

        // Update Attack Distribution
        if (charts.attackPie) {
            const ddosScore = Math.min(metrics.flags.syn * 2, 100);
            const scanScore = Object.keys(metrics.destPorts).length > 10 ? 50 : 0;
            const normalScore = Math.max(100 - ddosScore - scanScore, 0);

            charts.attackPie.data.datasets[0].data = [
                ddosScore / 4, scanScore / 4, 0, 0, normalScore
            ];
            charts.attackPie.update('none');
        }

        // Update Activity Chart
        if (charts.activity) {
            charts.activity.data.datasets[0].data.shift();
            charts.activity.data.datasets[0].data.push(metrics.totalPackets);
            charts.activity.data.datasets[1].data.shift();
            charts.activity.data.datasets[1].data.push(metrics.suspicious);
            charts.activity.update('none');
        }

        // Update Port Scan Chart
        if (charts.portScan) {
            const commonPorts = [22, 80, 443, 3306, 8080, 3389];
            const portScanData = commonPorts.map(port => metrics.destPorts[port] || 0);
            charts.portScan.data.datasets[0].data = portScanData;
            charts.portScan.update('none');
        }

        // Update Threat Gauge
        if (charts.threatGauge) {
            const securityScore = calculateSecurityScore(metrics);
            let gaugeData = [0, 0, 0, 0];
            if (securityScore > 75) gaugeData[0] = 100;
            else if (securityScore > 50) gaugeData[1] = 100;
            else if (securityScore > 25) gaugeData[2] = 100;
            else gaugeData[3] = 100;

            charts.threatGauge.data.datasets[0].data = gaugeData;
            charts.threatGauge.update('none');
        }
    }

    // Calculate security score
    function calculateSecurityScore(metrics) {
        let score = 100;
        score -= metrics.suspicious * 5;
        score -= (metrics.flags.syn > 100 ? 20 : metrics.flags.syn / 5);
        score = Math.max(0, Math.min(100, score));
        return Math.round(score);
    }

    // Update Dashboard UI elements
    function updateDashboardUI(metrics) {
        // Update counters
        $('#suspiciousFlows').text(metrics.suspicious);
        $('#packetRate').text(Math.round(metrics.totalPackets / 5) + ' pkt/s');

        // Update security score
        const securityScore = calculateSecurityScore(metrics);
        $('#securityScore').text(securityScore);

        // Update Top Talkers
        updateTopTalkers(metrics.sourceIPs);

        // Update attack badges
        updateAttackBadges(metrics);

        // Update attack timeline if suspicious
        if (metrics.suspicious > 0) {
            addAttackTimelineEntry(metrics.suspicious);
        }
    }

    // Update top talkers list
    function updateTopTalkers(sourceIPs) {
        const topTalkersList = Object.entries(sourceIPs)
            .sort((a, b) => b[1] - a[1])
            .slice(0, CONFIG.MAX_TOP_TALKERS)
            .map(([ip, count]) => `
                <div class="d-flex justify-content-between mb-1">
                    <small>${ip}</small>
                    <span class="badge bg-info">${count}</span>
                </div>
            `).join('');

        $('#topTalkers').html(topTalkersList || '<small class="text-muted">No data</small>');
    }

    // Update attack badges
    function updateAttackBadges(metrics) {
        const badges = [];
        const ddosScore = Math.min(metrics.flags.syn * 2, 100);
        const scanScore = Object.keys(metrics.destPorts).length > 10 ? 50 : 0;

        if (ddosScore > 20) badges.push('<span class="attack-type-badge threat-high">DDoS Risk</span>');
        if (scanScore > 20) badges.push('<span class="attack-type-badge threat-medium">Port Scan</span>');
        if (metrics.suspicious > 5) badges.push('<span class="attack-type-badge threat-high">Anomaly</span>');
        if (badges.length === 0) badges.push('<span class="attack-type-badge threat-low">Normal</span>');

        $('#attackBadges').html(badges.join(' '));
    }

    // Add entry to attack timeline
    function addAttackTimelineEntry(suspiciousCount) {
        const timelineEntry = `
            <div class="attack-entry">
                <strong>${new Date().toLocaleTimeString()}</strong><br>
                ${suspiciousCount} suspicious flows detected
            </div>
        `;
        $('#attackTimeline').prepend(timelineEntry);

        // Keep only last N entries
        $(`#attackTimeline .attack-entry:gt(${CONFIG.MAX_TIMELINE_ENTRIES - 1})`).remove();
    }

    // Load traffic logs
    function loadLogs() {
        $.ajax({
            url: LOGS_URL + '?_=' + Date.now(),
            dataType: 'text',
            success: function(responseText) {
                if (!responseText) {
                    console.warn("Empty logs response");
                    return;
                }

                let data;
                try {
                    data = JSON.parse(responseText);
                } catch (e) {
                    console.error("Invalid JSON:", e);
                    return;
                }

                if (!Array.isArray(data)) {
                    console.warn("Logs not array:", data);
                    return;
                }

                updateLogsTable(data);
            },
            error: function(xhr, status, error) {
                console.error("Failed to load logs:", error);
            }
        });
    }

    // Update logs table
    function updateLogsTable(data) {
        const tbody = $("#logsTable tbody");
        tbody.empty();

        // Helper function for safe display
        const safe = (val) => (val === null || val === undefined || val === "" ? "--" : val);

        // Add rows in reverse order (newest first)
        data.slice().reverse().forEach(packet => {
            if (!packet) return;

            const row = `<tr>
                <td>${safe(packet["Timestamp"])}</td>
                <td>${safe(packet["Src IP"])}</td>
                <td>${safe(packet["Src Port"])}</td>
                <td>${safe(packet["Dst IP"])}</td>
                <td>${safe(packet["Dst Port"])}</td>
                <td>${getProtocolName(packet["Protocol"])}</td>
                <td>${safe(packet["Flow Duration"])}</td>
                <td>${safe(packet["Total Fwd Packets"])}</td>
                <td>${safe(packet["Total Backward Packets"])}</td>
                <td>${safe(packet["Flow Bytes/s"])}</td>
            </tr>`;

            tbody.append(row);
        });
    }

    // Get protocol name from number
    function getProtocolName(proto) {
        if (proto === "6" || proto === 6) return "TCP";
        else if (proto === "17" || proto === 17) return "UDP";
        else if (proto === "1" || proto === 1) return "ICMP";
        else return proto || "--";
    }

    // Load validated alerts (filtered through threat intelligence APIs)
    function loadAlerts() {
        $.ajax({
            url: "<?= MDIR ?>get-validated-alerts?ts=" + Date.now(),
            dataType: 'json',
            success: function(response) {
                if (response.success) {
                    updateAlertsTable(response.alerts);

                    // Log validation statistics
                    if (response.stats) {
                        console.log('Alert Validation Stats:', response.stats);
                        if (response.stats.filtered_alerts > 0) {
                            console.log(`✓ Filtered ${response.stats.filtered_alerts} false positives`);
                        }
                    }
                } else {
                    console.warn("Failed to load validated alerts:", response.message);
                    updateAlertsTable([]);
                }
            },
            error: function(xhr, status, error) {
                console.error("Error loading validated alerts:", error);
                // Fallback to direct file access if API fails
                console.log("Falling back to direct alerts.json access...");
                $.ajax({
                    url: "assets/data/alerts.json?ts=" + Date.now(),
                    dataType: 'json',
                    success: function(data) {
                        updateAlertsTable(data || []);
                    },
                    error: function() {
                        updateAlertsTable([]);
                    }
                });
            }
        });
    }

    // Update alerts table
    function updateAlertsTable(data) {
        const table = document.getElementById("alerts_table");
        if (!table) return;

        table.innerHTML = "";

        if (!Array.isArray(data) || data.length === 0) {
            table.innerHTML = `<tr><td colspan="10" class="text-center">No alerts currently.</td></tr>`;
            return;
        }

        data.forEach(alert => {
            table.innerHTML += `
                <tr class="table-danger">
                    <td>${alert["Timestamp"] || "--"}</td>
                    <td>${alert["Src IP"] || "--"}</td>
                    <td>${alert["Src Port"] || "--"}</td>
                    <td>${alert["Dst IP"] || "--"}</td>
                    <td>${alert["Dst Port"] || "--"}</td>
                    <td>${getProtocolName(alert["Protocol"])}</td>
                    <td>${alert["Flow Duration"] || "--"}</td>
                    <td>${alert["Total Fwd Packets"] || "--"}</td>
                    <td>${alert["Total Backward Packets"] || "--"}</td>
                    <td>${alert["Flow Bytes/s"] || "--"}</td>
                </tr>`;
        });
    }

    // Start logs function - USING OLD WORKING PATTERN
    function startLogs() {
        $("#logsLoadingSpinner").removeClass("d-none");
        $("#startLogsBtn").prop('disabled', true);

        const logContainer = document.getElementById('logContainer');
        logContainer.textContent = "[INFO] Starting system...\n";

        $.ajax({
            url: "<?= MDIR ?>start-logs",
            method: "POST",
            dataType: "json",
            success: function(response) {
                if (response.success) {
                    logContainer.textContent += `[INFO] Traffic sniffer started\n[INFO] PID: ${response.pid}\n[INFO] Wait for 10 sec\n`;
                    logContainer.scrollTop = logContainer.scrollHeight;

                    let checkLogsLoaded;
                    const timeout = setTimeout(() => {
                        clearInterval(checkLogsLoaded);
                        loadLogs();
                        $("#logsLoadingSpinner").addClass("d-none");
                        $("#startLogsBtn").prop('disabled', false);
                        logContainer.textContent += "[WARN] Logs not found within 15 seconds. Timeout triggered.\n";
                        logContainer.scrollTop = logContainer.scrollHeight;
                    }, CONFIG.LOGS_CHECK_TIMEOUT);

                    checkLogsLoaded = setInterval(() => {
                        $.getJSON(LOGS_URL, function(data) {
                            if (Array.isArray(data) && data.length > 0) {
                                clearTimeout(timeout);
                                clearInterval(checkLogsLoaded);
                                loadLogs();
                                $("#logsLoadingSpinner").addClass("d-none");
                                $("#startLogsBtn").prop('disabled', false);
                                logContainer.textContent += "[INFO] Logs loaded successfully.\n";
                                logContainer.scrollTop = logContainer.scrollHeight;
                            }
                        });
                    }, 1000);
                } else {
                    logContainer.textContent += `[ERROR] ${response.message}\n`;
                    $("#logsLoadingSpinner").addClass("d-none");
                    $("#startLogsBtn").prop('disabled', false);
                }
            },
            error: function(xhr, status, err) {
                logContainer.textContent += `[ERROR] ${status} - ${err}\n`;
                if (xhr.status === 403) {
                    logContainer.textContent += `[ERROR] 403 Forbidden - Check server permissions or routing\n`;
                } else if (xhr.status === 404) {
                    logContainer.textContent += `[ERROR] 404 Not Found - Check endpoint URL\n`;
                } else if (xhr.status === 500) {
                    logContainer.textContent += `[ERROR] 500 Server Error - Check PHP logs\n`;
                }
                $("#logsLoadingSpinner").addClass("d-none");
                $("#startLogsBtn").prop('disabled', false);
                logContainer.scrollTop = logContainer.scrollHeight;
            }
        });
    }

    // Start model function
    function startModel() {
        $("#startModelBtn").prop('disabled', true);
        const logContainer = document.getElementById('logContainer');
        logContainer.textContent += "[INFO] Starting model...\n";

        $.ajax({
            url: "<?= MDIR ?>start-model",
            method: "POST",
            dataType: "json",
            success: function(response) {
                if (response.success) {
                    logContainer.textContent += "[INFO] Model started successfully\n";
                    $("#modelStatus").text("Model Active").removeClass("bg-secondary").addClass("bg-success");
                } else {
                    logContainer.textContent += `[ERROR] Failed to start model: ${response.message}\n`;
                }
                $("#startModelBtn").prop('disabled', false);
                logContainer.scrollTop = logContainer.scrollHeight;
            },
            error: function(xhr, status, err) {
                logContainer.textContent += `[ERROR] ${status} - ${err}\n`;
                $("#startModelBtn").prop('disabled', false);
                logContainer.scrollTop = logContainer.scrollHeight;
            }
        });
    }

    // Stop logs function
    function stopLogs() {
        $("#logsLoadingSpinner").removeClass("d-none");
        $("#stopLogsBtn").prop('disabled', true);

        const logContainer = document.getElementById('logContainer');
        logContainer.textContent += "[INFO] Stopping traffic sniffer...\n[INFO] Stopping model...\n";

        $.ajax({
            url: "<?= MDIR ?>stop-logs",
            method: "POST",
            dataType: "json",
            success: function(response) {
                if (response.success) {
                    logContainer.textContent += "[INFO] Sniffer stopped successfully.\n[INFO] Model stopped successfully.\n";
                    $("#modelStatus").text("Model Inactive").removeClass("bg-success").addClass("bg-secondary");
                } else {
                    logContainer.textContent += `[ERROR] Failed to stop: ${response.message}\n`;
                }
                $("#logsLoadingSpinner").addClass("d-none");
                $("#stopLogsBtn").prop('disabled', false);
                logContainer.scrollTop = logContainer.scrollHeight;
            },
            error: function(xhr, status, err) {
                logContainer.textContent += `[ERROR] ${status} - ${err}\n`;
                $("#logsLoadingSpinner").addClass("d-none");
                $("#stopLogsBtn").prop('disabled', false);
                logContainer.scrollTop = logContainer.scrollHeight;
            }
        });
    }

    // Clear traffic logs
    function clearTrafficLogs() {
        const modalElement = document.getElementById("confirmClearModal");
        const modalInstance = bootstrap.Modal.getOrCreateInstance(modalElement);
        const logContainer = document.getElementById("logContainer");

        modalInstance.show();

        $("#confirmClearBtn").off("click").on("click", function() {
            $.ajax({
                url: "<?= MDIR ?>clearlogs",
                method: "GET",
                dataType: "json",
                success: function(response) {
                    modalInstance.hide();
                    logContainer.textContent += "[INFO] Logs cleared successfully.\n[INFO] Reloading data...\n";
                    logContainer.scrollTop = logContainer.scrollHeight;

                    setTimeout(() => {
                        loadLogs();
                        loadAlerts();
                    }, 1000);
                },
                error: function(xhr, status, error) {
                    modalInstance.hide();
                    logContainer.textContent += `[ERROR] Failed to clear logs: ${error}\n`;
                    logContainer.scrollTop = logContainer.scrollHeight;
                }
            });
        });
    }

    // Refresh alerts manually
    function refreshAlerts() {
        loadAlerts();
        const logContainer = document.getElementById('logContainer');
        logContainer.textContent += "[INFO] Alerts refreshed.\n";
        logContainer.scrollTop = logContainer.scrollHeight;
    }

    // Setup search filter
    function setupSearchFilter() {
        $("#searchInput").on("keyup", function() {
            const value = $(this).val().toLowerCase();
            $("#logsTable tbody tr").filter(function() {
                $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1);
            });
        });
    }

    // Helper function to append log messages
    function appendLog(message) {
        const logContainer = document.getElementById('logContainer');
        if (logContainer) {
            logContainer.textContent += message + "\n";
            logContainer.scrollTop = logContainer.scrollHeight;
        }
    }

    // Update system status (placeholder for future implementation)
</script>
</html>