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
    <title>CyberHawk - Security Reporting</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    
    <style>
        @media print {
            .no-print { display: none !important; }
            .sidebar { display: none !important; }
            .main-header { display: none !important; }
            .main-content { margin: 0 !important; padding: 20px !important; }
            .card { page-break-inside: avoid; }
        }

        .gradient-text {
            background: linear-gradient(135deg, #0a74da, #061a40);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: bold;
        }

        .report-card {
            border: 2px solid #0a74da;
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .report-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(10, 116, 218, 0.3);
        }

        .stat-box {
            background: linear-gradient(135deg, rgba(10, 116, 218, 0.1), rgba(6, 26, 64, 0.1));
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            border: 2px solid #0a74da;
        }

        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            color: #0a74da;
        }

        .stat-label {
            color: #6c757d;
            font-size: 0.9rem;
            text-transform: uppercase;
        }

        .report-section {
            margin-bottom: 30px;
            padding: 25px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; font-weight: bold; }

        .export-btn {
            background: linear-gradient(135deg, #0a74da, #061a40);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
        }

        .export-btn:hover {
            transform: scale(1.05);
            box-shadow: 0 5px 15px rgba(10, 116, 218, 0.3);
        }

        .chart-container {
            position: relative;
            height: 300px;
            margin: 20px 0;
        }

        .timeline-item {
            border-left: 3px solid #0a74da;
            padding-left: 20px;
            margin-bottom: 20px;
            position: relative;
        }

        .timeline-item::before {
            content: '';
            position: absolute;
            left: -8px;
            top: 0;
            width: 12px;
            height: 12px;
            background: #0a74da;
            border-radius: 50%;
        }

        .filter-panel {
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }

        .badge-custom {
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.85rem;
        }

        .table-compact {
            font-size: 0.9rem;
        }

        .table-compact td, .table-compact th {
            padding: 8px;
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
                <div class="row mb-4 no-print">
                    <div class="col-12">
                        <h2 class="gradient-text">
                            <i class="bi bi-file-earmark-text"></i> Security Reporting & Analytics
                        </h2>
                        <p class="text-muted">Generate comprehensive security reports from all CyberHawk modules</p>
                    </div>
                </div>

                <!-- Filter Panel -->
                <div class="filter-panel no-print">
                    <div class="row align-items-end">
                        <div class="col-md-3">
                            <label class="form-label fw-bold">Report Type</label>
                            <select class="form-select" id="reportType">
                                <option value="executive">Executive Summary</option>
                                <option value="network">Network Traffic Report</option>
                                <option value="threats">Threat Detection Report</option>
                                <option value="ransomware">Ransomware Analysis</option>
                                <option value="malware">Malware Analysis</option>
                                <option value="combined">Combined Security Report</option>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label fw-bold">Date Range</label>
                            <select class="form-select" id="dateRange">
                                <option value="today">Today</option>
                                <option value="week">Last 7 Days</option>
                                <option value="month" selected>Last 30 Days</option>
                                <option value="all">All Time</option>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label fw-bold">Format</label>
                            <select class="form-select" id="exportFormat">
                                <option value="html">HTML (Print)</option>
                                <option value="csv">CSV Export</option>
                                <option value="json">JSON Data</option>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <button class="btn export-btn w-100" onclick="generateReport()">
                                <i class="bi bi-file-earmark-arrow-down me-2"></i>Generate Report
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Report Container -->
                <div id="reportContainer">
                    <!-- Welcome Message -->
                    <div class="text-center py-5">
                        <i class="bi bi-file-earmark-text" style="font-size: 5rem; color: #0a74da;"></i>
                        <h3 class="mt-3 gradient-text">Select Report Parameters</h3>
                        <p class="text-muted">Choose report type and date range, then click "Generate Report"</p>
                    </div>
                </div>

                <!-- Quick Stats (Always Visible) -->
                <div class="row g-4 mt-4 no-print">
                    <div class="col-md-3">
                        <div class="stat-box">
                            <i class="bi bi-shield-check" style="font-size: 2rem; color: #0a74da;"></i>
                            <div class="stat-number" id="quickTotalScans">-</div>
                            <div class="stat-label">Total Scans</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-box">
                            <i class="bi bi-exclamation-triangle" style="font-size: 2rem; color: #dc3545;"></i>
                            <div class="stat-number" id="quickThreatsDetected">-</div>
                            <div class="stat-label">Threats Detected</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-box">
                            <i class="bi bi-virus" style="font-size: 2rem; color: #fd7e14;"></i>
                            <div class="stat-number" id="quickMalwareDetected">-</div>
                            <div class="stat-label">Malware Found</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-box">
                            <i class="bi bi-file-lock" style="font-size: 2rem; color: #ffc107;"></i>
                            <div class="stat-number" id="quickRansomwareDetected">-</div>
                            <div class="stat-label">Ransomware Blocked</div>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    </div>

    <script>
        // Global data storage
        let reportData = {
            ips: null,
            alerts: null,
            ransomware: null,
            malware: null
        };

        // Initialize on load
        $(document).ready(function() {
            loadQuickStats();
        });

        // Load quick statistics
        function loadQuickStats() {
            $.when(
                $.getJSON("<?= MDIR ?>assets/data/traffic_log.json"),
                $.getJSON("<?= MDIR ?>assets/data/alerts.json"),
                $.getJSON("<?= MDIR ?>assets/data/ransomware_stats.json"),
                $.getJSON("<?= MDIR ?>assets/data/malware_stats.json")
            ).done(function(ips, alerts, ransomware, malware) {
                $('#quickTotalScans').text((ips[0] || []).length);
                $('#quickThreatsDetected').text((alerts[0] || []).length);
                $('#quickMalwareDetected').text(malware[0]?.malware_detected || 0);
                $('#quickRansomwareDetected').text(ransomware[0]?.threats_detected || 0);
            }).fail(function() {
                // Some data files not available yet - silent fail
            });
        }

        // Generate Report
        function generateReport() {
            const reportType = $('#reportType').val();
            const dateRange = $('#dateRange').val();
            const format = $('#exportFormat').val();

            showLoading();

            // Load all data sources
            $.when(
                $.getJSON("<?= MDIR ?>assets/data/traffic_log.json").catch(() => []),
                $.getJSON("<?= MDIR ?>assets/data/alerts.json").catch(() => []),
                $.getJSON("<?= MDIR ?>assets/data/ransomware_stats.json").catch(() => ({})),
                $.getJSON("<?= MDIR ?>assets/data/ransomware_activity.json").catch(() => []),
                $.getJSON("<?= MDIR ?>assets/data/malware_stats.json").catch(() => ({})),
                $.getJSON("<?= MDIR ?>assets/data/malware_reports.json").catch(() => [])
            ).done(function(ips, alerts, ransomStats, ransomActivity, malwareStats, malwareReports) {
                reportData = {
                    ips: filterByDateRange(ips[0] || [], dateRange),
                    alerts: filterByDateRange(alerts[0] || [], dateRange),
                    ransomwareStats: ransomStats[0] || {},
                    ransomwareActivity: filterByDateRange(ransomActivity[0] || [], dateRange),
                    malwareStats: malwareStats[0] || {},
                    malwareReports: filterByDateRange(malwareReports[0] || [], dateRange)
                };

                // Generate appropriate report
                switch(reportType) {
                    case 'executive':
                        generateExecutiveSummary();
                        break;
                    case 'network':
                        generateNetworkReport();
                        break;
                    case 'threats':
                        generateThreatsReport();
                        break;
                    case 'ransomware':
                        generateRansomwareReport();
                        break;
                    case 'malware':
                        generateMalwareReport();
                        break;
                    case 'combined':
                        generateCombinedReport();
                        break;
                }

                // Handle export format
                if (format === 'csv') {
                    exportToCSV(reportType);
                } else if (format === 'json') {
                    exportToJSON();
                } else {
                    // HTML format - add print button
                    addPrintButton();
                }
            }).fail(function(error) {
                showError();
            });
        }

        // Filter data by date range
        function filterByDateRange(data, range) {
            if (!Array.isArray(data) || data.length === 0) return data;
            
            const now = new Date();
            let cutoffDate;

            switch(range) {
                case 'today':
                    cutoffDate = new Date(now.setHours(0,0,0,0));
                    break;
                case 'week':
                    cutoffDate = new Date(now.setDate(now.getDate() - 7));
                    break;
                case 'month':
                    cutoffDate = new Date(now.setDate(now.getDate() - 30));
                    break;
                case 'all':
                default:
                    return data;
            }

            return data.filter(item => {
                const itemDate = new Date(item.Timestamp || item.timestamp || item.scan_date || item.quarantine_date);
                return itemDate >= cutoffDate;
            });
        }

        // ==================== REPORT GENERATORS ====================

        function generateExecutiveSummary() {
            const totalFlows = reportData.ips.length;
            const totalAlerts = reportData.alerts.length;
            const malwareDetected = reportData.malwareStats.malware_detected || 0;
            const ransomwareBlocked = reportData.ransomwareStats.threats_detected || 0;
            const threatRate = totalFlows > 0 ? ((totalAlerts / totalFlows) * 100).toFixed(2) : 0;

            const html = `
                <div class="report-section">
                    <div class="text-center mb-4">
                        <h1 class="gradient-text">CyberHawk Security Executive Summary</h1>
                        <p class="text-muted">Generated: ${new Date().toLocaleString()}</p>
                        <hr>
                    </div>

                    <h3 class="gradient-text mb-3">Overview</h3>
                    <div class="row g-3 mb-4">
                        <div class="col-md-3">
                            <div class="stat-box">
                                <div class="stat-number">${totalFlows}</div>
                                <div class="stat-label">Network Flows</div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stat-box">
                                <div class="stat-number text-danger">${totalAlerts}</div>
                                <div class="stat-label">Security Alerts</div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stat-box">
                                <div class="stat-number text-warning">${malwareDetected}</div>
                                <div class="stat-label">Malware Detected</div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stat-box">
                                <div class="stat-number text-info">${ransomwareBlocked}</div>
                                <div class="stat-label">Ransomware Blocked</div>
                            </div>
                        </div>
                    </div>

                    <h3 class="gradient-text mb-3">Security Posture</h3>
                    <div class="alert ${getThreatLevelClass(threatRate)}">
                        <h5><i class="bi bi-shield-check"></i> Threat Detection Rate: ${threatRate}%</h5>
                        <p class="mb-0">${getThreatLevelMessage(threatRate)}</p>
                    </div>

                    <h3 class="gradient-text mb-3">Key Findings</h3>
                    <ul class="list-group">
                        ${generateKeyFindings()}
                    </ul>

                    <div class="chart-container mt-4">
                        <canvas id="executiveChart"></canvas>
                    </div>
                </div>
            `;

            $('#reportContainer').html(html);
            renderExecutiveChart();
        }

        function generateNetworkReport() {
            const protocols = analyzeProtocols(reportData.ips);
            const topSources = getTopSources(reportData.ips, 10);

            const html = `
                <div class="report-section">
                    <h2 class="gradient-text mb-4">Network Traffic Analysis Report</h2>
                    <p class="text-muted">Generated: ${new Date().toLocaleString()}</p>
                    <hr>

                    <div class="row mb-4">
                        <div class="col-md-6">
                            <h4>Protocol Distribution</h4>
                            <div class="chart-container">
                                <canvas id="protocolChart"></canvas>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <h4>Traffic Volume Over Time</h4>
                            <div class="chart-container">
                                <canvas id="trafficChart"></canvas>
                            </div>
                        </div>
                    </div>

                    <h4>Top Source IPs</h4>
                    <table class="table table-striped table-compact">
                        <thead>
                            <tr>
                                <th>Rank</th>
                                <th>Source IP</th>
                                <th>Packets</th>
                                <th>Percentage</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${topSources.map((src, idx) => `
                                <tr>
                                    <td>${idx + 1}</td>
                                    <td>${src.ip}</td>
                                    <td>${src.count}</td>
                                    <td>${src.percentage}%</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>

                    <h4 class="mt-4">Traffic Statistics</h4>
                    <div class="row">
                        <div class="col-md-4">
                            <div class="stat-box">
                                <div class="stat-number">${reportData.ips.length}</div>
                                <div class="stat-label">Total Flows</div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="stat-box">
                                <div class="stat-number">${Object.keys(protocols).length}</div>
                                <div class="stat-label">Protocols Used</div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="stat-box">
                                <div class="stat-number">${new Set(reportData.ips.map(f => f['Src IP'])).size}</div>
                                <div class="stat-label">Unique Sources</div>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            $('#reportContainer').html(html);
            renderProtocolChart(protocols);
            renderTrafficChart();
        }

        function generateThreatsReport() {
            const attackTypes = analyzeAttackTypes(reportData.alerts);
            
            const html = `
                <div class="report-section">
                    <h2 class="gradient-text mb-4">Threat Detection Report</h2>
                    <p class="text-muted">Generated: ${new Date().toLocaleString()}</p>
                    <hr>

                    <div class="alert alert-danger">
                        <h4><i class="bi bi-exclamation-triangle"></i> Total Threats: ${reportData.alerts.length}</h4>
                    </div>

                    <h4>Attack Distribution</h4>
                    <div class="chart-container mb-4">
                        <canvas id="attackChart"></canvas>
                    </div>

                    <h4>Recent Alerts</h4>
                    <div class="table-responsive">
                        <table class="table table-striped table-compact">
                            <thead class="table-dark">
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Source</th>
                                    <th>Destination</th>
                                    <th>Attack Type</th>
                                    <th>Severity</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${reportData.alerts.slice(0, 50).map(alert => `
                                    <tr>
                                        <td>${new Date(alert.Timestamp).toLocaleString()}</td>
                                        <td>${alert['Src IP']}:${alert['Src Port']}</td>
                                        <td>${alert['Dst IP']}:${alert['Dst Port']}</td>
                                        <td><span class="badge bg-danger">${alert['Attack Type'] || 'Unknown'}</span></td>
                                        <td class="severity-${(alert.Severity || 'low').toLowerCase()}">${alert.Severity || 'N/A'}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;

            $('#reportContainer').html(html);
            renderAttackChart(attackTypes);
        }

        function generateRansomwareReport() {
            const stats = reportData.ransomwareStats;
            
            const html = `
                <div class="report-section">
                    <h2 class="gradient-text mb-4">Ransomware Analysis Report</h2>
                    <p class="text-muted">Generated: ${new Date().toLocaleString()}</p>
                    <hr>

                    <div class="row g-3 mb-4">
                        <div class="col-md-3">
                            <div class="stat-box">
                                <div class="stat-number">${stats.files_scanned || 0}</div>
                                <div class="stat-label">Files Scanned</div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stat-box">
                                <div class="stat-number text-danger">${stats.threats_detected || 0}</div>
                                <div class="stat-label">Threats Found</div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stat-box">
                                <div class="stat-number text-warning">${stats.quarantined || 0}</div>
                                <div class="stat-label">Quarantined</div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stat-box">
                                <div class="stat-number text-info">${stats.scan_rate || 0}</div>
                                <div class="stat-label">Files/Min</div>
                            </div>
                        </div>
                    </div>

                    <h4>Recent Activity</h4>
                    ${generateRansomwareActivityTimeline()}
                </div>
            `;

            $('#reportContainer').html(html);
        }

        function generateMalwareReport() {
            const stats = reportData.malwareStats;
            
            const html = `
                <div class="report-section">
                    <h2 class="gradient-text mb-4">Malware Analysis Report</h2>
                    <p class="text-muted">Generated: ${new Date().toLocaleString()}</p>
                    <hr>

                    <div class="row g-3 mb-4">
                        <div class="col-md-3">
                            <div class="stat-box">
                                <div class="stat-number">${stats.total_scans || 0}</div>
                                <div class="stat-label">Total Scans</div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stat-box">
                                <div class="stat-number text-danger">${stats.malware_detected || 0}</div>
                                <div class="stat-label">Malware Detected</div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stat-box">
                                <div class="stat-number text-success">${stats.clean_files || 0}</div>
                                <div class="stat-label">Clean Files</div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stat-box">
                                <div class="stat-number text-warning">${stats.suspicious_files || 0}</div>
                                <div class="stat-label">Suspicious</div>
                            </div>
                        </div>
                    </div>

                    <h4>Detection Results</h4>
                    <div class="chart-container mb-4">
                        <canvas id="malwareChart"></canvas>
                    </div>

                    <h4>Recent Scans</h4>
                    <table class="table table-striped table-compact">
                        <thead class="table-dark">
                            <tr>
                                <th>Filename</th>
                                <th>Scan Date</th>
                                <th>Threat Level</th>
                                <th>Detection Sources</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${reportData.malwareReports.slice(0, 20).map(report => `
                                <tr>
                                    <td>${report.filename}</td>
                                    <td>${new Date(report.scan_date).toLocaleString()}</td>
                                    <td><span class="badge ${getMalwareBadgeClass(report.threat_level)}">${report.threat_level}</span></td>
                                    <td>${report.detection_sources || 'None'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;

            $('#reportContainer').html(html);
            renderMalwareChart(stats);
        }

        function generateCombinedReport() {
            const html = `
                <div class="report-section">
                    <div class="text-center mb-4">
                        <h1 class="gradient-text">CyberHawk Comprehensive Security Report</h1>
                        <p class="text-muted">Generated: ${new Date().toLocaleString()}</p>
                        <hr>
                    </div>

                    <h2 class="gradient-text">Executive Summary</h2>
                    ${generateExecutiveSummaryContent()}

                    <h2 class="gradient-text mt-5">Network Traffic Analysis</h2>
                    ${generateNetworkSummary()}

                    <h2 class="gradient-text mt-5">Threat Detection</h2>
                    ${generateThreatsSummary()}

                    <h2 class="gradient-text mt-5">Ransomware Protection</h2>
                    ${generateRansomwareSummary()}

                    <h2 class="gradient-text mt-5">Malware Analysis</h2>
                    ${generateMalwareSummary()}

                    <div class="mt-5 text-center">
                        <p class="text-muted">End of Report</p>
                        <p class="small">CyberHawk IDS - Final Year Project</p>
                    </div>
                </div>
            `;

            $('#reportContainer').html(html);
        }

        // ==================== HELPER FUNCTIONS ====================

        function generateExecutiveSummaryContent() {
            const totalFlows = reportData.ips.length;
            const totalAlerts = reportData.alerts.length;
            const threatRate = totalFlows > 0 ? ((totalAlerts / totalFlows) * 100).toFixed(2) : 0;

            return `
                <div class="row g-3 mb-3">
                    <div class="col-md-4">
                        <div class="stat-box">
                            <div class="stat-number">${totalFlows}</div>
                            <div class="stat-label">Network Flows</div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="stat-box">
                            <div class="stat-number text-danger">${totalAlerts}</div>
                            <div class="stat-label">Security Alerts</div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="stat-box">
                            <div class="stat-number">${threatRate}%</div>
                            <div class="stat-label">Threat Rate</div>
                        </div>
                    </div>
                </div>
            `;
        }

        function generateNetworkSummary() {
            const protocols = analyzeProtocols(reportData.ips);
            return `
                <p><strong>Total Network Flows:</strong> ${reportData.ips.length}</p>
                <p><strong>Unique Sources:</strong> ${new Set(reportData.ips.map(f => f['Src IP'])).size}</p>
                <p><strong>Protocols Detected:</strong> ${Object.keys(protocols).join(', ')}</p>
            `;
        }

        function generateThreatsSummary() {
            const attackTypes = analyzeAttackTypes(reportData.alerts);
            return `
                <div class="alert alert-danger">
                    <strong>Total Threats Detected:</strong> ${reportData.alerts.length}
                </div>
                <p><strong>Attack Types:</strong> ${Object.keys(attackTypes).join(', ') || 'None'}</p>
            `;
        }

        function generateRansomwareSummary() {
            const stats = reportData.ransomwareStats;
            return `
                <p><strong>Files Scanned:</strong> ${stats.files_scanned || 0}</p>
                <p><strong>Threats Detected:</strong> ${stats.threats_detected || 0}</p>
                <p><strong>Files Quarantined:</strong> ${stats.quarantined || 0}</p>
            `;
        }

        function generateMalwareSummary() {
            const stats = reportData.malwareStats;
            return `
                <p><strong>Total Scans:</strong> ${stats.total_scans || 0}</p>
                <p><strong>Malware Detected:</strong> ${stats.malware_detected || 0}</p>
                <p><strong>Clean Files:</strong> ${stats.clean_files || 0}</p>
                <p><strong>Suspicious Files:</strong> ${stats.suspicious_files || 0}</p>
            `;
        }

        function generateKeyFindings() {
            const findings = [];
            
            if (reportData.alerts.length > 10) {
                findings.push(`<li class="list-group-item"><i class="bi bi-exclamation-circle text-danger"></i> High alert volume detected: ${reportData.alerts.length} security alerts</li>`);
            }
            
            if (reportData.malwareStats.malware_detected > 0) {
                findings.push(`<li class="list-group-item"><i class="bi bi-bug text-warning"></i> ${reportData.malwareStats.malware_detected} malware samples identified</li>`);
            }
            
            if (reportData.ransomwareStats.threats_detected > 0) {
                findings.push(`<li class="list-group-item"><i class="bi bi-shield-x text-danger"></i> ${reportData.ransomwareStats.threats_detected} ransomware threats blocked</li>`);
            }

            if (findings.length === 0) {
                findings.push(`<li class="list-group-item"><i class="bi bi-check-circle text-success"></i> No critical security issues detected</li>`);
            }

            return findings.join('');
        }

        function generateRansomwareActivityTimeline() {
            if (reportData.ransomwareActivity.length === 0) {
                return '<p class="text-muted">No ransomware activity detected in this period.</p>';
            }

            return reportData.ransomwareActivity.slice(0, 20).map(activity => `
                <div class="timeline-item">
                    <strong>${new Date(activity.timestamp).toLocaleString()}</strong><br>
                    <span class="badge ${activity.threat_level === 'safe' ? 'bg-success' : 'bg-danger'}">${activity.threat_level}</span>
                    <span class="ms-2">${activity.file_name}</span><br>
                    <small class="text-muted">${activity.file_path}</small>
                </div>
            `).join('');
        }

        // ==================== ANALYSIS FUNCTIONS ====================

        function analyzeProtocols(flows) {
            const protocols = {};
            flows.forEach(flow => {
                const proto = getProtocolName(flow.Protocol);
                protocols[proto] = (protocols[proto] || 0) + 1;
            });
            return protocols;
        }

        function analyzeAttackTypes(alerts) {
            const types = {};
            alerts.forEach(alert => {
                const type = alert['Attack Type'] || 'Unknown';
                types[type] = (types[type] || 0) + 1;
            });
            return types;
        }

        function getTopSources(flows, limit = 10) {
            const sources = {};
            flows.forEach(flow => {
                const ip = flow['Src IP'];
                sources[ip] = (sources[ip] || 0) + 1;
            });

            const total = flows.length;
            return Object.entries(sources)
                .map(([ip, count]) => ({
                    ip,
                    count,
                    percentage: ((count / total) * 100).toFixed(2)
                }))
                .sort((a, b) => b.count - a.count)
                .slice(0, limit);
        }

        function getProtocolName(proto) {
            if (proto === "6" || proto === 6) return "TCP";
            if (proto === "17" || proto === 17) return "UDP";
            if (proto === "1" || proto === 1) return "ICMP";
            return proto || "Other";
        }

        function getThreatLevelClass(rate) {
            if (rate > 10) return 'alert-danger';
            if (rate > 5) return 'alert-warning';
            return 'alert-success';
        }

        function getThreatLevelMessage(rate) {
            if (rate > 10) return 'HIGH RISK: Significant threat activity detected. Immediate action recommended.';
            if (rate > 5) return 'MEDIUM RISK: Moderate threat activity. Continue monitoring.';
            return 'LOW RISK: Security posture is good. Maintain current practices.';
        }

        function getMalwareBadgeClass(level) {
            switch(level?.toUpperCase()) {
                case 'MALICIOUS': return 'bg-danger';
                case 'SUSPICIOUS': return 'bg-warning';
                case 'LOW': return 'bg-info';
                default: return 'bg-success';
            }
        }

        // ==================== CHART RENDERING ====================

        function renderExecutiveChart() {
            const ctx = document.getElementById('executiveChart');
            if (!ctx) return;

            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['Network Flows', 'Alerts', 'Malware', 'Ransomware'],
                    datasets: [{
                        label: 'Security Metrics',
                        data: [
                            reportData.ips.length,
                            reportData.alerts.length,
                            reportData.malwareStats.malware_detected || 0,
                            reportData.ransomwareStats.threats_detected || 0
                        ],
                        backgroundColor: ['#0a74da', '#dc3545', '#fd7e14', '#ffc107']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } }
                }
            });
        }

        function renderProtocolChart(protocols) {
            const ctx = document.getElementById('protocolChart');
            if (!ctx) return;

            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(protocols),
                    datasets: [{
                        data: Object.values(protocols),
                        backgroundColor: ['#0a74da', '#17a2b8', '#28a745', '#ffc107']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        }

        function renderTrafficChart() {
            const ctx = document.getElementById('trafficChart');
            if (!ctx) return;

            // Group traffic by hour
            const hourlyData = {};
            reportData.ips.forEach(flow => {
                const hour = new Date(flow.Timestamp).getHours();
                hourlyData[hour] = (hourlyData[hour] || 0) + 1;
            });

            const hours = Array.from({length: 24}, (_, i) => i);
            const counts = hours.map(h => hourlyData[h] || 0);

            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: hours.map(h => `${h}:00`),
                    datasets: [{
                        label: 'Traffic Volume',
                        data: counts,
                        borderColor: '#0a74da',
                        backgroundColor: 'rgba(10, 116, 218, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        }

        function renderAttackChart(attackTypes) {
            const ctx = document.getElementById('attackChart');
            if (!ctx) return;

            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: Object.keys(attackTypes),
                    datasets: [{
                        label: 'Attack Count',
                        data: Object.values(attackTypes),
                        backgroundColor: '#dc3545'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y'
                }
            });
        }

        function renderMalwareChart(stats) {
            const ctx = document.getElementById('malwareChart');
            if (!ctx) return;

            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: ['Malware', 'Clean', 'Suspicious'],
                    datasets: [{
                        data: [
                            stats.malware_detected || 0,
                            stats.clean_files || 0,
                            stats.suspicious_files || 0
                        ],
                        backgroundColor: ['#dc3545', '#28a745', '#ffc107']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        }

        // ==================== EXPORT FUNCTIONS ====================

        function exportToCSV(reportType) {
            let csvContent = "data:text/csv;charset=utf-8,";
            
            switch(reportType) {
                case 'network':
                    csvContent += "Timestamp,Source IP,Source Port,Dest IP,Dest Port,Protocol\n";
                    reportData.ips.forEach(flow => {
                        csvContent += `${flow.Timestamp},${flow['Src IP']},${flow['Src Port']},${flow['Dst IP']},${flow['Dst Port']},${getProtocolName(flow.Protocol)}\n`;
                    });
                    break;
                case 'threats':
                    csvContent += "Timestamp,Source,Destination,Attack Type,Severity\n";
                    reportData.alerts.forEach(alert => {
                        csvContent += `${alert.Timestamp},${alert['Src IP']}:${alert['Src Port']},${alert['Dst IP']}:${alert['Dst Port']},${alert['Attack Type']},${alert.Severity}\n`;
                    });
                    break;
                case 'malware':
                    csvContent += "Filename,Scan Date,Threat Level,Detection Sources\n";
                    reportData.malwareReports.forEach(report => {
                        csvContent += `${report.filename},${report.scan_date},${report.threat_level},${report.detection_sources}\n`;
                    });
                    break;
                default:
                    csvContent += "Metric,Value\n";
                    csvContent += `Network Flows,${reportData.ips.length}\n`;
                    csvContent += `Security Alerts,${reportData.alerts.length}\n`;
                    csvContent += `Malware Detected,${reportData.malwareStats.malware_detected || 0}\n`;
                    csvContent += `Ransomware Blocked,${reportData.ransomwareStats.threats_detected || 0}\n`;
            }

            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", `cyberhawk_${reportType}_${Date.now()}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);

            showNotification('Success', 'CSV file downloaded', 'success');
        }

        function exportToJSON() {
            const dataStr = JSON.stringify(reportData, null, 2);
            const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
            
            const link = document.createElement('a');
            link.setAttribute('href', dataUri);
            link.setAttribute('download', `cyberhawk_report_${Date.now()}.json`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);

            showNotification('Success', 'JSON file downloaded', 'success');
        }

        function addPrintButton() {
            const printBtn = `
                <div class="text-center mt-4 no-print">
                    <button class="btn export-btn btn-lg" onclick="window.print()">
                        <i class="bi bi-printer me-2"></i>Print Report
                    </button>

<button class="btn export-btn btn-lg ms-2" onclick="downloadReportHTML()">
    <i class="bi bi-download me-2"></i>Download HTML
</button>

<button class="btn export-btn btn-lg ms-2" onclick="showEmailModal()">
    <i class="bi bi-envelope me-2"></i>Email Report
</button>

<button class="btn btn-secondary btn-lg ms-2" onclick="location.reload()">
    <i class="bi bi-arrow-clockwise me-2"></i>New Report
</button>

</div>
`;
$('#reportContainer').append(printBtn);
}

// ==================== DOWNLOAD REPORT (HTML FILE) ====================
function downloadReportHTML() {
    const reportType = $('#reportType').val();
    const reportContent = $('#reportContainer').html();

    const fullHTML = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CyberHawk Security Report</title>

        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { padding: 20px; font-family: Arial, sans-serif; }
            .gradient-text { 
                background: linear-gradient(135deg, #0a74da, #061a40); 
                -webkit-background-clip: text; 
                -webkit-text-fill-color: transparent; 
                font-weight: bold; 
            }
            .stat-box { 
                background: linear-gradient(135deg, rgba(10, 116, 218, 0.1), rgba(6, 26, 64, 0.1));
                border-radius: 10px; 
                padding: 20px; 
                text-align: center; 
                border: 2px solid #0a74da; 
            }
            .stat-number { font-size: 2.5rem; font-weight: bold; color: #0a74da; }
            .severity-critical { color: #dc3545; font-weight: bold; }
            .severity-high { color: #fd7e14; font-weight: bold; }
            .severity-medium { color: #ffc107; font-weight: bold; }
            .severity-low { color: #28a745; font-weight: bold; }
            .no-print { display: none; }
        </style>
    </head>

    <body>
        <div class="container">
            <div class="text-center mb-4">
                <h1 class="gradient-text">CyberHawk Security Report</h1>
                <p class="text-muted">Generated on ${new Date().toLocaleString()}</p>
            </div>
            ${reportContent}
        </div>
    </body>
    </html>
    `;

    const blob = new Blob([fullHTML], { type: 'text/html' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');

    link.href = url;
    link.download = `cyberhawk_${reportType}_report_${Date.now()}.html`;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);

    showNotification('Success', 'Report downloaded successfully', 'success');
}

// ==================== EMAIL REPORT (SHOW MODAL) ====================
function showEmailModal() {
    const modal = `
        <div class="modal fade" id="emailReportModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">

                    <div class="modal-header" style="background: linear-gradient(135deg, #0a74da, #061a40); color: white;">
                        <h5 class="modal-title"><i class="bi bi-envelope me-2"></i>Email Report</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>

                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="emailRecipient" class="form-label">Recipient Email</label>
                            <input type="email" class="form-control" id="emailRecipient" placeholder="Enter email address" required>
                        </div>

                        <div class="alert alert-info">
                            <i class="bi bi-info-circle me-2"></i>
                            The report will be sent as an HTML email to the specified address.
                        </div>
                    </div>

                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn export-btn" onclick="sendReportEmail()">
                            <i class="bi bi-send me-2"></i>Send Email
                        </button>
                    </div>

                </div>
            </div>
        </div>
    `;

    $('#emailReportModal').remove();
    $('body').append(modal);

    const emailModal = new bootstrap.Modal(document.getElementById('emailReportModal'));
    emailModal.show();
}

// ==================== SEND REPORT EMAIL (AJAX) ====================
function sendReportEmail() {
    const recipientEmail = $('#emailRecipient').val();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!recipientEmail) {
        showNotification('Error', 'Please enter a recipient email address', 'danger');
        return;
    }

    if (!emailRegex.test(recipientEmail)) {
        showNotification('Error', 'Please enter a valid email address', 'danger');
        return;
    }

    const reportType = $('#reportType').val();
    const reportContent = $('#reportContainer').clone().find('.no-print').remove().end().html();

    $('#emailReportModal .modal-body').html(`
        <div class="text-center py-4">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Sending...</span>
            </div>
            <p class="mt-3 text-muted">Sending email to ${recipientEmail}...</p>
        </div>
    `);

    $.ajax({
        url: '<?= MDIR ?>email-report',
        method: 'POST',
        data: {
            email: recipientEmail,
            report_type: reportType,
            report_data: reportContent
        },

        success: function(response) {
            $('#emailReportModal').modal('hide');

            if (response.success) {
                showNotification('Email Sent', 'Report has been sent successfully to: ' + recipientEmail, 'success');
            } else {
                showNotification('Error', response.message || 'Failed to send email', 'danger');
            }
        },

        error: function() {
            $('#emailReportModal').modal('hide');
            showNotification('Error', 'Failed to send email. Please try again.', 'danger');
        }
    });
}


        // ==================== UI FUNCTIONS ====================

        function showLoading() {
            $('#reportContainer').html(`
                <div class="text-center py-5">
                    <div class="spinner-border text-primary" style="width: 3rem; height: 3rem;" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                    <h4 class="mt-3 gradient-text">Generating Report...</h4>
                    <p class="text-muted">Please wait while we compile your security data</p>
                </div>
            `);
        }

        function showError() {
            $('#reportContainer').html(`
                <div class="text-center py-5">
                    <i class="bi bi-exclamation-circle" style="font-size: 5rem; color: #dc3545;"></i>
                    <h3 class="mt-3 text-danger">Error Loading Data</h3>
                    <p class="text-muted">Some data files may not be available. Please ensure the system has been running.</p>
                    <button class="btn btn-primary mt-3" onclick="location.reload()">
                        <i class="bi bi-arrow-clockwise me-2"></i>Try Again
                    </button>
                </div>
            `);
        }

        function showNotification(title, message, type) {
            const alertClass = type === 'success' ? 'alert-success' : 
                              type === 'warning' ? 'alert-warning' : 'alert-danger';
            
            const notification = $(`
                <div class="alert ${alertClass} alert-dismissible fade show position-fixed" 
                     style="top: 80px; right: 20px; z-index: 10001; min-width: 300px; box-shadow: 0 5px 15px rgba(0,0,0,0.3);">
                    <strong>${title}:</strong> ${message}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            `);
            
            $('body').append(notification);
            
            setTimeout(() => {
                notification.fadeOut(() => $(this).remove());
            }, 5000);
        }
    </script>
    
</body>
</html>