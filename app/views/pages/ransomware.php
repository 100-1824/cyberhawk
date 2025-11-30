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
    <title>CyberHawk - Ransomware Detection</title>
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
            border: 2px solid #dc3545;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        #monitorStatusText{
            color: #2c3246ff;
        }

        .gradient-text {
            background: linear-gradient(135deg, #dc3545, #6f0a1e);
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
            background-color: #dc3545;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }

        .live-indicator.inactive {
            background-color: #6c757d;
            animation: none;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }

        .file-activity-item {
            padding: 12px;
            margin-bottom: 10px;
            background: linear-gradient(135deg, rgba(10, 116, 218, 0.1), rgba(6, 26, 64, 0.1));
            border-left: 4px solid #0a74da;
            border-radius: 4px;
            animation: slideIn 0.3s ease-out;
            overflow: hidden;
        }

        .file-activity-item.threat {
            background: linear-gradient(135deg, rgba(220, 53, 69, 0.1), rgba(111, 10, 30, 0.1));
            border-left-color: #dc3545;
        }

        .file-activity-item.safe {
            background: linear-gradient(135deg, rgba(10, 116, 218, 0.05), rgba(6, 26, 64, 0.05));
            border-left-color: #0a74da;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        .file-activity-item .file-name {
            display: block;
            max-width: 100%;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            word-break: break-all;
        }

        .file-activity-item .file-path {
            display: block;
            max-width: 100%;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            word-break: break-all;
        }

        .process-monitor {
            max-height: 350px;
            overflow-y: auto;
            overflow-x: hidden;
        }

        .process-monitor::-webkit-scrollbar {
            width: 8px;
        }

        .process-monitor::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }

        .process-monitor::-webkit-scrollbar-thumb {
            background: #888;
            border-radius: 10px;
        }

        .process-monitor::-webkit-scrollbar-thumb:hover {
            background: #555;
        }

        .behavior-indicator {
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 0.8rem;
            display: inline-block;
            margin: 3px;
        }

        .behavior-encryption {
            background-color: #dc3545;
            color: white;
        }

        .behavior-deletion {
            background-color: #fd7e14;
            color: white;
        }

        .behavior-extension {
            background-color: #6f42c1;
            color: white;
        }

        .scan-progress {
            height: 30px;
            border-radius: 8px;
        }

        .quarantine-box {
            background-color: #fff3cd;
            border: 2px dashed #ffc107;
            padding: 15px;
            border-radius: 8px;
            min-height: 200px;
            max-height: 300px;
            overflow-y: auto;
        }

        .stats-card {
            text-align: center;
            padding: 20px;
        }

        .stats-number {
            font-size: 2.5rem;
            font-weight: bold;
            margin: 10px 0;
        }

        .stats-label {
            color: #6c757d;
            font-size: 0.9rem;
        }

        .control-panel {
                background: linear-gradient(135deg, #0a74da, #061a40);
            border-radius: 15px;
            padding: 25px;
            color: white;
        }

        .control-btn {
            width: 100%;
            padding: 15px;
            font-size: 1.1rem;
            border-radius: 10px;
            border: none;
            transition: all 0.3s ease;
            margin-bottom: 10px;
        }

        .control-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
        }

        .control-btn.btn-monitor {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .control-btn.btn-monitor.active {
            background: linear-gradient(135deg, #0a74da 0%, #57d3f5ff 100%);
        }

        .scan-modal {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            z-index: 10000;
            min-width: 500px;
            display: none;
        }

        .scan-modal.active {
            display: block;
        }

        .modal-backdrop {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.7);
            z-index: 9999;
            display: none;
        }

        .modal-backdrop.active {
            display: block;
        }

        .progress-ring {
            width: 150px;
            height: 150px;
            margin: 0 auto;
        }

        .spinner {
            border: 4px solid rgba(0,0,0,0.1);
            border-left-color: #dc3545;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
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
                            <i class="bi bi-virus"></i> Ransomware Detection & Prevention
                        </h2>
                        <p class="text-muted">Real-time behavioral analysis and threat detection system</p>
                    </div>
                </div>

                <!-- Control Panel -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="control-panel">
                            <div class="row align-items-center">
                                <div class="col-md-8">
                                    <h4 class="mb-3">
                                        <span class="live-indicator" id="monitorIndicator"></span>
                                        <span id="monitorStatusText">Monitoring System</span>
                                    </h4>
                                    <p class="mb-0" id="monitorDescription">
                                        Real-time file system monitoring is currently <strong id="statusWord">inactive</strong>
                                    </p>
                                </div>
                                <div class="col-md-4 text-end">
                                    <button class="control-btn btn-monitor" onclick="toggleMonitoring()" id="mainMonitorBtn">
                                        <i class="bi bi-play-fill" id="monitorIcon"></i>
                                        <span id="monitorBtnText">Start Monitoring</span>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Statistics Row -->
                <div class="row g-4">
                    <div class="col-md-3">
                        <div class="card my-card">
                            <div class="card-body stats-card">
                                <i class="bi bi-file-earmark-check" style="font-size: 2rem; color: #0a74da;"></i>
                                <div class="stats-number text-primary" id="filesScanned">0</div>
                                <div class="stats-label">Files Scanned</div>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-3">
                        <div class="card my-card">
                            <div class="card-body stats-card">
                                <i class="bi bi-exclamation-triangle-fill" style="font-size: 2rem; color: #dc3545;"></i>
                                <div class="stats-number text-danger" id="threatsDetected">0</div>
                                <div class="stats-label">Threats Detected</div>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-3">
                        <div class="card my-card">
                            <div class="card-body stats-card">
                                <i class="bi bi-shield-lock" style="font-size: 2rem; color: #ffc107;"></i>
                                <div class="stats-number text-warning" id="quarantinedFiles">0</div>
                                <div class="stats-label">Quarantined</div>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-3">
                        <div class="card my-card">
                            <div class="card-body stats-card">
                                <i class="bi bi-speedometer2" style="font-size: 2rem; color: #17a2b8;"></i>
                                <div class="stats-number text-info" id="scanRate">0</div>
                                <div class="stats-label">Files/Min</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Main Monitoring Row -->
                <div class="row g-4 mt-3">
                    <!-- Real-Time Activity -->
                    <div class="col-md-8">
                        <div class="card my-card" style="height: 450px;">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="card-title mb-0 gradient-text">
                                    <span class="live-indicator" id="activityIndicator"></span> 
                                    Real-Time File Activity
                                </h5>
                                <span class="badge bg-info" id="activityCount">0 events</span>
                            </div>
                            <div class="card-body" style="overflow: hidden;">
                                <div class="row mb-3">
                                    <div class="col-12">
                                        <small class="text-muted" id="currentScanFile">Waiting for monitoring to start...</small>
                                        <div class="progress scan-progress mt-2">
                                            <div class="progress-bar progress-bar-striped bg-danger" 
                                                 role="progressbar" id="scanProgress" style="width: 0%"></div>
                                        </div>
                                    </div>
                                </div>
                                <div class="process-monitor" id="fileActivityList">
                                    <div class="text-center text-muted py-5">
                                        <i class="bi bi-hourglass-split" style="font-size: 3rem;"></i>
                                        <p>Start monitoring to see real-time file activity</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Threat Detection -->
                    <div class="col-md-4">
                        <div class="card my-card" style="height: 450px;">
                            <div class="card-header">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-shield-exclamation"></i> Detection Engines
                                </h5>
                            </div>
                            <div class="card-body">
                                <h6 class="mb-3">Active Algorithms</h6>
                                <div class="small mb-3">
                                    <div class="d-flex justify-content-between mb-2">
                                        <span><i class="bi bi-check-circle text-success"></i> Extension Analysis</span>
                                        <span class="badge bg-success" id="engine1">Ready</span>
                                    </div>
                                    <div class="d-flex justify-content-between mb-2">
                                        <span><i class="bi bi-check-circle text-success"></i> Entropy Detection</span>
                                        <span class="badge bg-success" id="engine2">Ready</span>
                                    </div>
                                    <div class="d-flex justify-content-between mb-2">
                                        <span><i class="bi bi-check-circle text-success"></i> Behavior Analysis</span>
                                        <span class="badge bg-success" id="engine3">Ready</span>
                                    </div>
                                    <div class="d-flex justify-content-between mb-2">
                                        <span><i class="bi bi-check-circle text-success"></i> Mass Operation Detection</span>
                                        <span class="badge bg-success" id="engine4">Ready</span>
                                    </div>
                                </div>

                                <hr>

                                <h6 class="mb-3">Recent Threats</h6>
                                <div id="recentThreats" style="max-height: 200px; overflow-y: auto;">
                                    <p class="text-muted small">No threats detected</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Action Buttons -->
                <div class="row g-4 mt-3">
                    <div class="col-md-6">
                        <div class="card my-card">
                            <div class="card-header">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-gear-fill"></i> Scan Actions
                                </h5>
                            </div>
                            <div class="card-body">
                                <button class="btn btn-lg btn-danger w-100 mb-3" onclick="startFullScan()">
                                    <i class="bi bi-search"></i> Start Full System Scan
                                </button>
                                <button class="btn btn-lg btn-warning w-100 mb-3" onclick="startQuickScan()">
                                    <i class="bi bi-lightning-fill"></i> Quick Scan (User Folders)
                                </button>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-6">
                        <div class="card my-card">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-folder-x"></i> Quarantine Zone
                                </h5>
                                <button class="btn btn-sm btn-outline-warning" onclick="loadQuarantineFiles()">
                                    <i class="bi bi-arrow-clockwise"></i> Refresh
                                </button>
                            </div>
                            <div class="card-body">
                                <div class="quarantine-box" id="quarantineList">
                                    <div class="text-center text-muted">
                                        <i class="bi bi-shield-check" style="font-size: 3rem;"></i>
                                        <p>No quarantined files</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Detection Log -->
                <div class="row g-4 mt-3">
                    <div class="col-12">
                        <div class="card my-card">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="card-title mb-0 gradient-text">
                                    <i class="bi bi-journal-text"></i> Detection Log
                                </h5>
                                <button class="btn btn-sm btn-outline-danger" onclick="clearDetectionLog()">
                                    <i class="bi bi-trash"></i> Clear Log
                                </button>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
                                    <table class="table table-striped table-hover">
                                        <thead class="table-dark sticky-top">
                                            <tr>
                                                <th>Timestamp</th>
                                                <th>File Path</th>
                                                <th>Threat Type</th>
                                                <th>Severity</th>
                                                <th>Action</th>
                                            </tr>
                                        </thead>
                                        <tbody id="detectionLogTable">
                                            <tr>
                                                <td colspan="5" class="text-center text-muted">No detections recorded</td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    </div>

    <!-- Scan Progress Modal -->
    <div class="modal-backdrop" id="scanBackdrop"></div>
    <div class="scan-modal" id="scanModal">
        <div class="text-center">
            <h4 class="gradient-text mb-4">
                <i class="bi bi-shield-check"></i> <span id="scanModalTitle">Scanning System</span>
            </h4>
            <div class="spinner"></div>
            <div class="mt-4">
                <h2 class="text-primary" id="scanPercentage">0%</h2>
                <div class="progress scan-progress mt-3">
                    <div class="progress-bar progress-bar-striped progress-bar-animated bg-primary" 
                         id="modalScanProgress" style="width: 0%"></div>
                </div>
                <p class="text-muted mt-3" id="scanStatusText">Initializing scan...</p>
                <small class="text-muted" id="scanCurrentFile">Preparing...</small>
            </div>
            <button class="btn btn-danger mt-4" onclick="cancelScan()">
                <i class="bi bi-x-circle"></i> Cancel Scan
            </button>
        </div>
    </div>

    <script>
        // Global state
        let monitoringActive = false;
        let scanningActive = false;
        let scanCheckInterval = null;
        let activityCheckInterval = null;
        let statsCheckInterval = null;

        // Initialize on load
        $(document).ready(function() {
            console.log('[INIT] Initializing ransomware detection page...');
            checkMonitorStatus();
            loadQuarantineFiles();
            updateStatistics();
        });

        // ==================== MONITOR CONTROL ====================

        function checkMonitorStatus() {
            $.ajax({
                url: "<?= MDIR ?>get-monitor-status",
                method: "GET",
                dataType: "json",
                success: function(data) {
                    console.log('[STATUS]', data);
                    monitoringActive = data.running || false;
                    updateMonitorUI();
                    
                    if (monitoringActive) {
                        startActivityPolling();
                    } else {
                        stopActivityPolling();
                    }
                },
                error: function(xhr, status, error) {
                    console.error('[ERROR] Failed to check monitor status:', error);
                }
            });
        }

        function toggleMonitoring() {
            const endpoint = monitoringActive ? 'stop-ransomware-monitor' : 'start-ransomware-monitor';
            const btn = $('#mainMonitorBtn');
            
            btn.prop('disabled', true);
            btn.html('<i class="bi bi-hourglass-split"></i> Processing...');
            
            $.ajax({
                url: "<?= MDIR ?>" + endpoint,
                method: "POST",
                dataType: "json",
                success: function(response) {
                    console.log('[MONITOR]', response);
                    if (response.success) {
                        monitoringActive = !monitoringActive;
                        updateMonitorUI();
                        
                        if (monitoringActive) {
                            showNotification('Success', 'Monitoring started successfully', 'success');
                            startActivityPolling();
                        } else {
                            showNotification('Success', 'Monitoring stopped', 'info');
                            stopActivityPolling();
                        }
                    } else {
                        showNotification('Error', response.message, 'error');
                    }
                },
                error: function(xhr, status, error) {
                    showNotification('Error', 'Failed to toggle monitoring: ' + error, 'error');
                },
                complete: function() {
                    btn.prop('disabled', false);
                }
            });
        }

        function updateMonitorUI() {
            const btn = $('#mainMonitorBtn');
            const indicator = $('#monitorIndicator');
            const activityIndicator = $('#activityIndicator');
            const statusWord = $('#statusWord');
            
            if (monitoringActive) {
                btn.removeClass('btn-monitor').addClass('btn-monitor active');
                btn.html('<i class="bi bi-stop-fill" id="monitorIcon"></i> <span id="monitorBtnText">Stop Monitoring</span>');
                indicator.removeClass('inactive');
                activityIndicator.removeClass('inactive');
                statusWord.text('active').css('color', '#28a745');
                $('#engine1, #engine2, #engine3, #engine4').removeClass('bg-success').addClass('bg-primary').text('Active');
            } else {
                btn.removeClass('active').addClass('btn-monitor');
                btn.html('<i class="bi bi-play-fill" id="monitorIcon"></i> <span id="monitorBtnText">Start Monitoring</span>');
                indicator.addClass('inactive');
                activityIndicator.addClass('inactive');
                statusWord.text('inactive').css('color', '#dc3545');
                $('#engine1, #engine2, #engine3, #engine4').removeClass('bg-primary').addClass('bg-success').text('Ready');
            }
        }

        // ==================== ACTIVITY POLLING ====================

        function startActivityPolling() {
            console.log('[POLLING] Starting activity polling...');
            updateFileActivity();
            updateStatistics();
            
            activityCheckInterval = setInterval(updateFileActivity, 2000);
            statsCheckInterval = setInterval(updateStatistics, 3000);
        }

        function stopActivityPolling() {
            console.log('[POLLING] Stopping activity polling...');
            if (activityCheckInterval) {
                clearInterval(activityCheckInterval);
                activityCheckInterval = null;
            }
            if (statsCheckInterval) {
                clearInterval(statsCheckInterval);
                statsCheckInterval = null;
            }
        }

        function updateFileActivity() {
            $.ajax({
                url: "<?= MDIR ?>get-ransomware-activity",
                method: "GET",
                dataType: "json",
                success: function(data) {
                    if (data && data.length > 0) {
                        displayFileActivity(data);
                        $('#activityCount').text(data.length + ' events');
                    }
                },
                error: function(xhr, status, error) {
                    console.error('[ERROR] Failed to fetch activity:', error);
                }
            });
        }

        function displayFileActivity(activities) {
            const container = $('#fileActivityList');
            container.empty();
            
            activities.slice(0, 15).forEach(activity => {
                const isSafe = activity.threat_level === 'safe';
                const icon = isSafe ? 'bi-check-circle-fill' : 'bi-exclamation-triangle-fill';
                const iconColor = isSafe ? '#0a74da' : '#dc3545';
                const statusClass = isSafe ? 'safe' : 'threat';
                const badgeClass = isSafe ? 'bg-primary' : 'bg-danger';
                
                const behaviorBadge = activity.behavior_type && !isSafe ? 
                    `<span class="behavior-indicator behavior-${activity.behavior_type}">${activity.behavior_type.toUpperCase()}</span>` : '';
                
                const html = `
                    <div class="file-activity-item ${statusClass}">
                        <div class="d-flex justify-content-between align-items-start">
                            <div class="flex-grow-1" style="min-width: 0; max-width: calc(100% - 120px);">
                                <div class="d-flex align-items-center">
                                    <i class="bi ${icon}" style="color: ${iconColor}; flex-shrink: 0;"></i>
                                    <strong class="ms-2 file-name" title="${activity.file_name}">${activity.file_name}</strong>
                                </div>
                                <small class="text-muted ms-4 d-block file-path" title="${activity.file_path}">${activity.file_path}</small>
                                <div class="mt-1 ms-4">
                                    <span class="badge ${badgeClass}">
                                        ${activity.threat_level.toUpperCase()}
                                    </span>
                                    ${behaviorBadge}
                                </div>
                            </div>
                            <small class="text-muted ms-2" style="white-space: nowrap; flex-shrink: 0;">${activity.timestamp}</small>
                        </div>
                    </div>
                `;
                container.append(html);
            });
        }

        function updateStatistics() {
            $.ajax({
                url: "<?= MDIR ?>get-ransomware-stats",
                method: "GET",
                dataType: "json",
                success: function(data) {
                    $('#filesScanned').text(data.files_scanned || 0);
                    $('#threatsDetected').text(data.threats_detected || 0);
                    $('#quarantinedFiles').text(data.quarantined || 0);
                    $('#scanRate').text(Math.round(data.scan_rate || 0));

                    const progress = data.scan_progress || 0;
                    const progressBar = $('#scanProgress');

                    // If monitoring is active and progress is 0, show animated bar
                    if (monitoringActive && progress === 0) {
                        progressBar.css('width', '100%');
                        progressBar.addClass('progress-bar-animated');
                    } else if (progress > 0) {
                        // During actual scan, show percentage
                        progressBar.css('width', progress + '%');
                        progressBar.addClass('progress-bar-animated');
                    } else {
                        // Idle state
                        progressBar.css('width', '0%');
                        progressBar.removeClass('progress-bar-animated');
                    }

                    $('#currentScanFile').text(data.current_file || 'Monitoring...');
                },
                error: function(xhr, status, error) {
                    console.error('[ERROR] Failed to fetch stats:', error);
                }
            });
        }

        // ==================== SCANNING ====================

        function startFullScan() {
            if (scanningActive) {
                showNotification('Scanning', 'A scan is already in progress', 'warning');
                return;
            }
            
            showScanModal('Full System Scan');
            
            $.ajax({
                url: "<?= MDIR ?>start-full-scan",
                method: "POST",
                dataType: "json",
                success: function(response) {
                    console.log('[SCAN]', response);
                    if (response.success) {
                        scanningActive = true;
                        startScanProgressTracking();
                        showNotification('Scan Started', response.message, 'success');
                    } else {
                        hideScanModal();
                        showNotification('Error', response.message, 'error');
                    }
                },
                error: function(xhr, status, error) {
                    hideScanModal();
                    showNotification('Error', 'Failed to start scan: ' + error, 'error');
                }
            });
        }

        function startQuickScan() {
            if (scanningActive) {
                showNotification('Scanning', 'A scan is already in progress', 'warning');
                return;
            }
            
            showScanModal('Quick Scan');
            
            $.ajax({
                url: "<?= MDIR ?>start-quick-scan",
                method: "POST",
                dataType: "json",
                success: function(response) {
                    console.log('[SCAN]', response);
                    if (response.success) {
                        scanningActive = true;
                        startScanProgressTracking();
                        showNotification('Scan Started', 'Quick scan initiated', 'success');
                    } else {
                        hideScanModal();
                        showNotification('Error', response.message, 'error');
                    }
                },
                error: function(xhr, status, error) {
                    hideScanModal();
                    showNotification('Error', 'Failed to start scan: ' + error, 'error');
                }
            });
        }

        function startScanProgressTracking() {
            console.log('[PROGRESS] Starting scan progress tracking...');
            
            scanCheckInterval = setInterval(function() {
                $.ajax({
                    url: "<?= MDIR ?>get-scan-progress",
                    method: "GET",
                    dataType: "json",
                    success: function(data) {
                        console.log('[PROGRESS]', data);
                        
                        const progress = data.progress || 0;
                        $('#scanPercentage').text(progress + '%');
                        $('#modalScanProgress').css('width', progress + '%');
                        $('#scanStatusText').text(data.status || 'Scanning...');
                        $('#scanCurrentFile').text(data.current_file || 'Processing...');
                        
                        // Update stats in real-time during scan
                        if (data.files_scanned !== undefined) {
                            $('#filesScanned').text(data.files_scanned);
                        }
                        if (data.threats_found !== undefined) {
                            $('#threatsDetected').text(data.threats_found);
                        }
                        
                        if (progress >= 100) {
                            console.log('[COMPLETE] Scan finished');
                            clearInterval(scanCheckInterval);
                            scanningActive = false;
                            setTimeout(function() {
                                hideScanModal();
                                showNotification('Scan Complete', 'Scan finished successfully', 'success');
                                updateStatistics();
                                loadQuarantineFiles();
                            }, 1500);
                        }
                    },
                    error: function(xhr, status, error) {
                        console.error('[ERROR] Failed to get progress:', error);
                    }
                });
            }, 1000); // Check every second
        }

        function cancelScan() {
            if (confirm('Are you sure you want to cancel the scan?')) {
                clearInterval(scanCheckInterval);
                scanningActive = false;
                hideScanModal();
                showNotification('Cancelled', 'Scan cancelled by user', 'info');
            }
        }

        function showScanModal(title) {
            $('#scanModalTitle').text(title);
            $('#scanPercentage').text('0%');
            $('#modalScanProgress').css('width', '0%');
            $('#scanStatusText').text('Initializing scan...');
            $('#scanCurrentFile').text('Preparing...');
            $('#scanBackdrop').addClass('active');
            $('#scanModal').addClass('active');
        }

        function hideScanModal() {
            $('#scanBackdrop').removeClass('active');
            $('#scanModal').removeClass('active');
        }

        // ==================== QUARANTINE ====================

        function loadQuarantineFiles() {
            $.ajax({
                url: "<?= MDIR ?>get-quarantine-files",
                method: "GET",
                dataType: "json",
                success: function(data) {
                    displayQuarantineFiles(data);
                },
                error: function(xhr, status, error) {
                    console.error('[ERROR] Failed to load quarantine:', error);
                }
            });
        }

        function displayQuarantineFiles(files) {
            const container = $('#quarantineList');
            
            if (!files || files.length === 0) {
                container.html(`
                    <div class="text-center text-muted">
                        <i class="bi bi-shield-check" style="font-size: 3rem;"></i>
                        <p>No quarantined files</p>
                    </div>
                `);
                return;
            }

            container.empty();
            files.forEach(file => {
                const html = `
                    <div class="alert alert-warning d-flex justify-content-between align-items-center mb-2">
                        <div style="min-width: 0; flex: 1;">
                            <i class="bi bi-file-earmark-x-fill"></i>
                            <strong class="ms-2" style="word-break: break-all;">${file.name}</strong><br>
                            <small class="ms-4 text-muted">${file.quarantine_date}</small>
                        </div>
                        <div style="flex-shrink: 0; margin-left: 10px;">
                            <button class="btn btn-sm btn-outline-success me-1" onclick="restoreFile('${file.id}')">
                                <i class="bi bi-arrow-return-left"></i> Restore
                            </button>
                            <button class="btn btn-sm btn-outline-danger" onclick="deleteFile('${file.id}')">
                                <i class="bi bi-trash"></i>
                            </button>
                        </div>
                    </div>
                `;
                container.append(html);
            });
        }

        function restoreFile(fileId) {
            if (confirm('Restore this file from quarantine?')) {
                $.ajax({
                    url: "<?= MDIR ?>restore-quarantine-file",
                    method: "POST",
                    data: { file_id: fileId },
                    dataType: "json",
                    success: function(response) {
                        if (response.success) {
                            showNotification('Restored', response.message, 'success');
                            loadQuarantineFiles();
                            updateStatistics();
                        } else {
                            showNotification('Error', response.message, 'error');
                        }
                    },
                    error: function(xhr, status, error) {
                        showNotification('Error', 'Failed to restore file', 'error');
                    }
                });
            }
        }

        function deleteFile(fileId) {
            if (confirm('Permanently delete this file? This action cannot be undone!')) {
                $.ajax({
                    url: "<?= MDIR ?>delete-quarantine-file",
                    method: "POST",
                    data: { file_id: fileId },
                    dataType: "json",
                    success: function(response) {
                        if (response.success) {
                            showNotification('Deleted', response.message, 'success');
                            loadQuarantineFiles();
                            updateStatistics();
                        } else {
                            showNotification('Error', response.message, 'error');
                        }
                    },
                    error: function(xhr, status, error) {
                        showNotification('Error', 'Failed to delete file', 'error');
                    }
                });
            }
        }

        // ==================== DETECTION LOG ====================

        function clearDetectionLog() {
            if (confirm('Clear all detection logs?')) {
                $('#detectionLogTable').html('<tr><td colspan="5" class="text-center text-muted">No detections recorded</td></tr>');
                showNotification('Cleared', 'Detection log cleared', 'info');
            }
        }

        // ==================== UTILITIES ====================

        function showNotification(title, message, type) {
            const colors = {
                success: '#28a745',
                error: '#dc3545',
                info: '#17a2b8',
                warning: '#ffc107'
            };
            
            const icon = {
                success: 'bi-check-circle-fill',
                error: 'bi-x-circle-fill',
                info: 'bi-info-circle-fill',
                warning: 'bi-exclamation-triangle-fill'
            };
            
            const notification = $(`
                <div class="alert alert-${type} alert-dismissible fade show position-fixed" 
                     style="top: 80px; right: 20px; z-index: 10001; min-width: 300px; box-shadow: 0 5px 15px rgba(0,0,0,0.3);">
                    <i class="bi ${icon[type]}"></i>
                    <strong>${title}:</strong> ${message}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            `);
            
            $('body').append(notification);
            
            setTimeout(function() {
                notification.fadeOut(function() {
                    $(this).remove();
                });
            }, 5000);
        }

        // Cleanup on page unload
        $(window).on('beforeunload', function() {
            stopActivityPolling();
            if (scanCheckInterval) {
                clearInterval(scanCheckInterval);
            }
        });
    </script>
</body>
</html>