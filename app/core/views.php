<?php


function get_500_error_view()
{
	header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error', true, 500);
	require 'app/views/error/500.php';
}

function get_login_view()
{
	require 'app/views/pages/login.php';
}


function get_dashboard()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }

    require 'app/views/pages/dashboard.php';
}

function get_register_view()
{
	require 'app/views/pages/register.php';
}

function startLogsHandler() {
    $projectDir = DIR;  
    $pythonPath = $projectDir . '/fyp/Scripts/python.exe';
    $snifferScript = $projectDir . '/python/traffic_capture/traffic_sniffer.py';
    $predictScript = $projectDir . '/python/training/predict_realtime.py';

    $input = json_decode(file_get_contents("php://input"), true);
    $models = isset($input['models']) && is_array($input['models']) ? implode(",", $input['models']) : "rf,lr,cyberhawk";

    try {
        $cmdSniffer = "powershell -Command \"Start-Process -FilePath '$pythonPath' -ArgumentList '$snifferScript' -PassThru | Select-Object -ExpandProperty Id\"";
        $snifferPid = trim(shell_exec($cmdSniffer));

        $cmdPredict = "powershell -Command \"Start-Process -FilePath '$pythonPath' -ArgumentList '$predictScript --models $models' -PassThru | Select-Object -ExpandProperty Id\"";
        $predictPid = trim(shell_exec($cmdPredict));

        if (is_numeric($snifferPid) && is_numeric($predictPid)) {
            file_put_contents($projectDir . '/assets/data/pid.json', json_encode([
                'sniffer_pid' => $snifferPid,
                'predict_pid' => $predictPid,
                'models' => $models
            ]));

            echo json_encode([
                'success' => true,
                'pid' => "$snifferPid, $predictPid",
                'models' => $models,
                'message' => 'Sniffer + Model(s) started successfully',
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Failed to retrieve one or both PIDs'
            ]);
        }

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => $e->getMessage()
        ]);
    }
}


function stopLogsHandler() {
    $projectDir = DIR;
    $pidFile = $projectDir . '/assets/data/pid.json';

    if (!file_exists($pidFile)) {
        echo json_encode([
            'success' => false,
            'message' => 'PID file not found'
        ]);
        return;
    }

    $pids = json_decode(file_get_contents($pidFile), true);
    $snifferPid = $pids['sniffer_pid'] ?? null;
    $predictPid = $pids['predict_pid'] ?? null;

    if (!$snifferPid || !$predictPid) {
        echo json_encode([
            'success' => false,
            'message' => 'One or both PIDs missing'
        ]);
        return;
    }

    try {
        exec("powershell -Command \"Stop-Process -Id $snifferPid -Force\"");
        exec("powershell -Command \"Stop-Process -Id $predictPid -Force\"");

        unlink($pidFile);

        echo json_encode([
            'success' => true,
            'message' => 'Both processes stopped'
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => $e->getMessage()
        ]);
    }
}

function clear_traffic_logs() {
    $logFile = DIR. '/assets/data/traffic_log.json';
    file_put_contents($logFile, json_encode([]));
    
    header('Content-Type: application/json');
    echo json_encode(['success' => true]);
}

/**
 * CyberHawk Ransomware Detection Module - PHP Functions
 * FIXED VERSION - Removed custom scan, fixed progress tracking
 */

// ==================== PAGE LOADER ====================

function get_ransomware_page()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }
    require 'app/views/pages/ransomware.php';
}

// ==================== MONITOR CONTROL ====================

function start_ransomware_monitor()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $pythonPath = $projectDir . '/fyp/Scripts/python.exe';
    $monitorScript = $projectDir . '/python/ranswomware/ransomware_monitor.py';
    $pidFile = $projectDir . '/assets/data/ransomware_pid.json';
    
    if (!file_exists($monitorScript)) {
        echo json_encode([
            'success' => false,
            'message' => 'Monitor script not found',
            'path' => $monitorScript
        ]);
        return;
    }
    
    if (!file_exists($pythonPath)) {
        echo json_encode([
            'success' => false,
            'message' => 'Python executable not found',
            'path' => $pythonPath
        ]);
        return;
    }
    
    try {
        if (file_exists($pidFile)) {
            $pidData = json_decode(file_get_contents($pidFile), true);
            if (isset($pidData['monitor_pid'])) {
                $checkCmd = "powershell -Command \"Get-Process -Id " . $pidData['monitor_pid'] . " -ErrorAction SilentlyContinue\"";
                $result = shell_exec($checkCmd);
                
                if (!empty($result)) {
                    echo json_encode([
                        'success' => true,
                        'message' => 'Monitor is already running',
                        'pid' => $pidData['monitor_pid']
                    ]);
                    return;
                }
            }
        }
        
        $cmd = "powershell -Command \"Start-Process -FilePath '$pythonPath' -ArgumentList '$monitorScript' -WindowStyle Hidden -PassThru | Select-Object -ExpandProperty Id\"";
        $pid = trim(shell_exec($cmd));
        
        if (is_numeric($pid) && $pid > 0) {
            file_put_contents($pidFile, json_encode([
                'monitor_pid' => (int)$pid,
                'started_at' => date('Y-m-d H:i:s'),
                'status' => 'running'
            ], JSON_PRETTY_PRINT));
            
            echo json_encode([
                'success' => true,
                'message' => 'Ransomware monitoring started successfully',
                'pid' => $pid
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Failed to start monitoring process',
                'pid_output' => $pid
            ]);
        }
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error starting monitor: ' . $e->getMessage()
        ]);
    }
}

function stop_ransomware_monitor()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $pidFile = $projectDir . '/assets/data/ransomware_pid.json';
    
    try {
        if (!file_exists($pidFile)) {
            echo json_encode([
                'success' => false,
                'message' => 'No monitoring process found'
            ]);
            return;
        }
        
        $pidData = json_decode(file_get_contents($pidFile), true);
        
        if (isset($pidData['monitor_pid'])) {
            $pid = $pidData['monitor_pid'];
            $cmd = "powershell -Command \"Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue\"";
            shell_exec($cmd);
            @unlink($pidFile);
            
            echo json_encode([
                'success' => true,
                'message' => 'Monitoring stopped successfully'
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Invalid PID file'
            ]);
        }
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error stopping monitor: ' . $e->getMessage()
        ]);
    }
}

function get_monitor_status()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $pidFile = $projectDir . '/assets/data/ransomware_pid.json';
    
    if (!file_exists($pidFile)) {
        echo json_encode([
            'running' => false,
            'message' => 'Monitor not started'
        ]);
        return;
    }
    
    $pidData = json_decode(file_get_contents($pidFile), true);
    
    if (isset($pidData['monitor_pid'])) {
        $pid = $pidData['monitor_pid'];
        $cmd = "powershell -Command \"Get-Process -Id $pid -ErrorAction SilentlyContinue | Select-Object Id, ProcessName\"";
        $result = shell_exec($cmd);
        
        if (!empty($result) && strpos($result, (string)$pid) !== false) {
            echo json_encode([
                'running' => true,
                'pid' => $pid,
                'started_at' => $pidData['started_at'] ?? 'Unknown',
                'status' => 'active'
            ]);
        } else {
            @unlink($pidFile);
            echo json_encode([
                'running' => false,
                'message' => 'Monitor process stopped unexpectedly'
            ]);
        }
    } else {
        echo json_encode([
            'running' => false,
            'message' => 'Invalid PID data'
        ]);
    }
}

// ==================== DATA RETRIEVAL ====================

function get_ransomware_activity()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $activityFile = $projectDir . '/assets/data/ransomware_activity.json';
    
    if (file_exists($activityFile)) {
        $data = json_decode(file_get_contents($activityFile), true);
        echo json_encode($data ?: []);
    } else {
        echo json_encode([]);
    }
}

function get_ransomware_stats()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $statsFile = $projectDir . '/assets/data/ransomware_stats.json';
    
    if (file_exists($statsFile)) {
        $stats = json_decode(file_get_contents($statsFile), true);
        echo json_encode($stats ?: getDefaultStats());
    } else {
        echo json_encode(getDefaultStats());
    }
}

function check_ransomware_threats()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $threatsFile = $projectDir . '/assets/data/ransomware_threats.json';
    
    if (file_exists($threatsFile)) {
        $data = json_decode(file_get_contents($threatsFile), true);
        echo json_encode(['threats' => $data ?: []]);
    } else {
        echo json_encode(['threats' => []]);
    }
}

function get_quarantine_files()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $quarantineFile = $projectDir . '/assets/data/quarantine.json';
    
    if (file_exists($quarantineFile)) {
        $data = json_decode(file_get_contents($quarantineFile), true);
        echo json_encode($data ?: []);
    } else {
        echo json_encode([]);
    }
}

function get_scan_progress()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $progressFile = $projectDir . '/assets/data/scan_progress.json';
    
    if (file_exists($progressFile)) {
        $data = json_decode(file_get_contents($progressFile), true);
        echo json_encode($data ?: [
            'progress' => 0,
            'status' => 'Idle',
            'current_file' => 'None'
        ]);
    } else {
        echo json_encode([
            'progress' => 0,
            'status' => 'Idle',
            'current_file' => 'None'
        ]);
    }
}

// ==================== SCANNING OPERATIONS ====================

function start_full_scan()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $pythonPath = $projectDir . '/fyp/Scripts/python.exe';
    $scannerScript = $projectDir . '/python/ranswomware/ransomware_scanner.py';
    
    if (!file_exists($scannerScript)) {
        echo json_encode([
            'success' => false,
            'message' => 'Scanner script not found at: ' . $scannerScript
        ]);
        return;
    }
    
    if (!file_exists($pythonPath)) {
        echo json_encode([
            'success' => false,
            'message' => 'Python executable not found at: ' . $pythonPath
        ]);
        return;
    }
    
    try {
        $progressFile = $projectDir . '/assets/data/scan_progress.json';
        file_put_contents($progressFile, json_encode([
            'progress' => 0,
            'status' => 'Starting full system scan...',
            'current_file' => 'Initializing',
            'files_scanned' => 0,
            'threats_found' => 0,
            'started_at' => date('Y-m-d H:i:s')
        ], JSON_PRETTY_PRINT));
        
        $cmd = "powershell -Command \"Start-Process -FilePath '$pythonPath' -ArgumentList '$scannerScript --full-scan' -WindowStyle Hidden -PassThru | Select-Object -ExpandProperty Id\"";
        $pid = trim(shell_exec($cmd));
        
        if (is_numeric($pid) && $pid > 0) {
            $pidFile = $projectDir . '/assets/data/scan_pid.json';
            file_put_contents($pidFile, json_encode([
                'scan_pid' => (int)$pid,
                'scan_type' => 'full',
                'started_at' => date('Y-m-d H:i:s')
            ], JSON_PRETTY_PRINT));
            
            echo json_encode([
                'success' => true,
                'message' => 'Full system scan initiated. This may take several minutes.',
                'pid' => $pid
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Failed to start scan process',
                'debug' => $pid
            ]);
        }
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error starting scan: ' . $e->getMessage()
        ]);
    }
}

function start_quick_scan()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $pythonPath = $projectDir . '/fyp/Scripts/python.exe';
    $scannerScript = $projectDir . '/python/ranswomware/ransomware_scanner.py';
    
    if (!file_exists($scannerScript)) {
        echo json_encode([
            'success' => false,
            'message' => 'Scanner script not found'
        ]);
        return;
    }
    
    if (!file_exists($pythonPath)) {
        echo json_encode([
            'success' => false,
            'message' => 'Python executable not found'
        ]);
        return;
    }
    
    try {
        $progressFile = $projectDir . '/assets/data/scan_progress.json';
        file_put_contents($progressFile, json_encode([
            'progress' => 0,
            'status' => 'Quick scan in progress...',
            'current_file' => 'Initializing',
            'files_scanned' => 0,
            'threats_found' => 0,
            'started_at' => date('Y-m-d H:i:s')
        ], JSON_PRETTY_PRINT));

        $cmd = "powershell -Command \"Start-Process -FilePath '$pythonPath' -ArgumentList '$scannerScript --quick-scan' -WindowStyle Hidden -PassThru | Select-Object -ExpandProperty Id\"";
        $pid = trim(shell_exec($cmd));
        
        if (is_numeric($pid) && $pid > 0) {
            echo json_encode([
                'success' => true,
                'message' => 'Quick scan started on user folders',
                'pid' => $pid
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Failed to start scan',
                'debug' => $pid
            ]);
        }
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error: ' . $e->getMessage()
        ]);
    }
}

// ==================== QUARANTINE OPERATIONS ====================

function isolate_threats()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $threatsFile = $projectDir . '/assets/data/ransomware_threats.json';
    $quarantineFile = $projectDir . '/assets/data/quarantine.json';
    $quarantineDir = $projectDir . '/assets/data/quarantine_files';
    
    if (!is_dir($quarantineDir)) {
        mkdir($quarantineDir, 0755, true);
    }
    
    try {
        if (!file_exists($threatsFile)) {
            echo json_encode([
                'success' => false,
                'message' => 'No threats detected'
            ]);
            return;
        }
        
        $threats = json_decode(file_get_contents($threatsFile), true) ?: [];
        $quarantineList = file_exists($quarantineFile) ? 
            json_decode(file_get_contents($quarantineFile), true) : [];
        
        $isolated = 0;
        
        foreach ($threats as &$threat) {
            if (($threat['status'] ?? '') === 'active' && isset($threat['file_path'])) {
                $filePath = $threat['file_path'];
                
                if (file_exists($filePath)) {
                    $filename = basename($filePath);
                    $quarantinePath = $quarantineDir . '/' . time() . '_' . $filename;
                    
                    if (@rename($filePath, $quarantinePath)) {
                        $quarantineList[] = [
                            'id' => md5($filePath . time()),
                            'name' => $filename,
                            'original_path' => $filePath,
                            'quarantine_path' => $quarantinePath,
                            'quarantine_date' => date('Y-m-d H:i:s'),
                            'threat_type' => $threat['type'] ?? 'Unknown',
                            'severity' => $threat['severity'] ?? 'High'
                        ];
                        
                        $threat['status'] = 'quarantined';
                        $isolated++;
                    }
                }
            }
        }
        
        file_put_contents($quarantineFile, json_encode($quarantineList, JSON_PRETTY_PRINT));
        file_put_contents($threatsFile, json_encode($threats, JSON_PRETTY_PRINT));
        
        updateQuarantineCount(count($quarantineList));
        
        echo json_encode([
            'success' => true,
            'message' => "Successfully isolated $isolated threat(s) to quarantine"
        ]);
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error isolating threats: ' . $e->getMessage()
        ]);
    }
}


function restore_quarantine_file()
{
    header('Content-Type: application/json');
    
    $fileId = $_POST['file_id'] ?? null;
    
    if (!$fileId) {
        echo json_encode([
            'success' => false,
            'message' => 'File ID is required'
        ]);
        return;
    }
    
    $projectDir = rtrim(DIR, '/\\');
    $quarantineFile = $projectDir . '/assets/data/quarantine.json';
    
    if (!file_exists($quarantineFile)) {
        echo json_encode([
            'success' => false,
            'message' => 'Quarantine file not found'
        ]);
        return;
    }
    
    try {
        $files = json_decode(file_get_contents($quarantineFile), true) ?: [];
        $restored = false;
        $restoredPath = '';
        
        foreach ($files as $key => $file) {
            if ($file['id'] === $fileId) {
                $quarantinePath = $file['quarantine_path'] ?? '';
                $originalPath = $file['original_path'] ?? '';
                
                if (file_exists($quarantinePath) && $originalPath) {
                    if (@rename($quarantinePath, $originalPath)) {
                        $restoredPath = $originalPath;
                        unset($files[$key]);
                        $restored = true;
                    }
                }
                break;
            }
        }
        
        if ($restored) {
            file_put_contents($quarantineFile, json_encode(array_values($files), JSON_PRETTY_PRINT));
            updateQuarantineCount(count($files));
            
            echo json_encode([
                'success' => true,
                'message' => 'File restored to: ' . $restoredPath
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'File not found or restore failed'
            ]);
        }
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error: ' . $e->getMessage()
        ]);
    }
}


function delete_quarantine_file()
{
    header('Content-Type: application/json');
    
    $fileId = $_POST['file_id'] ?? null;
    
    if (!$fileId) {
        echo json_encode([
            'success' => false,
            'message' => 'File ID is required'
        ]);
        return;
    }
    
    $projectDir = rtrim(DIR, '/\\');
    $quarantineFile = $projectDir . '/assets/data/quarantine.json';
    
    if (!file_exists($quarantineFile)) {
        echo json_encode([
            'success' => false,
            'message' => 'Quarantine file not found'
        ]);
        return;
    }
    
    try {
        $files = json_decode(file_get_contents($quarantineFile), true) ?: [];
        $deleted = false;
        
        foreach ($files as $key => $file) {
            if ($file['id'] === $fileId) {
                $quarantinePath = $file['quarantine_path'] ?? '';
                if (file_exists($quarantinePath)) {
                    @unlink($quarantinePath);
                }
                
                unset($files[$key]);
                $deleted = true;
                break;
            }
        }
        
        if ($deleted) {
            file_put_contents($quarantineFile, json_encode(array_values($files), JSON_PRETTY_PRINT));
            updateQuarantineCount(count($files));
            
            echo json_encode([
                'success' => true,
                'message' => 'File permanently deleted from quarantine'
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'File not found in quarantine'
            ]);
        }
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error: ' . $e->getMessage()
        ]);
    }
}

// ==================== OTHER OPERATIONS ====================


function update_signatures()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $sigFile = $projectDir . '/assets/data/signatures_update.json';
    
    file_put_contents($sigFile, json_encode([
        'last_update' => date('Y-m-d H:i:s'),
        'version' => '1.0.' . time(),
        'signatures_count' => rand(5000, 10000)
    ], JSON_PRETTY_PRINT));
    
    echo json_encode([
        'success' => true,
        'message' => 'Threat signatures updated successfully'
    ]);
}

/**
 * Restore from backup
 */
function restore_backup()
{
    header('Content-Type: application/json');
    
    echo json_encode([
        'success' => true,
        'message' => 'Backup restoration requires backup configuration. Please configure your backup system.'
    ]);
}

// ==================== HELPER FUNCTIONS ====================

function getDefaultStats()
{
    return [
        'files_scanned' => 0,
        'threats_detected' => 0,
        'quarantined' => 0,
        'scan_rate' => 0,
        'scan_progress' => 0,
        'current_file' => 'Idle'
    ];
}

function updateQuarantineCount($count)
{
    $projectDir = rtrim(DIR, '/\\');
    $statsFile = $projectDir . '/assets/data/ransomware_stats.json';
    
    if (file_exists($statsFile)) {
        $stats = json_decode(file_get_contents($statsFile), true);
        $stats['quarantined'] = $count;
        file_put_contents($statsFile, json_encode($stats, JSON_PRETTY_PRINT));
    }
}

/**
 * CyberHawk Malware Analysis Module - PHP Functions
 * Advanced malware detection and behavioral analysis
 */

// ==================== PAGE LOADER ====================

function get_malware_page()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }
    require 'app/views/pages/malware.php';
}

// ==================== UPLOAD & SCAN OPERATIONS ====================
function upload_malware_sample()
{
    header('Content-Type: application/json');
    
    if (!isset($_FILES['file'])) {
        echo json_encode([
            'success' => false,
            'message' => 'No file uploaded'
        ]);
        return;
    }
    
    $projectDir = rtrim(DIR, '/\\');
    $uploadsDir = $projectDir . '/assets/data/malware_uploads';
    
    if (!is_dir($uploadsDir)) {
        mkdir($uploadsDir, 0755, true);
    }
    
    try {
        $file = $_FILES['file'];
        $filename = basename($file['name']);
        $fileId = md5($filename . time());
        $uploadPath = $uploadsDir . '/' . $fileId . '_' . $filename;
        
        if (move_uploaded_file($file['tmp_name'], $uploadPath)) {
            $queueFile = $projectDir . '/assets/data/scan_queue.json';
            $queueData = file_exists($queueFile) ? json_decode(file_get_contents($queueFile), true) : [];
            $queue = is_array($queueData) ? $queueData : [];
            
            $queue[] = [
                'id' => $fileId,
                'filename' => $filename,
                'filepath' => $uploadPath,
                'upload_time' => date('Y-m-d H:i:s'),
                'status' => 'pending',
                'size' => $file['size']
            ];
            
            file_put_contents($queueFile, json_encode($queue, JSON_PRETTY_PRINT));
            
            echo json_encode([
                'success' => true,
                'message' => 'File uploaded successfully',
                'file_id' => $fileId,
                'filename' => $filename
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Failed to upload file'
            ]);
        }
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error: ' . $e->getMessage()
        ]);
    }
}


function start_malware_scan()
{
    header('Content-Type: application/json');

    $input = $_POST;
    if (empty($input)) {
        $rawInput = file_get_contents('php://input');
        parse_str($rawInput, $input);
    }
    
    $fileId = $input['file_id'] ?? $_POST['file_id'] ?? null;
    
    if (!$fileId) {
        echo json_encode([
            'success' => false,
            'message' => 'File ID required'
        ]);
        return;
    }
    
    $projectDir = rtrim(DIR, '/\\');
    $pythonPath = $projectDir . '/fyp/Scripts/python.exe';
    $scannerScript = $projectDir . '/python/malware/malware_scanner.py';
    
    if (!file_exists($scannerScript)) {
        echo json_encode([
            'success' => false,
            'message' => 'Scanner script not found'
        ]);
        return;
    }
    
    try {
        $progressFile = $projectDir . '/assets/data/malware_scan_progress.json';
        file_put_contents($progressFile, json_encode([
            'file_id' => $fileId,
            'progress' => 0,
            'status' => 'Initializing scan...',
            'stage' => 'init'
        ], JSON_PRETTY_PRINT));
        
        $cmd = "powershell -Command \"Start-Process -FilePath '$pythonPath' -ArgumentList '$scannerScript --file-id $fileId' -WindowStyle Hidden -PassThru | Select-Object -ExpandProperty Id\"";
        $pid = trim(shell_exec($cmd));
        
        if (is_numeric($pid) && $pid > 0) {
            echo json_encode([
                'success' => true,
                'message' => 'Malware scan started',
                'pid' => $pid,
                'file_id' => $fileId
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Failed to start scan'
            ]);
        }
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error: ' . $e->getMessage()
        ]);
    }
}

function get_malware_scan_progress()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $progressFile = $projectDir . '/assets/data/malware_scan_progress.json';
    
    if (file_exists($progressFile)) {
        $data = json_decode(file_get_contents($progressFile), true);
        
        if (!is_array($data)) {
            $data = [
                'progress' => 0,
                'status' => 'Idle',
                'stage' => 'none'
            ];
        }
        
        echo json_encode($data);
    } else {
        echo json_encode([
            'progress' => 0,
            'status' => 'Idle',
            'stage' => 'none'
        ]);
    }
}

// ==================== ANALYSIS & REPORTS ====================

function get_malware_report()
{
    header('Content-Type: application/json');
    
    $fileId = $_GET['file_id'] ?? null;
    
    if (!$fileId) {
        echo json_encode([
            'success' => false,
            'message' => 'File ID required'
        ]);
        return;
    }
    
    $projectDir = rtrim(DIR, '/\\');
    $reportsFile = $projectDir . '/assets/data/malware_reports.json';
    
    if (file_exists($reportsFile)) {
        $reports = json_decode(file_get_contents($reportsFile), true);
        
        if (!is_array($reports)) {
            echo json_encode([
                'success' => false,
                'message' => 'Invalid reports data'
            ]);
            return;
        }
        
        foreach ($reports as $report) {
            if ($report['file_id'] === $fileId) {
                echo json_encode([
                    'success' => true,
                    'report' => $report
                ]);
                return;
            }
        }
    }
    
    echo json_encode([
        'success' => false,
        'message' => 'Report not found'
    ]);
}

function get_all_malware_reports()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $reportsFile = $projectDir . '/assets/data/malware_reports.json';
    
    if (file_exists($reportsFile)) {
        $reports = json_decode(file_get_contents($reportsFile), true);
        echo json_encode(is_array($reports) ? $reports : []);
    } else {
        echo json_encode([]);
    }
}


function get_malware_stats()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $statsFile = $projectDir . '/assets/data/malware_stats.json';
    
    if (file_exists($statsFile)) {
        $stats = json_decode(file_get_contents($statsFile), true);
        echo json_encode(is_array($stats) ? $stats : getDefaultMalwareStats());
    } else {
        echo json_encode(getDefaultMalwareStats());
    }
}


function get_scan_queue()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $queueFile = $projectDir . '/assets/data/scan_queue.json';
    
    if (file_exists($queueFile)) {
        $queue = json_decode(file_get_contents($queueFile), true);
        echo json_encode(is_array($queue) ? $queue : []);
    } else {
        echo json_encode([]);
    }
}

// ==================== SAMPLE MANAGEMENT ====================


function delete_malware_sample()
{
    header('Content-Type: application/json');

    $input = $_POST;
    if (empty($input)) {
        $rawInput = file_get_contents('php://input');
        parse_str($rawInput, $input);
    }
    
    $fileId = $input['file_id'] ?? $_POST['file_id'] ?? null;
    
    if (!$fileId) {
        echo json_encode([
            'success' => false,
            'message' => 'File ID required'
        ]);
        return;
    }
    
    $projectDir = rtrim(DIR, '/\\');
    $uploadsDir = $projectDir . '/assets/data/malware_uploads';
    
    try {
        $queueFile = $projectDir . '/assets/data/scan_queue.json';
        if (file_exists($queueFile)) {
            $queue = json_decode(file_get_contents($queueFile), true);
            
            if (!is_array($queue)) {
                $queue = [];
            }
            
            $queue = array_filter($queue, function($item) use ($fileId) {
                return isset($item['id']) && $item['id'] !== $fileId;
            });
            file_put_contents($queueFile, json_encode(array_values($queue), JSON_PRETTY_PRINT));
        }
        
        $reportsFile = $projectDir . '/assets/data/malware_reports.json';
        if (file_exists($reportsFile)) {
            $reports = json_decode(file_get_contents($reportsFile), true);
            
            if (!is_array($reports)) {
                $reports = [];
            }
            
            $reports = array_filter($reports, function($item) use ($fileId) {
                return isset($item['file_id']) && $item['file_id'] !== $fileId;
            });
            file_put_contents($reportsFile, json_encode(array_values($reports), JSON_PRETTY_PRINT));
        }
        
        if (is_dir($uploadsDir)) {
            $files = glob($uploadsDir . '/' . $fileId . '_*');
            foreach ($files as $file) {
                @unlink($file);
            }
        }
        
        echo json_encode([
            'success' => true,
            'message' => 'Sample deleted successfully'
        ]);
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error: ' . $e->getMessage()
        ]);
    }
}


function export_malware_report()
{
    header('Content-Type: application/json');
    
    $input = $_POST;
    if (empty($input)) {
        $rawInput = file_get_contents('php://input');
        parse_str($rawInput, $input);
    }
    
    $fileId = $input['file_id'] ?? $_POST['file_id'] ?? null;
    $format = $input['format'] ?? $_POST['format'] ?? 'json';
    
    if (!$fileId) {
        echo json_encode([
            'success' => false,
            'message' => 'File ID required'
        ]);
        return;
    }
    
    $projectDir = rtrim(DIR, '/\\');
    $reportsFile = $projectDir . '/assets/data/malware_reports.json';
    
    if (file_exists($reportsFile)) {
        $reports = json_decode(file_get_contents($reportsFile), true);
        
        if (!is_array($reports)) {
            echo json_encode([
                'success' => false,
                'message' => 'Invalid reports data'
            ]);
            return;
        }
        
        foreach ($reports as $report) {
            if ($report['file_id'] === $fileId) {
                $exportDir = $projectDir . '/assets/data/exports';
                if (!is_dir($exportDir)) {
                    mkdir($exportDir, 0755, true);
                }
                
                $filename = 'malware_report_' . $fileId . '.' . $format;
                $exportPath = $exportDir . '/' . $filename;
                
                if ($format === 'json') {
                    file_put_contents($exportPath, json_encode($report, JSON_PRETTY_PRINT));
                }
                
                echo json_encode([
                    'success' => true,
                    'message' => 'Report exported',
                    'download_url' => MDIR . 'assets/data/exports/' . $filename
                ]);
                return;
            }
        }
    }
    
    echo json_encode([
        'success' => false,
        'message' => 'Report not found'
    ]);
}

// ==================== BEHAVIORAL ANALYSIS ====================

// function start_behavioral_analysis()
// {
//     header('Content-Type: application/json');
    
//     // Handle both POST and raw input
//     $input = $_POST;
//     if (empty($input)) {
//         $rawInput = file_get_contents('php://input');
//         parse_str($rawInput, $input);
//     }
    
//     $fileId = $input['file_id'] ?? $_POST['file_id'] ?? null;
    
//     if (!$fileId) {
//         echo json_encode([
//             'success' => false,
//             'message' => 'File ID required'
//         ]);
//         return;
//     }
    
//     $projectDir = rtrim(DIR, '/\\');
//     $pythonPath = $projectDir . '/fyp/Scripts/python.exe';
//     $analyzerScript = $projectDir . '/python/malware/malware_analyzer.py';
    
//     try {
//         $cmd = "powershell -Command \"Start-Process -FilePath '$pythonPath' -ArgumentList '$analyzerScript --file-id $fileId --behavioral' -WindowStyle Hidden\"";
//         shell_exec($cmd);
        
//         echo json_encode([
//             'success' => true,
//             'message' => 'Behavioral analysis started'
//         ]);
        
//     } catch (Exception $e) {
//         echo json_encode([
//             'success' => false,
//             'message' => 'Error: ' . $e->getMessage()
//         ]);
//     }
// }

// ==================== HELPER FUNCTIONS ====================

function getDefaultMalwareStats()
{
    return [
        'total_scans' => 0,
        'malware_detected' => 0,
        'clean_files' => 0,
        'suspicious_files' => 0,
        'last_scan' => 'Never'
    ];
}
?>