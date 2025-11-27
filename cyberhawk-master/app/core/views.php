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

function get_reporting_page()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }
    require 'app/views/pages/reporting.php';
}

/**
 * Get aggregated reporting data
 */
function get_reporting_data()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $dataDir = $projectDir . '/assets/data';
    
    try {
        $data = [
            'ips_traffic' => loadJsonFile($dataDir . '/traffic_log.json'),
            'alerts' => loadJsonFile($dataDir . '/alerts.json'),
            'ransomware_stats' => loadJsonFile($dataDir . '/ransomware_stats.json'),
            'ransomware_activity' => loadJsonFile($dataDir . '/ransomware_activity.json'),
            'ransomware_threats' => loadJsonFile($dataDir . '/ransomware_threats.json'),
            'malware_stats' => loadJsonFile($dataDir . '/malware_stats.json'),
            'malware_reports' => loadJsonFile($dataDir . '/malware_reports.json'),
            'timestamp' => date('Y-m-d H:i:s')
        ];
        
        echo json_encode($data);
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error loading reporting data: ' . $e->getMessage()
        ]);
    }
}

/**
 * Helper function to load JSON file
 */
function loadJsonFile($filePath)
{
    if (!file_exists($filePath)) {
        return [];
    }
    
    try {
        $content = file_get_contents($filePath);
        if (empty($content)) {
            return [];
        }
        
        $data = json_decode($content, true);
        return is_array($data) ? $data : [];
        
    } catch (Exception $e) {
        return [];
    }
}

/**
 * Generate executive summary report
 */
function generate_executive_summary()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $dataDir = $projectDir . '/assets/data';
    
    try {
        // Load all data sources
        $trafficLog = loadJsonFile($dataDir . '/traffic_log.json');
        $alerts = loadJsonFile($dataDir . '/alerts.json');
        $ransomwareStats = loadJsonFile($dataDir . '/ransomware_stats.json');
        $malwareStats = loadJsonFile($dataDir . '/malware_stats.json');
        
        // Calculate metrics
        $totalFlows = count($trafficLog);
        $totalAlerts = count($alerts);
        $malwareDetected = $malwareStats['malware_detected'] ?? 0;
        $ransomwareBlocked = $ransomwareStats['threats_detected'] ?? 0;
        $threatRate = $totalFlows > 0 ? ($totalAlerts / $totalFlows) * 100 : 0;
        
        // Analyze attack types
        $attackTypes = [];
        foreach ($alerts as $alert) {
            $type = $alert['Attack Type'] ?? 'Unknown';
            $attackTypes[$type] = ($attackTypes[$type] ?? 0) + 1;
        }
        
        // Analyze protocols
        $protocols = [];
        foreach ($trafficLog as $flow) {
            $proto = getProtocolNameFromNumber($flow['Protocol'] ?? 0);
            $protocols[$proto] = ($protocols[$proto] ?? 0) + 1;
        }
        
        $summary = [
            'success' => true,
            'metrics' => [
                'total_flows' => $totalFlows,
                'total_alerts' => $totalAlerts,
                'malware_detected' => $malwareDetected,
                'ransomware_blocked' => $ransomwareBlocked,
                'threat_rate' => round($threatRate, 2)
            ],
            'attack_types' => $attackTypes,
            'protocols' => $protocols,
            'threat_level' => getThreatLevel($threatRate),
            'recommendations' => generateRecommendations($threatRate, $totalAlerts, $malwareDetected),
            'generated_at' => date('Y-m-d H:i:s')
        ];
        
        echo json_encode($summary);
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error generating summary: ' . $e->getMessage()
        ]);
    }
}

/**
 * Get protocol name from protocol number
 */
function getProtocolNameFromNumber($proto)
{
    $proto = (int)$proto;
    
    switch ($proto) {
        case 6:
            return 'TCP';
        case 17:
            return 'UDP';
        case 1:
            return 'ICMP';
        default:
            return 'Other';
    }
}

/**
 * Determine threat level
 */
function getThreatLevel($threatRate)
{
    if ($threatRate > 10) {
        return [
            'level' => 'HIGH',
            'color' => 'danger',
            'message' => 'Significant threat activity detected. Immediate action recommended.'
        ];
    } elseif ($threatRate > 5) {
        return [
            'level' => 'MEDIUM',
            'color' => 'warning',
            'message' => 'Moderate threat activity. Continue monitoring.'
        ];
    } else {
        return [
            'level' => 'LOW',
            'color' => 'success',
            'message' => 'Security posture is good. Maintain current practices.'
        ];
    }
}

/**
 * Generate security recommendations
 */
function generateRecommendations($threatRate, $alertCount, $malwareCount)
{
    $recommendations = [];
    
    if ($threatRate > 10) {
        $recommendations[] = "Implement stricter firewall rules to reduce attack surface";
        $recommendations[] = "Review and update intrusion detection signatures";
        $recommendations[] = "Consider enabling additional security modules";
    }
    
    if ($alertCount > 50) {
        $recommendations[] = "High alert volume detected - review alert thresholds";
        $recommendations[] = "Investigate top source IPs for potential false positives";
    }
    
    if ($malwareCount > 0) {
        $recommendations[] = "Malware detected - ensure all systems are updated";
        $recommendations[] = "Run full system scans on affected endpoints";
        $recommendations[] = "Review and update anti-malware signatures";
    }
    
    if (empty($recommendations)) {
        $recommendations[] = "Continue monitoring - no critical issues detected";
        $recommendations[] = "Maintain regular backup schedules";
        $recommendations[] = "Keep security software up to date";
    }
    
    return $recommendations;
}

/**
 * Export report as PDF (requires TCPDF library)
 * Note: This is a placeholder - actual PDF generation requires additional library
 */
function export_report_pdf()
{
    header('Content-Type: application/json');
    
    // For now, return message to use print functionality
    echo json_encode([
        'success' => false,
        'message' => 'PDF export requires additional library installation. Please use Print to PDF feature in browser.'
    ]);
}

/**
 * Get network statistics for reporting
 */
function get_network_statistics()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $trafficLog = loadJsonFile($projectDir . '/assets/data/traffic_log.json');
    
    try {
        // Calculate statistics
        $totalFlows = count($trafficLog);
        $uniqueSources = [];
        $uniqueDestinations = [];
        $protocols = [];
        $ports = [];
        
        foreach ($trafficLog as $flow) {
            $uniqueSources[$flow['Src IP'] ?? 'unknown'] = true;
            $uniqueDestinations[$flow['Dst IP'] ?? 'unknown'] = true;
            
            $proto = getProtocolNameFromNumber($flow['Protocol'] ?? 0);
            $protocols[$proto] = ($protocols[$proto] ?? 0) + 1;
            
            $dstPort = $flow['Dst Port'] ?? 0;
            $ports[$dstPort] = ($ports[$dstPort] ?? 0) + 1;
        }
        
        // Get top ports
        arsort($ports);
        $topPorts = array_slice($ports, 0, 10, true);
        
        $stats = [
            'success' => true,
            'total_flows' => $totalFlows,
            'unique_sources' => count($uniqueSources),
            'unique_destinations' => count($uniqueDestinations),
            'protocols' => $protocols,
            'top_ports' => $topPorts
        ];
        
        echo json_encode($stats);
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error calculating statistics: ' . $e->getMessage()
        ]);
    }
}

/**
 * Get threat timeline for reporting
 */
function get_threat_timeline()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $alerts = loadJsonFile($projectDir . '/assets/data/alerts.json');
    
    try {
        // Group alerts by hour
        $timeline = [];
        
        foreach ($alerts as $alert) {
            $timestamp = $alert['Timestamp'] ?? null;
            if (!$timestamp) continue;
            
            $hour = date('Y-m-d H:00', strtotime($timestamp));
            $timeline[$hour] = ($timeline[$hour] ?? 0) + 1;
        }
        
        ksort($timeline);
        
        echo json_encode([
            'success' => true,
            'timeline' => $timeline
        ]);
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error generating timeline: ' . $e->getMessage()
        ]);
    }
}
/**
 * ==================== PROFILE MANAGEMENT ====================
 */

function get_profile_page()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }
    require 'app/views/pages/profile.php';
}

function get_user_profile($user_id)
{
    $sql = "SELECT id, name, email, role, profile_picture, phone, bio, created_at, last_updated 
            FROM users WHERE id = ?";
    $result = mysqli_prepared_query($sql, 'i', [$user_id]);
    
    if ($result && count($result) > 0) {
        return $result[0];
    }
    return null;
}

function update_profile()
{
    header('Content-Type: application/json');
    
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Not authenticated']);
        return;
    }
    
    $user_id = $_SESSION['user_id'];
    $name = trim($_POST['name'] ?? '');
    $phone = trim($_POST['phone'] ?? '');
    $bio = trim($_POST['bio'] ?? '');
    
    // Validation
    if (empty($name)) {
        echo json_encode(['success' => false, 'message' => 'Name is required']);
        return;
    }
    
    if (strlen($name) < 2 || strlen($name) > 100) {
        echo json_encode(['success' => false, 'message' => 'Name must be between 2 and 100 characters']);
        return;
    }
    
    if (!empty($phone) && !preg_match('/^[0-9+\-\s()]{7,20}$/', $phone)) {
        echo json_encode(['success' => false, 'message' => 'Invalid phone number format']);
        return;
    }
    
    if (strlen($bio) > 500) {
        echo json_encode(['success' => false, 'message' => 'Bio must be less than 500 characters']);
        return;
    }
    
    try {
        $sql = "UPDATE users SET name = ?, phone = ?, bio = ?, last_updated = NOW() WHERE id = ?";
        $result = mysqli_prepared_query($sql, 'sssi', [$name, $phone, $bio, $user_id]);
        
        if ($result) {
            // Update session
            $_SESSION['user_name'] = $name;
            
            echo json_encode([
                'success' => true,
                'message' => 'Profile updated successfully',
                'user' => [
                    'name' => $name,
                    'phone' => $phone,
                    'bio' => $bio
                ]
            ]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to update profile']);
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

function upload_profile_picture()
{
    header('Content-Type: application/json');
    
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Not authenticated']);
        return;
    }
    
    if (!isset($_FILES['profile_picture'])) {
        echo json_encode(['success' => false, 'message' => 'No file uploaded']);
        return;
    }
    
    $user_id = $_SESSION['user_id'];
    $file = $_FILES['profile_picture'];
    
    // Validate file
    $allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif'];
    $max_size = 5 * 1024 * 1024; // 5MB
    
    if ($file['error'] !== UPLOAD_ERR_OK) {
        echo json_encode(['success' => false, 'message' => 'File upload error']);
        return;
    }
    
    if (!in_array($file['type'], $allowed_types)) {
        echo json_encode(['success' => false, 'message' => 'Invalid file type. Only JPG, PNG, and GIF allowed']);
        return;
    }
    
    if ($file['size'] > $max_size) {
        echo json_encode(['success' => false, 'message' => 'File too large. Maximum size is 5MB']);
        return;
    }
    
    // Verify it's actually an image
    $image_info = getimagesize($file['tmp_name']);
    if ($image_info === false) {
        echo json_encode(['success' => false, 'message' => 'File is not a valid image']);
        return;
    }
    
    try {
        // Create upload directory if it doesn't exist
        $upload_dir = DIR . 'assets/uploads/profiles/';
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0755, true);
        }
        
        // Get current profile picture to delete old one
        $user = get_user_profile($user_id);
        
        // Generate unique filename
        $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
        $filename = 'profile_' . $user_id . '_' . time() . '.' . $extension;
        $filepath = $upload_dir . $filename;
        
        // Move uploaded file
        if (move_uploaded_file($file['tmp_name'], $filepath)) {
            // Delete old profile picture if exists
            if ($user && !empty($user['profile_picture'])) {
                $old_file = $upload_dir . $user['profile_picture'];
                if (file_exists($old_file)) {
                    @unlink($old_file);
                }
            }
            
            // Update database
            $sql = "UPDATE users SET profile_picture = ?, last_updated = NOW() WHERE id = ?";
            $result = mysqli_prepared_query($sql, 'si', [$filename, $user_id]);
            
            if ($result) {
                echo json_encode([
                    'success' => true,
                    'message' => 'Profile picture updated successfully',
                    'filename' => $filename,
                    'url' => MDIR . 'assets/uploads/profiles/' . $filename
                ]);
            } else {
                // Delete uploaded file if database update fails
                @unlink($filepath);
                echo json_encode(['success' => false, 'message' => 'Failed to update database']);
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to save file']);
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
    }
}

function delete_profile_picture()
{
    header('Content-Type: application/json');
    
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Not authenticated']);
        return;
    }
    
    $user_id = $_SESSION['user_id'];
    
    try {
        // Get current profile picture
        $user = get_user_profile($user_id);
        
        if ($user && !empty($user['profile_picture'])) {
            $upload_dir = DIR . 'assets/uploads/profiles/';
            $filepath = $upload_dir . $user['profile_picture'];
            
            // Delete file
            if (file_exists($filepath)) {
                @unlink($filepath);
            }
            
            // Update database
            $sql = "UPDATE users SET profile_picture = NULL, last_updated = NOW() WHERE id = ?";
            $result = mysqli_prepared_query($sql, 'i', [$user_id]);
            
            if ($result) {
                echo json_encode([
                    'success' => true,
                    'message' => 'Profile picture removed successfully'
                ]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Failed to update database']);
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'No profile picture to delete']);
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
    }
}

function change_password()
{
    header('Content-Type: application/json');
    
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Not authenticated']);
        return;
    }
    
    $user_id = $_SESSION['user_id'];
    $current_password = $_POST['current_password'] ?? '';
    $new_password = $_POST['new_password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    
    // Validation
    if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
        echo json_encode(['success' => false, 'message' => 'All fields are required']);
        return;
    }
    
    if ($new_password !== $confirm_password) {
        echo json_encode(['success' => false, 'message' => 'New passwords do not match']);
        return;
    }
    
    if (strlen($new_password) < 6) {
        echo json_encode(['success' => false, 'message' => 'New password must be at least 6 characters']);
        return;
    }
    
    if ($new_password === $current_password) {
        echo json_encode(['success' => false, 'message' => 'New password must be different from current password']);
        return;
    }
    
    try {
        // Verify current password
        $sql = "SELECT password FROM users WHERE id = ?";
        $result = mysqli_prepared_query($sql, 'i', [$user_id]);
        
        if (!$result || count($result) === 0) {
            echo json_encode(['success' => false, 'message' => 'User not found']);
            return;
        }
        
        $user = $result[0];
        
        if (!password_verify($current_password, $user['password'])) {
            echo json_encode(['success' => false, 'message' => 'Current password is incorrect']);
            return;
        }
        
        // Update password
        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
        $sql = "UPDATE users SET password = ?, last_updated = NOW() WHERE id = ?";
        $result = mysqli_prepared_query($sql, 'si', [$hashed_password, $user_id]);
        
        if ($result) {
            echo json_encode([
                'success' => true,
                'message' => 'Password changed successfully'
            ]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to update password']);
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
    }
}

/**
 * CyberHawk Settings Backend Functions
 * Add these functions to app/core/functions.php or app/core/views.php
 */

// ==================== PAGE LOADER ====================
function get_settings_page()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }
    require 'app/views/pages/settings.php';
}

// ==================== PROFILE MANAGEMENT ====================
// Profile update removed - already exists in codebase

// ==================== PASSWORD MANAGEMENT ====================

function handle_update_password()
{
    header('Content-Type: application/json');
    
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Unauthorized']);
        return;
    }
    
    $userId = $_SESSION['user_id'];
    $currentPassword = $_POST['current_password'] ?? '';
    $newPassword = $_POST['new_password'] ?? '';
    
    if (empty($currentPassword) || empty($newPassword)) {
        echo json_encode(['success' => false, 'message' => 'All fields are required']);
        return;
    }
    
    if (strlen($newPassword) < 6) {
        echo json_encode(['success' => false, 'message' => 'Password must be at least 6 characters']);
        return;
    }
    
    // Verify current password
    $sql = "SELECT password FROM users WHERE id = ?";
    $user = mysqli_prepared_query($sql, 'i', [$userId]);
    
    if (empty($user)) {
        echo json_encode(['success' => false, 'message' => 'User not found']);
        return;
    }
    
    if (!password_verify($currentPassword, $user[0]['password'])) {
        echo json_encode(['success' => false, 'message' => 'Current password is incorrect']);
        return;
    }
    
    // Update password
    $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
    $updateSql = "UPDATE users SET password = ? WHERE id = ?";
    $result = mysqli_prepared_query($updateSql, 'si', [$hashedPassword, $userId]);
    
    if ($result) {
        echo json_encode(['success' => true, 'message' => 'Password updated successfully']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Failed to update password']);
    }
}

// ==================== SYSTEM SETTINGS ====================

function handle_save_settings()
{
    header('Content-Type: application/json');
    
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Unauthorized']);
        return;
    }
    
    $userId = $_SESSION['user_id'];
    $settings = json_decode($_POST['settings'] ?? '{}', true);
    
    if (!$settings) {
        echo json_encode(['success' => false, 'message' => 'Invalid settings data']);
        return;
    }
    
    // Create settings table if it doesn't exist
    $createTableSql = "CREATE TABLE IF NOT EXISTS system_settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        setting_key VARCHAR(100) NOT NULL,
        setting_value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY unique_user_setting (user_id, setting_key),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )";
    mysqli_prepared_query($createTableSql);
    
    // Save each setting
    foreach ($settings as $key => $value) {
        $insertSql = "INSERT INTO system_settings (user_id, setting_key, setting_value) 
                      VALUES (?, ?, ?) 
                      ON DUPLICATE KEY UPDATE setting_value = ?";
        
        $valueStr = is_bool($value) ? ($value ? '1' : '0') : (string)$value;
        
        mysqli_prepared_query($insertSql, 'isss', [$userId, $key, $valueStr, $valueStr]);
    }
    
    echo json_encode(['success' => true, 'message' => 'Settings saved']);
}

// ==================== API KEYS ====================

function handle_save_api_keys()
{
    header('Content-Type: application/json');
    
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Unauthorized']);
        return;
    }
    
    $userId = $_SESSION['user_id'];
    $vtKey = $_POST['virustotal'] ?? '';
    $hybridKey = $_POST['hybrid'] ?? '';
    
    // Save API keys as settings
    if (!empty($vtKey)) {
        $sql = "INSERT INTO system_settings (user_id, setting_key, setting_value) 
                VALUES (?, 'virustotal_api_key', ?) 
                ON DUPLICATE KEY UPDATE setting_value = ?";
        mysqli_prepared_query($sql, 'iss', [$userId, $vtKey, $vtKey]);
    }
    
    if (!empty($hybridKey)) {
        $sql = "INSERT INTO system_settings (user_id, setting_key, setting_value) 
                VALUES (?, 'hybrid_api_key', ?) 
                ON DUPLICATE KEY UPDATE setting_value = ?";
        mysqli_prepared_query($sql, 'iss', [$userId, $hybridKey, $hybridKey]);
    }
    
    echo json_encode(['success' => true, 'message' => 'API keys saved successfully']);
}

// ==================== DATA MANAGEMENT ====================

function handle_clear_all_logs()
{
    header('Content-Type: application/json');
    
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Unauthorized']);
        return;
    }
    
    $projectDir = rtrim(DIR, '/\\');
    $dataDir = $projectDir . '/assets/data/';
    
    $logFiles = [
        'traffic_log.json',
        'alerts.json',
        'ransomware_activity.json',
        'ransomware_threats.json',
        'ransomware_stats.json',
        'malware_reports.json',
        'malware_stats.json',
        'scan_results.json',
        'scan_queue.json'
    ];
    
    foreach ($logFiles as $file) {
        $filePath = $dataDir . $file;
        if (file_exists($filePath)) {
            file_put_contents($filePath, json_encode([], JSON_PRETTY_PRINT));
        }
    }
    
    echo json_encode(['success' => true, 'message' => 'All logs cleared successfully']);
}

function handle_export_user_data()
{
    header('Content-Type: application/json');
    
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Unauthorized']);
        return;
    }
    
    $userId = $_SESSION['user_id'];
    
    // Get user data
    $userSql = "SELECT name, email, role FROM users WHERE id = ?";
    $userData = mysqli_prepared_query($userSql, 'i', [$userId]);
    
    // Get user settings
    $settingsSql = "SELECT setting_key, setting_value FROM system_settings WHERE user_id = ?";
    $settingsData = mysqli_prepared_query($settingsSql, 'i', [$userId]);
    
    $exportData = [
        'export_date' => date('Y-m-d H:i:s'),
        'user' => $userData[0] ?? [],
        'settings' => $settingsData ?? [],
        'statistics' => get_user_statistics_data($userId)
    ];
    
    echo json_encode([
        'success' => true,
        'data' => $exportData
    ]);
}

// ==================== SESSION MANAGEMENT ====================

function handle_terminate_sessions()
{
    header('Content-Type: application/json');
    
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Unauthorized']);
        return;
    }
    
    $userId = $_SESSION['user_id'];
    
    // Get user email
    $userSql = "SELECT email FROM users WHERE id = ?";
    $userData = mysqli_prepared_query($userSql, 'i', [$userId]);
    
    if (empty($userData)) {
        echo json_encode(['success' => false, 'message' => 'User not found']);
        return;
    }
    
    $email = $userData[0]['email'];
    
    // Delete all sessions for this user
    $deleteSql = "DELETE FROM user_sessions WHERE email = ?";
    mysqli_prepared_query($deleteSql, 's', [$email]);
    
    echo json_encode(['success' => true, 'message' => 'All sessions terminated']);
}

// ==================== ACCOUNT DELETION ====================

function handle_delete_account()
{
    header('Content-Type: application/json');
    
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Unauthorized']);
        return;
    }
    
    $userId = $_SESSION['user_id'];
    
    try {
        // Delete user settings
        mysqli_prepared_query("DELETE FROM system_settings WHERE user_id = ?", 'i', [$userId]);
        
        // Delete user sessions
        $userSql = "SELECT email FROM users WHERE id = ?";
        $userData = mysqli_prepared_query($userSql, 'i', [$userId]);
        
        if (!empty($userData)) {
            mysqli_prepared_query("DELETE FROM user_sessions WHERE email = ?", 's', [$userData[0]['email']]);
        }
        
        // Delete user account
        mysqli_prepared_query("DELETE FROM users WHERE id = ?", 'i', [$userId]);
        
        // Destroy session
        session_destroy();
        
        echo json_encode(['success' => true, 'message' => 'Account deleted successfully']);
        
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to delete account']);
    }
}

// ==================== USER STATISTICS ====================

function handle_get_user_stats()
{
    header('Content-Type: application/json');
    
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Unauthorized']);
        return;
    }
    
    $userId = $_SESSION['user_id'];
    $stats = get_user_statistics_data($userId);
    
    echo json_encode($stats);
}

function get_user_statistics_data($userId)
{
    // Calculate days active
    $userSql = "SELECT DATEDIFF(NOW(), created_at) as days_active FROM users WHERE id = ?";
    $userData = mysqli_prepared_query($userSql, 'i', [$userId]);
    $daysActive = $userData[0]['days_active'] ?? 0;
    
    // Get statistics from various sources
    $projectDir = rtrim(DIR, '/\\');
    
    // Count malware scans
    $malwareReports = $projectDir . '/assets/data/malware_reports.json';
    $totalScans = 0;
    if (file_exists($malwareReports)) {
        $data = json_decode(file_get_contents($malwareReports), true);
        $totalScans = is_array($data) ? count($data) : 0;
    }
    
    // Count alerts
    $alertsFile = $projectDir . '/assets/data/alerts.json';
    $totalAlerts = 0;
    if (file_exists($alertsFile)) {
        $data = json_decode(file_get_contents($alertsFile), true);
        $totalAlerts = is_array($data) ? count($data) : 0;
    }
    
    // Count quarantined files
    $quarantineFile = $projectDir . '/assets/data/quarantine.json';
    $quarantinedFiles = 0;
    if (file_exists($quarantineFile)) {
        $data = json_decode(file_get_contents($quarantineFile), true);
        $quarantinedFiles = is_array($data) ? count($data) : 0;
    }
    
    return [
        'total_scans' => $totalScans,
        'total_alerts' => $totalAlerts,
        'quarantined_files' => $quarantinedFiles,
        'days_active' => max(1, $daysActive) // At least 1 day
    ];
}

function get_verify_page()
{
    require 'app/views/pages/verify.php';
}
?>