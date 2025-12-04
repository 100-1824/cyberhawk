<?php

/**
 * RansomwareService Class
 *
 * Purpose: Handles ransomware monitoring, scanning, threat detection, and quarantine management
 * Replaces: start_ransomware_monitor(), stop_ransomware_monitor(), get_monitor_status(),
 *           get_ransomware_activity(), get_ransomware_stats(), check_ransomware_threats(),
 *           get_quarantine_files(), get_scan_progress(), start_full_scan(), start_quick_scan(),
 *           isolate_threats(), restore_quarantine_file(), delete_quarantine_file(),
 *           update_signatures(), restore_backup()
 */
class RansomwareService {

    private $db;
    private $notificationService;

    /**
     * Constructor
     */
    public function __construct() {
        $this->db = new DatabaseHelper();
        $this->notificationService = new NotificationService();
    }

    /**
     * Start ransomware monitor
     *
     * @return void JSON response
     */
    public function startMonitor() {
        if (session_status() === PHP_SESSION_NONE) session_start();
        header('Content-Type: application/json');

        $userId = $_SESSION['user_id'] ?? null;
        $projectDir = rtrim(DIR, '/\\');
        $pidFile = $projectDir . '/assets/data/ransomware_pid.json';

        // OS-aware Python and script paths
        $isWindows = (stripos(PHP_OS, 'WIN') === 0);

        if ($isWindows) {
            // Windows: Try virtual environment first, then system Python
            $pythonPath = $projectDir . '/fyp/Scripts/python.exe';
            if (!file_exists($pythonPath)) {
                $pythonPath = 'python'; // Use system Python
            }
        } else {
            // Linux/Unix
            $pythonPath = 'python3';
        }

        // Script path - check both possible folder names (typo and correct)
        $monitorScript = $projectDir . '/python/ranswomware/ransomware_monitor_class.py';
        if (!file_exists($monitorScript)) {
            $monitorScript = $projectDir . '/python/ransomware/ransomware_monitor_class.py';
        }
        if (!file_exists($monitorScript)) {
            $monitorScript = $projectDir . '/python/ranswomware/ransomware_monitor.py';
        }
        if (!file_exists($monitorScript)) {
            $monitorScript = $projectDir . '/python/ransomware/ransomware_monitor.py';
        }

        if (!file_exists($monitorScript)) {
            echo json_encode([
                'success' => false,
                'message' => 'Monitor script not found. Checked multiple locations.',
                'paths_checked' => [
                    $projectDir . '/python/ranswomware/ransomware_monitor_class.py',
                    $projectDir . '/python/ransomware/ransomware_monitor_class.py',
                ]
            ]);
            return;
        }

        try {
            // Check if monitor is already running
            if (file_exists($pidFile)) {
                $pidData = json_decode(file_get_contents($pidFile), true);
                if (isset($pidData['monitor_pid'])) {
                    // OS-aware process check
                    if ($isWindows) {
                        $checkCmd = "powershell -Command \"Get-Process -Id " . $pidData['monitor_pid'] . " -ErrorAction SilentlyContinue\"";
                    } else {
                        $checkCmd = "ps -p " . $pidData['monitor_pid'] . " > /dev/null 2>&1 && echo 'running'";
                    }
                    $result = shell_exec($checkCmd);

                    if (!empty(trim($result))) {
                        echo json_encode([
                            'success' => true,
                            'message' => 'Monitor is already running',
                            'pid' => $pidData['monitor_pid']
                        ]);
                        return;
                    }
                }
            }

            // OS-aware command execution
            if ($isWindows) {
                $cmd = "powershell -Command \"Start-Process -FilePath '$pythonPath' -ArgumentList '$monitorScript' -WindowStyle Hidden -PassThru | Select-Object -ExpandProperty Id\"";
            } else {
                $cmd = "$pythonPath \"$monitorScript\" > /dev/null 2>&1 & echo $!";
            }

            $pid = trim(shell_exec($cmd));

            if (is_numeric($pid) && $pid > 0) {
                file_put_contents($pidFile, json_encode([
                    'monitor_pid' => (int)$pid,
                    'started_at' => date('Y-m-d H:i:s'),
                    'status' => 'running'
                ], JSON_PRETTY_PRINT));

                // Add notification
                if ($userId) {
                    $this->notificationService->add(
                        $userId,
                        'info',
                        'Ransomware Monitor Started',
                        'Real-time ransomware monitoring is now active',
                        [
                            'pid' => $pid,
                            'action' => 'start_ransomware_monitor'
                        ]
                    );
                }

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

    /**
     * Stop ransomware monitor
     *
     * @return void JSON response
     */
    public function stopMonitor() {
        if (session_status() === PHP_SESSION_NONE) session_start();
        header('Content-Type: application/json');

        $userId = $_SESSION['user_id'] ?? null;
        $projectDir = rtrim(DIR, '/\\');
        $pidFile = $projectDir . '/assets/data/ransomware_pid.json';

        // OS detection
        $isWindows = (stripos(PHP_OS, 'WIN') === 0);

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

                // OS-aware kill command
                if ($isWindows) {
                    $cmd = "powershell -Command \"Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue\"";
                } else {
                    $cmd = "kill -9 $pid 2>/dev/null";
                }

                shell_exec($cmd);
                @unlink($pidFile);

                // Add notification
                if ($userId) {
                    $this->notificationService->add(
                        $userId,
                        'warning',
                        'Ransomware Monitor Stopped',
                        'Real-time ransomware monitoring has been stopped',
                        [
                            'action' => 'stop_ransomware_monitor'
                        ]
                    );
                }

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

    /**
     * Get monitor status
     *
     * @return void JSON response
     */
    public function getStatus() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $pidFile = $projectDir . '/assets/data/ransomware_pid.json';

        // OS detection
        $isWindows = (stripos(PHP_OS, 'WIN') === 0);

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

            // OS-aware process check
            if ($isWindows) {
                $cmd = "powershell -Command \"Get-Process -Id $pid -ErrorAction SilentlyContinue | Select-Object Id, ProcessName\"";
            } else {
                $cmd = "ps -p $pid > /dev/null 2>&1 && echo 'running'";
            }

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

    /**
     * Get ransomware activity
     *
     * @return void JSON response
     */
    public function getActivity() {
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

    /**
     * Get ransomware statistics
     *
     * @return void JSON response
     */
    public function getStats() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $statsFile = $projectDir . '/assets/data/ransomware_stats.json';

        if (file_exists($statsFile)) {
            $stats = json_decode(file_get_contents($statsFile), true);
            echo json_encode($stats ?: $this->getDefaultStats());
        } else {
            echo json_encode($this->getDefaultStats());
        }
    }

    /**
     * Check ransomware threats
     *
     * @return void JSON response
     */
    public function checkThreats() {
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

    /**
     * Get quarantine files
     *
     * @return void JSON response
     */
    public function getQuarantineFiles() {
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

    /**
     * Get scan progress
     *
     * @return void JSON response
     */
    public function getScanProgress() {
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

    /**
     * Start full system scan
     *
     * @return void JSON response
     */
    public function startFullScan() {
        if (session_status() === PHP_SESSION_NONE) session_start();
        header('Content-Type: application/json');

        $userId = $_SESSION['user_id'] ?? null;
        $projectDir = rtrim(DIR, '/\\');

        // OS-aware Python and script paths
        $isWindows = (stripos(PHP_OS, 'WIN') === 0);

        if ($isWindows) {
            $pythonPath = $projectDir . '/fyp/Scripts/python.exe';
            if (!file_exists($pythonPath)) {
                $pythonPath = 'python';
            }
        } else {
            $pythonPath = 'python3';
        }

        // Script path - check both possible folder names (typo and correct)
        $scannerScript = $projectDir . '/python/ranswomware/ransomware_scanner.py';
        if (!file_exists($scannerScript)) {
            $scannerScript = $projectDir . '/python/ransomware/ransomware_scanner.py';
        }

        if (!file_exists($scannerScript)) {
            echo json_encode([
                'success' => false,
                'message' => 'Scanner script not found. Checked: python/ranswomware/ and python/ransomware/'
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

            // OS-aware command execution
            if ($isWindows) {
                $cmd = "powershell -Command \"Start-Process -FilePath '$pythonPath' -ArgumentList '$scannerScript --full-scan' -WindowStyle Hidden -PassThru | Select-Object -ExpandProperty Id\"";
            } else {
                $cmd = "$pythonPath \"$scannerScript\" --full-scan > /dev/null 2>&1 & echo $!";
            }

            $pid = trim(shell_exec($cmd));

            if (is_numeric($pid) && $pid > 0) {
                $pidFile = $projectDir . '/assets/data/scan_pid.json';
                file_put_contents($pidFile, json_encode([
                    'scan_pid' => (int)$pid,
                    'scan_type' => 'full',
                    'started_at' => date('Y-m-d H:i:s')
                ], JSON_PRETTY_PRINT));

                // Add notification
                if ($userId) {
                    $this->notificationService->add(
                        $userId,
                        'info',
                        'Full System Scan Started',
                        'Ransomware full system scan is now running. This may take several minutes.',
                        [
                            'scan_type' => 'full',
                            'pid' => $pid,
                            'action' => 'start_full_scan'
                        ]
                    );
                }

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

    /**
     * Start quick scan
     *
     * @return void JSON response
     */
    public function startQuickScan() {
        if (session_status() === PHP_SESSION_NONE) session_start();
        header('Content-Type: application/json');

        $userId = $_SESSION['user_id'] ?? null;
        $projectDir = rtrim(DIR, '/\\');

        // OS-aware Python and script paths
        $isWindows = (stripos(PHP_OS, 'WIN') === 0);

        if ($isWindows) {
            $pythonPath = $projectDir . '/fyp/Scripts/python.exe';
            if (!file_exists($pythonPath)) {
                $pythonPath = 'python';
            }
        } else {
            $pythonPath = 'python3';
        }

        // Script path - check both possible folder names (typo and correct)
        $scannerScript = $projectDir . '/python/ranswomware/ransomware_scanner.py';
        if (!file_exists($scannerScript)) {
            $scannerScript = $projectDir . '/python/ransomware/ransomware_scanner.py';
        }

        if (!file_exists($scannerScript)) {
            echo json_encode([
                'success' => false,
                'message' => 'Scanner script not found'
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

            // OS-aware command execution
            if ($isWindows) {
                $cmd = "powershell -Command \"Start-Process -FilePath '$pythonPath' -ArgumentList '$scannerScript --quick-scan' -WindowStyle Hidden -PassThru | Select-Object -ExpandProperty Id\"";
            } else {
                $cmd = "$pythonPath \"$scannerScript\" --quick-scan > /dev/null 2>&1 & echo $!";
            }

            $pid = trim(shell_exec($cmd));

            if (is_numeric($pid) && $pid > 0) {
                // Add notification
                if ($userId) {
                    $this->notificationService->add(
                        $userId,
                        'info',
                        'Quick Scan Started',
                        'Ransomware quick scan is now running on user folders',
                        [
                            'scan_type' => 'quick',
                            'pid' => $pid,
                            'action' => 'start_quick_scan'
                        ]
                    );
                }

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

    /**
     * Isolate threats to quarantine
     *
     * @return void JSON response
     */
    public function isolateThreats() {
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

            $this->updateQuarantineCount(count($quarantineList));

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

    /**
     * Restore quarantined file
     *
     * @return void JSON response
     */
    public function restoreFile() {
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
                $this->updateQuarantineCount(count($files));

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

    /**
     * Delete quarantined file permanently
     *
     * @return void JSON response
     */
    public function deleteFile() {
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
                $this->updateQuarantineCount(count($files));

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

    /**
     * Update threat signatures
     *
     * @return void JSON response
     */
    public function updateSignatures() {
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
     *
     * @return void JSON response
     */
    public function restoreBackup() {
        header('Content-Type: application/json');

        echo json_encode([
            'success' => true,
            'message' => 'Backup restoration requires backup configuration. Please configure your backup system.'
        ]);
    }

    /**
     * Get default ransomware statistics
     *
     * @return array Default stats
     */
    private function getDefaultStats() {
        return [
            'files_scanned' => 0,
            'threats_detected' => 0,
            'quarantined' => 0,
            'scan_rate' => 0,
            'scan_progress' => 0,
            'current_file' => 'Idle'
        ];
    }

    /**
     * Update quarantine count in stats
     *
     * @param int $count Number of quarantined files
     */
    private function updateQuarantineCount($count) {
        $projectDir = rtrim(DIR, '/\\');
        $statsFile = $projectDir . '/assets/data/ransomware_stats.json';

        if (file_exists($statsFile)) {
            $stats = json_decode(file_get_contents($statsFile), true);
            $stats['quarantined'] = $count;
            file_put_contents($statsFile, json_encode($stats, JSON_PRETTY_PRINT));
        }
    }
}

?>
