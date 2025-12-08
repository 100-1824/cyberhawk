<?php

/**
 * ViewController Class
 *
 * Purpose: Handles simple view rendering and traffic operations
 * Replaces: Various view functions from views.php
 */
class ViewController {

    private $logManager;
    private $notificationService;

    /**
     * Constructor
     */
    public function __construct() {
        $this->logManager = new LogManager();
        $this->notificationService = new NotificationService();
    }

    /**
     * Show login page
     *
     * @param array $vars Route variables
     * @return void
     */
    public function showLogin($vars = []) {
        require 'app/views/pages/login.php';
    }

    /**
     * Show register page
     *
     * @param array $vars Route variables
     * @return void
     */
    public function showRegister($vars = []) {
        require 'app/views/pages/register.php';
    }

    /**
     * Show verify page
     *
     * @param array $vars Route variables
     * @return void
     */
    public function showVerify($vars = []) {
        if (!isset($_SESSION['pending_email'])) {
            header("Location: " . MDIR . "login");
            exit;
        }
        require 'app/views/pages/verify.php';
    }

    /**
     * Show 500 error page
     *
     * @param array $vars Route variables
     * @return void
     */
    public function show500Error($vars = []) {
        require 'app/views/pages/500.php';
    }

    /**
     * Start traffic logs handler
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function startLogsHandler($vars = []) {
        header('Content-Type: application/json');

        $pythonDir = DIR . 'python';
        $snifferScript = $pythonDir . '/traffic_capture/traffic_sniffer.py';
        $predictScript = $pythonDir . '/detection/realtime_predict.py';

        // Determine OS
        $isWindows = (stripos(PHP_OS, 'WIN') === 0);

        if ($isWindows) {
            // Windows - Use fyp venv Python for correct dependencies
            $pythonExe = DIR . 'fyp/Scripts/python.exe';
            
            // Fallback to system Python if venv not found
            if (!file_exists($pythonExe)) {
                $pythonExe = 'python';
            }
            
            // Log the Python path being used
            $logFile = DIR . 'assets/data/start_logs_debug.txt';
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Using Python: $pythonExe\n", FILE_APPEND);
            
            // Start traffic sniffer with venv Python
            $snifferCmd = "powershell -Command \"Start-Process -FilePath '$pythonExe' -ArgumentList '\\\"$snifferScript\\\"' -WindowStyle Hidden -PassThru | Select-Object -ExpandProperty Id\"";
            $snifferPid = shell_exec($snifferCmd);
            
            // Start prediction model with venv Python
            $predictCmd = "powershell -Command \"Start-Process -FilePath '$pythonExe' -ArgumentList '\\\"$predictScript\\\"' -WindowStyle Hidden -PassThru | Select-Object -ExpandProperty Id\"";
            $predictPid = shell_exec($predictCmd);

            $snifferPid = trim($snifferPid);
            $predictPid = trim($predictPid);

            // Log for debugging
            $logFile = DIR . 'assets/data/start_logs_debug.txt';
            $debugInfo = date('Y-m-d H:i:s') . " - Sniffer PID: '$snifferPid', Predict PID: '$predictPid'\n";
            file_put_contents($logFile, $debugInfo, FILE_APPEND);

            // Check if PIDs are valid
            if (empty($snifferPid) || !is_numeric($snifferPid)) {
                echo json_encode([
                    'success' => false,
                    'message' => 'Failed to start traffic sniffer',
                    'debug' => "Sniffer PID is empty or invalid: '$snifferPid'"
                ]);
                exit;
            }

            if (empty($predictPid) || !is_numeric($predictPid)) {
                echo json_encode([
                    'success' => false,
                    'message' => 'Failed to start prediction model',
                    'debug' => "Predict PID is empty or invalid: '$predictPid'"
                ]);
                exit;
            }

            // Save PIDs
            $pidData = [
                'sniffer_pid' => (int)$snifferPid,
                'predict_pid' => (int)$predictPid
            ];

            file_put_contents(DIR . 'assets/data/pid_sniffer.json', json_encode($pidData));

            // Add notification
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            $userId = $_SESSION['user_id'] ?? null;
            if ($userId) {
                $this->notificationService->add(
                    $userId,
                    'success',
                    'Traffic Monitoring Started',
                    'Network packet capture and ML prediction model are now active.',
                    ['sniffer_pid' => $snifferPid, 'predict_pid' => $predictPid]
                );
            }

            echo json_encode([
                'success' => true,
                'message' => 'Traffic monitoring started',
                'pid' => $snifferPid,  // For frontend compatibility
                'sniffer_pid' => $snifferPid,
                'predict_pid' => $predictPid
            ]);
        } else {
            // Linux/Unix
            $snifferCommand = "python3 \"$snifferScript\" > /dev/null 2>&1 & echo $!";
            $predictCommand = "python3 \"$predictScript\" > /dev/null 2>&1 & echo $!";

            $snifferPid = shell_exec($snifferCommand);
            $predictPid = shell_exec($predictCommand);

            $snifferPid = trim($snifferPid);
            $predictPid = trim($predictPid);

            // Save PIDs
            $pidData = [
                'sniffer_pid' => (int)$snifferPid,
                'predict_pid' => (int)$predictPid
            ];

            file_put_contents(DIR . 'assets/data/pid_sniffer.json', json_encode($pidData));

            echo json_encode([
                'success' => true,
                'message' => 'Traffic monitoring started',
                'pid' => $snifferPid,  // For frontend compatibility
                'sniffer_pid' => $snifferPid,
                'predict_pid' => $predictPid
            ]);
        }
        exit;
    }

    /**
     * Stop traffic logs handler
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function stopLogsHandler($vars = []) {
        header('Content-Type: application/json');

        $pidFile = DIR . 'assets/data/pid_sniffer.json';

        if (!file_exists($pidFile)) {
            echo json_encode([
                'success' => false,
                'message' => 'No running process found'
            ]);
            exit;
        }

        $pidData = json_decode(file_get_contents($pidFile), true);

        if (!isset($pidData['sniffer_pid']) || !isset($pidData['predict_pid'])) {
            echo json_encode([
                'success' => false,
                'message' => 'Invalid PID data'
            ]);
            exit;
        }

        $snifferPid = $pidData['sniffer_pid'];
        $predictPid = $pidData['predict_pid'];

        // Determine OS
        $isWindows = (stripos(PHP_OS, 'WIN') === 0);

        try {
            if ($isWindows) {
                // Windows
                exec("powershell -Command \"Stop-Process -Id $snifferPid -Force\"");
                exec("powershell -Command \"Stop-Process -Id $predictPid -Force\"");
            } else {
                // Linux/Unix
                exec("kill -9 $snifferPid");
                exec("kill -9 $predictPid");
            }

            unlink($pidFile);

            // Add notification
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            $userId = $_SESSION['user_id'] ?? null;
            if ($userId) {
                $this->notificationService->add(
                    $userId,
                    'info',
                    'Traffic Monitoring Stopped',
                    'Network packet capture and ML prediction model have been stopped.',
                    ['sniffer_pid' => $snifferPid, 'predict_pid' => $predictPid]
                );
            }

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
        exit;
    }

    /**
     * Clear traffic logs
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function clearTrafficLogs($vars = []) {
        $this->logManager->clearTrafficLogs();

        header('Content-Type: application/json');
        echo json_encode(['success' => true]);
        exit;
    }

    /**
     * Get traffic logs as JSON
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getTrafficLogsJson($vars = []) {
        header('Content-Type: application/json');
        $logs = $this->logManager->getTrafficLogsJson();
        echo json_encode($logs);
        exit;
    }

    /**
     * Clear all logs
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function clearAllLogs($vars = []) {
        $accountService = new AccountService();
        return $accountService->clearAllLogs();
    }

    /**
     * Get user profile data
     *
     * @param int $userId User ID
     * @return array|null User profile data
     */
    public function getUserProfile($userId) {
        $db = new DatabaseHelper();
        $sql = "SELECT id, name, email, role, profile_picture, phone, bio, created_at, last_updated
                FROM users WHERE id = ?";
        $result = $db->query($sql, 'i', [$userId]);

        if ($result && count($result) > 0) {
            return $result[0];
        }
        return null;
    }
}

?>
