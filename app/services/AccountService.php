<?php

/**
 * AccountService Class
 *
 * Purpose: Handles account management and data operations
 * Replaces: handle_clear_all_logs(), handle_export_user_data(), handle_terminate_sessions(), handle_delete_account()
 */
class AccountService {

    private $db;
    private $logManager;
    private $notificationService;

    /**
     * Constructor
     */
    public function __construct() {
        $this->db = new DatabaseHelper();
        $this->logManager = new LogManager();
        $this->notificationService = new NotificationService();
    }

    /**
     * Clear all log files
     *
     * @return void JSON response
     */
    public function clearAllLogs() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

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

        // Add notification
        $userId = $_SESSION['user_id'];
        $this->notificationService->add(
            $userId,
            'info',
            'Logs Cleared',
            'All system logs have been cleared.',
            []
        );

        echo json_encode(['success' => true, 'message' => 'All logs cleared successfully']);
    }

    /**
     * Export user data
     *
     * @return void JSON response
     */
    public function exportUserData() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        header('Content-Type: application/json');

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            echo json_encode(['success' => false, 'message' => 'Invalid request method']);
            exit;
        }

        $userId = $_SESSION['user_id'];

        // User data
        $userSql = "SELECT id, name, email, role FROM users WHERE id = ?";
        $userData = $this->db->query($userSql, 'i', [$userId]);

        // User settings
        $settingsSql = "SELECT setting_key, setting_value FROM system_settings WHERE user_id = ?";
        $settingsData = $this->db->query($settingsSql, 'i', [$userId]);

        $exportData = [
            'user' => $userData[0] ?? null,
            'settings' => $settingsData ?? [],
            'export_date' => date('Y-m-d H:i:s')
        ];

        // Create directory
        $exportDir = DIR . 'assets/exports/';
        if (!file_exists($exportDir)) {
            mkdir($exportDir, 0755, true);
        }

        $filename = 'user_data_' . $userId . '_' . date('YmdHis') . '.json';
        $filepath = $exportDir . $filename;

        file_put_contents($filepath, json_encode($exportData, JSON_PRETTY_PRINT));

        echo json_encode([
            'success' => true,
            'message' => 'User data exported successfully',
            'download_url' => MDIR . 'assets/exports/' . $filename
        ]);
        exit;
    }

    /**
     * Terminate all sessions except current
     *
     * @return void JSON response
     */
    public function terminateSessions() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        header('Content-Type: application/json');

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            echo json_encode(['success' => false, 'message' => 'Invalid request method']);
            exit;
        }

        $userId = $_SESSION['user_id'];
        $currentSessionId = session_id();

        $deleteSql = "DELETE FROM user_sessions WHERE user_id = ? AND session_id != ?";
        $this->db->query($deleteSql, 'is', [$userId, $currentSessionId]);

        // Add notification
        $this->notificationService->add(
            $userId,
            'warning',
            'Sessions Terminated',
            'All other browser sessions have been signed out.',
            []
        );

        echo json_encode(['success' => true, 'message' => 'All other sessions terminated']);
        exit;
    }

    /**
     * Delete user account permanently
     *
     * @return void JSON response
     */
    public function deleteAccount() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        header('Content-Type: application/json');

        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['success' => false, 'message' => 'Unauthorized']);
            return;
        }

        $userId = $_SESSION['user_id'];

        try {
            // Delete user settings
            $this->db->query("DELETE FROM system_settings WHERE user_id = ?", 'i', [$userId]);

            // Delete user sessions
            $userSql = "SELECT email FROM users WHERE id = ?";
            $userData = $this->db->query($userSql, 'i', [$userId]);

            if (!empty($userData)) {
                $this->db->query("DELETE FROM user_sessions WHERE email = ?", 's', [$userData[0]['email']]);
            }

            // Delete user account
            $this->db->query("DELETE FROM users WHERE id = ?", 'i', [$userId]);

            // Clear logs
            $this->logManager->clearAllLogs();

            // Destroy session
            session_destroy();

            echo json_encode(['success' => true, 'message' => 'Account deleted successfully']);

        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Failed to delete account']);
        }
    }
}

?>
