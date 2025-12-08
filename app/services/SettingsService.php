<?php

/**
 * SettingsService Class
 *
 * Purpose: Handles system settings and user configuration
 * Replaces: handle_save_settings(), handle_save_api_keys(), handle_get_user_stats()
 */
class SettingsService {

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
     * Save system settings
     *
     * @return void JSON response
     */
    public function saveSettings() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        header('Content-Type: application/json');

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            echo json_encode(['success' => false, 'message' => 'Invalid request method']);
            exit;
        }

        $userId = $_SESSION['user_id'];

        // Decode JSON settings
        $settingsJson = $_POST['settings'] ?? '';
        $settings = json_decode($settingsJson, true);

        if (empty($settings) || !is_array($settings)) {
            echo json_encode(['success' => false, 'message' => 'No settings provided or invalid format']);
            exit;
        }

        // Create system_settings table if it doesn't exist
        $createTableSql = "CREATE TABLE IF NOT EXISTS system_settings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            setting_key VARCHAR(255) NOT NULL,
            setting_value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_user_setting (user_id, setting_key)
        )";

        // Execute table creation
        global $oConnection;
        if (!$oConnection->dbc->query($createTableSql)) {
            error_log("Failed to create system_settings table: " . $oConnection->dbc->error);
        }

        // Update or insert each setting in database
        foreach ($settings as $key => $value) {
            // Convert boolean to string for storage
            $dbValue = is_bool($value) ? ($value ? '1' : '0') : $value;

            $checkSql = "SELECT id FROM system_settings WHERE user_id = ? AND setting_key = ?";
            $existing = $this->db->query($checkSql, 'is', [$userId, $key]);

            if ($existing && count($existing) > 0) {
                $updateSql = "UPDATE system_settings SET setting_value = ? WHERE user_id = ? AND setting_key = ?";
                $this->db->query($updateSql, 'sis', [$dbValue, $userId, $key]);
            } else {
                $insertSql = "INSERT INTO system_settings (user_id, setting_key, setting_value) VALUES (?, ?, ?)";
                $this->db->query($insertSql, 'iss', [$userId, $key, $dbValue]);
            }
        }

        // Write to config file for Python scripts
        $configPath = DIR . 'assets/config/settings.json';

        // Prepare config data for Python scripts
        $configData = [
            'alert_threshold' => floatval($settings['alert_threshold'] ?? 85) / 100,
            'session_timeout' => intval($settings['session_timeout'] ?? 30),
            'enable_email_alerts' => (bool)($settings['enable_email_alerts'] ?? false),
            'enable_desktop_alerts' => (bool)($settings['enable_desktop_alerts'] ?? true),
            'log_retention_days' => intval($settings['log_retention_days'] ?? 30),
            'auto_quarantine' => (bool)($settings['auto_quarantine'] ?? true),
            'scan_on_upload' => (bool)($settings['scan_on_upload'] ?? true),
            'alert_sound' => (bool)($settings['alert_sound'] ?? false),
            'daily_summary' => (bool)($settings['daily_summary'] ?? false),
            'theme' => $settings['theme'] ?? 'light',
            'last_updated' => date('c')
        ];

        // Write config file
        $configJson = json_encode($configData, JSON_PRETTY_PRINT);
        if (file_put_contents($configPath, $configJson) === false) {
            error_log("Failed to write settings config file: $configPath");
        }

        // Add notification
        $this->notificationService->add(
            $userId,
            'success',
            'Settings Saved',
            'Your system settings have been updated successfully.',
            []
        );

        echo json_encode(['success' => true, 'message' => 'Settings saved successfully']);
        exit;
    }

    /**
     * Save API keys
     *
     * @return void JSON response
     */
    public function saveApiKeys() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        header('Content-Type: application/json');

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            echo json_encode(['success' => false, 'message' => 'Invalid request method']);
            exit;
        }

        $userId = $_SESSION['user_id'];
        $virusTotalKey = $_POST['virustotal_api_key'] ?? '';
        $hybridAnalysisKey = $_POST['hybrid_analysis_key'] ?? '';
        $abuseIPDBKey = $_POST['abuseipdb_api_key'] ?? '';
        $alienVaultKey = $_POST['alienvault_api_key'] ?? '';
        $ipQualityKey = $_POST['ipqualityscore_api_key'] ?? '';

        // Save all API keys
        $this->saveSetting($userId, 'virustotal_api_key', $virusTotalKey);
        $this->saveSetting($userId, 'hybrid_analysis_key', $hybridAnalysisKey);
        $this->saveSetting($userId, 'abuseipdb_api_key', $abuseIPDBKey);
        $this->saveSetting($userId, 'alienvault_api_key', $alienVaultKey);
        $this->saveSetting($userId, 'ipqualityscore_api_key', $ipQualityKey);

        // Add notification
        $this->notificationService->add(
            $userId,
            'success',
            'API Keys Saved',
            'Your API keys have been updated successfully.',
            []
        );

        echo json_encode(['success' => true, 'message' => 'API keys saved successfully']);
        exit;
    }

    /**
     * Get user statistics
     *
     * @return void JSON response
     */
    public function getUserStats() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        header('Content-Type: application/json');

        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['success' => false, 'message' => 'Unauthorized']);
            return;
        }

        $userId = $_SESSION['user_id'];
        $stats = $this->getUserStatisticsData($userId);

        echo json_encode($stats);
    }

    /**
     * Save or update a single setting
     *
     * @param int $userId User ID
     * @param string $key Setting key
     * @param string $value Setting value
     */
    private function saveSetting($userId, $key, $value) {
        if (empty($value)) return;

        $checkSql = "SELECT id FROM system_settings WHERE user_id = ? AND setting_key = ?";
        $existing = $this->db->query($checkSql, 'is', [$userId, $key]);

        if ($existing && count($existing) > 0) {
            $updateSql = "UPDATE system_settings SET setting_value = ? WHERE user_id = ? AND setting_key = ?";
            $this->db->query($updateSql, 'sis', [$value, $userId, $key]);
        } else {
            $insertSql = "INSERT INTO system_settings (user_id, setting_key, setting_value) VALUES (?, ?, ?)";
            $this->db->query($insertSql, 'iss', [$userId, $key, $value]);
        }
    }

    /**
     * Get user statistics data
     *
     * @param int $userId User ID
     * @return array Statistics data
     */
    private function getUserStatisticsData($userId) {
        // Calculate days active
        $userSql = "SELECT DATEDIFF(NOW(), created_at) as days_active FROM users WHERE id = ?";
        $userData = $this->db->query($userSql, 'i', [$userId]);
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
            'days_active' => max(1, $daysActive)
        ];
    }
}

?>
