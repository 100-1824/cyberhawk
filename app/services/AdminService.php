<?php

/**
 * AdminService Class
 * 
 * Purpose: Handle all admin-related business logic including user management,
 * system statistics, and endpoint monitoring
 */
class AdminService {

    private $db;

    /**
     * Constructor
     */
    public function __construct() {
        $this->db = new DatabaseHelper();
    }

    /**
     * Get all users from the database
     * 
     * @param int $limit Maximum number of users to return
     * @param int $offset Offset for pagination
     * @return array Array of user data
     */
    public function getAllUsers($limit = 100, $offset = 0) {
        $sql = "SELECT id, name, email, role, is_verified, created_at, phone, bio, profile_picture 
                FROM users 
                ORDER BY id DESC 
                LIMIT ? OFFSET ?";
        
        $result = $this->db->query($sql, 'ii', [$limit, $offset]);
        
        return $result ?: [];
    }

    /**
     * Get total count of users
     * 
     * @return int Total number of users
     */
    public function getTotalUsersCount() {
        $sql = "SELECT COUNT(*) as total FROM users";
        $result = $this->db->query($sql, '', []);
        
        return $result ? (int)$result[0]['total'] : 0;
    }

    /**
     * Get user by ID
     * 
     * @param int $userId The user ID
     * @return array|null User data or null if not found
     */
    public function getUserById($userId) {
        $sql = "SELECT id, name, email, role, is_verified, created_at, phone, bio, profile_picture 
                FROM users WHERE id = ?";
        
        $result = $this->db->query($sql, 'i', [$userId]);
        
        return $result && count($result) > 0 ? $result[0] : null;
    }

    /**
     * Update user information
     * 
     * @param int $userId The user ID
     * @param array $data User data to update
     * @return bool Success status
     */
    public function updateUser($userId, $data) {
        $allowedFields = ['name', 'email', 'role', 'phone', 'bio', 'is_verified'];
        $updates = [];
        $params = [];
        $types = '';

        foreach ($data as $key => $value) {
            if (in_array($key, $allowedFields)) {
                $updates[] = "$key = ?";
                $params[] = $value;
                $types .= 's';
            }
        }

        if (empty($updates)) {
            return false;
        }

        $params[] = $userId;
        $types .= 'i';

        $sql = "UPDATE users SET " . implode(', ', $updates) . ", last_updated = NOW() WHERE id = ?";
        
        return $this->db->query($sql, $types, $params) !== false;
    }

    /**
     * Delete a user
     * 
     * @param int $userId The user ID to delete
     * @return bool Success status
     */
    public function deleteUser($userId) {
        // Don't allow deleting own account through admin panel
        if (isset($_SESSION['user_id']) && $_SESSION['user_id'] == $userId) {
            return false;
        }

        // Delete user sessions first
        $this->db->query("DELETE FROM user_sessions WHERE email = (SELECT email FROM users WHERE id = ?)", 'i', [$userId]);
        
        // Delete user settings
        $this->db->query("DELETE FROM system_settings WHERE user_id = ?", 'i', [$userId]);
        
        // Delete the user
        return $this->db->query("DELETE FROM users WHERE id = ?", 'i', [$userId]) !== false;
    }

    /**
     * Get system statistics
     * 
     * @return array System statistics
     */
    public function getSystemStats() {
        $stats = [
            'total_users' => 0,
            'verified_users' => 0,
            'admin_users' => 0,
            'users_today' => 0,
            'total_sessions' => 0,
            'total_notifications' => 0
        ];

        // Total users
        $result = $this->db->query("SELECT COUNT(*) as count FROM users", '', []);
        $stats['total_users'] = $result ? (int)$result[0]['count'] : 0;

        // Verified users
        $result = $this->db->query("SELECT COUNT(*) as count FROM users WHERE is_verified = 1", '', []);
        $stats['verified_users'] = $result ? (int)$result[0]['count'] : 0;

        // Admin users
        $result = $this->db->query("SELECT COUNT(*) as count FROM users WHERE role = 'admin'", '', []);
        $stats['admin_users'] = $result ? (int)$result[0]['count'] : 0;

        // Users registered today
        $result = $this->db->query("SELECT COUNT(*) as count FROM users WHERE DATE(created_at) = CURDATE()", '', []);
        $stats['users_today'] = $result ? (int)$result[0]['count'] : 0;

        // Active sessions
        $result = $this->db->query("SELECT COUNT(*) as count FROM user_sessions", '', []);
        $stats['total_sessions'] = $result ? (int)$result[0]['count'] : 0;

        // Total notifications
        $result = $this->db->query("SELECT COUNT(*) as count FROM notifications", '', []);
        $stats['total_notifications'] = $result ? (int)$result[0]['count'] : 0;

        return $stats;
    }

    /**
     * Get all system endpoints/routes
     * 
     * @return array List of endpoints with their details
     */
    public function getEndpoints() {
        // Define all system endpoints with metadata
        $endpoints = [
            // Public Routes
            ['method' => 'GET', 'path' => '/', 'name' => 'Home Page', 'auth' => false, 'category' => 'Public'],
            ['method' => 'GET', 'path' => '/home', 'name' => 'Landing Page', 'auth' => false, 'category' => 'Public'],
            ['method' => 'GET', 'path' => '/login', 'name' => 'Login Page', 'auth' => false, 'category' => 'Public'],
            ['method' => 'POST', 'path' => '/auth/login', 'name' => 'Login Handler', 'auth' => false, 'category' => 'Public'],
            ['method' => 'GET', 'path' => '/register', 'name' => 'Register Page', 'auth' => false, 'category' => 'Public'],
            ['method' => 'POST', 'path' => '/register', 'name' => 'Register Handler', 'auth' => false, 'category' => 'Public'],
            ['method' => 'GET', 'path' => '/logout', 'name' => 'Logout', 'auth' => true, 'category' => 'Public'],
            ['method' => 'GET', 'path' => '/verify', 'name' => 'Email Verification Page', 'auth' => false, 'category' => 'Public'],
            ['method' => 'POST', 'path' => '/verify-email', 'name' => 'Email Verification Handler', 'auth' => false, 'category' => 'Public'],

            // Dashboard Routes
            ['method' => 'GET', 'path' => '/dashboard', 'name' => 'Main Dashboard', 'auth' => true, 'category' => 'Dashboard'],
            ['method' => 'POST', 'path' => '/start-logs', 'name' => 'Start Traffic Logs', 'auth' => false, 'category' => 'Dashboard'],
            ['method' => 'POST', 'path' => '/stop-logs', 'name' => 'Stop Traffic Logs', 'auth' => false, 'category' => 'Dashboard'],
            ['method' => 'GET', 'path' => '/clearlogs', 'name' => 'Clear Traffic Logs', 'auth' => false, 'category' => 'Dashboard'],
            ['method' => 'POST', 'path' => '/start-model', 'name' => 'Start ML Model', 'auth' => false, 'category' => 'Dashboard'],
            ['method' => 'GET', 'path' => '/get-intrusion-chart-data', 'name' => 'Get Intrusion Chart Data', 'auth' => false, 'category' => 'Dashboard'],
            ['method' => 'GET', 'path' => '/get-validated-alerts', 'name' => 'Get Validated Alerts', 'auth' => true, 'category' => 'Dashboard'],

            // Admin Routes
            ['method' => 'GET', 'path' => '/admin/dashboard', 'name' => 'Admin Dashboard', 'auth' => true, 'category' => 'Admin'],
            ['method' => 'GET', 'path' => '/admin/users', 'name' => 'Get All Users', 'auth' => true, 'category' => 'Admin'],
            ['method' => 'GET', 'path' => '/admin/get-user', 'name' => 'Get Single User', 'auth' => true, 'category' => 'Admin'],
            ['method' => 'POST', 'path' => '/admin/update-user', 'name' => 'Update User', 'auth' => true, 'category' => 'Admin'],
            ['method' => 'POST', 'path' => '/admin/delete-user', 'name' => 'Delete User', 'auth' => true, 'category' => 'Admin'],
            ['method' => 'GET', 'path' => '/admin/stats', 'name' => 'System Statistics', 'auth' => true, 'category' => 'Admin'],
            ['method' => 'GET', 'path' => '/admin/endpoints', 'name' => 'System Endpoints', 'auth' => true, 'category' => 'Admin'],
            ['method' => 'POST', 'path' => '/admin/reset-password', 'name' => 'Reset User Password', 'auth' => true, 'category' => 'Admin'],

            // Ransomware Routes
            ['method' => 'GET', 'path' => '/ransomware', 'name' => 'Ransomware Dashboard', 'auth' => true, 'category' => 'Ransomware'],
            ['method' => 'GET', 'path' => '/get-ransomware-activity', 'name' => 'Get Ransomware Activity', 'auth' => true, 'category' => 'Ransomware'],
            ['method' => 'GET', 'path' => '/get-ransomware-stats', 'name' => 'Get Ransomware Stats', 'auth' => true, 'category' => 'Ransomware'],
            ['method' => 'GET', 'path' => '/check-ransomware-threats', 'name' => 'Check Ransomware Threats', 'auth' => true, 'category' => 'Ransomware'],
            ['method' => 'GET', 'path' => '/get-quarantine-files', 'name' => 'Get Quarantine Files', 'auth' => true, 'category' => 'Ransomware'],
            ['method' => 'GET', 'path' => '/get-scan-progress', 'name' => 'Get Scan Progress', 'auth' => true, 'category' => 'Ransomware'],
            ['method' => 'GET', 'path' => '/get-monitor-status', 'name' => 'Get Monitor Status', 'auth' => true, 'category' => 'Ransomware'],
            ['method' => 'POST', 'path' => '/start-full-scan', 'name' => 'Start Full Scan', 'auth' => true, 'category' => 'Ransomware'],
            ['method' => 'POST', 'path' => '/start-quick-scan', 'name' => 'Start Quick Scan', 'auth' => true, 'category' => 'Ransomware'],
            ['method' => 'POST', 'path' => '/start-ransomware-monitor', 'name' => 'Start Ransomware Monitor', 'auth' => true, 'category' => 'Ransomware'],
            ['method' => 'POST', 'path' => '/stop-ransomware-monitor', 'name' => 'Stop Ransomware Monitor', 'auth' => true, 'category' => 'Ransomware'],
            ['method' => 'POST', 'path' => '/isolate-threats', 'name' => 'Isolate Threats', 'auth' => true, 'category' => 'Ransomware'],
            ['method' => 'POST', 'path' => '/restore-quarantine-file', 'name' => 'Restore Quarantine File', 'auth' => true, 'category' => 'Ransomware'],
            ['method' => 'POST', 'path' => '/delete-quarantine-file', 'name' => 'Delete Quarantine File', 'auth' => true, 'category' => 'Ransomware'],
            ['method' => 'POST', 'path' => '/update-signatures', 'name' => 'Update Signatures', 'auth' => true, 'category' => 'Ransomware'],
            ['method' => 'POST', 'path' => '/restore-backup', 'name' => 'Restore Backup', 'auth' => true, 'category' => 'Ransomware'],

            // Malware Routes
            ['method' => 'GET', 'path' => '/malware', 'name' => 'Malware Dashboard', 'auth' => true, 'category' => 'Malware'],
            ['method' => 'GET', 'path' => '/get-malware-stats', 'name' => 'Get Malware Stats', 'auth' => true, 'category' => 'Malware'],
            ['method' => 'GET', 'path' => '/get-all-malware-reports', 'name' => 'Get All Malware Reports', 'auth' => true, 'category' => 'Malware'],
            ['method' => 'GET', 'path' => '/get-malware-report', 'name' => 'Get Malware Report', 'auth' => true, 'category' => 'Malware'],
            ['method' => 'GET', 'path' => '/get-scan-queue', 'name' => 'Get Scan Queue', 'auth' => true, 'category' => 'Malware'],
            ['method' => 'GET', 'path' => '/get-malware-scan-progress', 'name' => 'Get Malware Scan Progress', 'auth' => true, 'category' => 'Malware'],
            ['method' => 'POST', 'path' => '/upload-malware-sample', 'name' => 'Upload Malware Sample', 'auth' => true, 'category' => 'Malware'],
            ['method' => 'POST', 'path' => '/start-malware-scan', 'name' => 'Start Malware Scan', 'auth' => true, 'category' => 'Malware'],
            ['method' => 'POST', 'path' => '/delete-malware-sample', 'name' => 'Delete Malware Sample', 'auth' => true, 'category' => 'Malware'],
            ['method' => 'POST', 'path' => '/export-malware-report', 'name' => 'Export Malware Report', 'auth' => true, 'category' => 'Malware'],

            // Reporting Routes
            ['method' => 'GET', 'path' => '/reporting', 'name' => 'Reporting Dashboard', 'auth' => true, 'category' => 'Reporting'],
            ['method' => 'GET', 'path' => '/get-reporting-data', 'name' => 'Get Reporting Data', 'auth' => true, 'category' => 'Reporting'],
            ['method' => 'GET', 'path' => '/generate-executive-summary', 'name' => 'Generate Executive Summary', 'auth' => true, 'category' => 'Reporting'],
            ['method' => 'GET', 'path' => '/get-network-statistics', 'name' => 'Get Network Statistics', 'auth' => true, 'category' => 'Reporting'],
            ['method' => 'GET', 'path' => '/get-threat-timeline', 'name' => 'Get Threat Timeline', 'auth' => true, 'category' => 'Reporting'],
            ['method' => 'POST', 'path' => '/export-report-pdf', 'name' => 'Export PDF Report', 'auth' => true, 'category' => 'Reporting'],
            ['method' => 'POST', 'path' => '/download-report', 'name' => 'Download Report', 'auth' => true, 'category' => 'Reporting'],
            ['method' => 'POST', 'path' => '/email-report', 'name' => 'Email Report', 'auth' => true, 'category' => 'Reporting'],

            // Profile Routes
            ['method' => 'GET', 'path' => '/profile', 'name' => 'User Profile', 'auth' => true, 'category' => 'Profile'],
            ['method' => 'POST', 'path' => '/update-profile', 'name' => 'Update Profile', 'auth' => true, 'category' => 'Profile'],
            ['method' => 'POST', 'path' => '/upload-profile-picture', 'name' => 'Upload Profile Picture', 'auth' => true, 'category' => 'Profile'],
            ['method' => 'POST', 'path' => '/delete-profile-picture', 'name' => 'Delete Profile Picture', 'auth' => true, 'category' => 'Profile'],
            ['method' => 'POST', 'path' => '/change-password', 'name' => 'Change Password', 'auth' => true, 'category' => 'Profile'],

            // Settings Routes
            ['method' => 'GET', 'path' => '/settings', 'name' => 'Settings Page', 'auth' => true, 'category' => 'Settings'],
            ['method' => 'POST', 'path' => '/update-password', 'name' => 'Update Password', 'auth' => true, 'category' => 'Settings'],
            ['method' => 'POST', 'path' => '/save-settings', 'name' => 'Save Settings', 'auth' => true, 'category' => 'Settings'],
            ['method' => 'POST', 'path' => '/save-api-keys', 'name' => 'Save API Keys', 'auth' => true, 'category' => 'Settings'],
            ['method' => 'POST', 'path' => '/clear-all-logs', 'name' => 'Clear All Logs', 'auth' => true, 'category' => 'Settings'],
            ['method' => 'POST', 'path' => '/export-user-data', 'name' => 'Export User Data', 'auth' => true, 'category' => 'Settings'],
            ['method' => 'POST', 'path' => '/terminate-sessions', 'name' => 'Terminate Sessions', 'auth' => true, 'category' => 'Settings'],
            ['method' => 'POST', 'path' => '/delete-account', 'name' => 'Delete Account', 'auth' => true, 'category' => 'Settings'],
            ['method' => 'GET', 'path' => '/get-user-stats', 'name' => 'Get User Stats', 'auth' => true, 'category' => 'Settings'],

            // Notification Routes
            ['method' => 'GET', 'path' => '/get-notifications', 'name' => 'Get Notifications', 'auth' => true, 'category' => 'Notifications'],
            ['method' => 'POST', 'path' => '/mark-notification-read', 'name' => 'Mark Notification Read', 'auth' => true, 'category' => 'Notifications'],
            ['method' => 'POST', 'path' => '/mark-all-notifications-read', 'name' => 'Mark All Notifications Read', 'auth' => true, 'category' => 'Notifications'],
            ['method' => 'POST', 'path' => '/delete-notification', 'name' => 'Delete Notification', 'auth' => true, 'category' => 'Notifications'],
            ['method' => 'POST', 'path' => '/clear-all-notifications', 'name' => 'Clear All Notifications', 'auth' => true, 'category' => 'Notifications'],

            // Threat Intelligence Routes
            ['method' => 'GET', 'path' => '/threat-intelligence', 'name' => 'Threat Intelligence Dashboard', 'auth' => true, 'category' => 'Threat Intel'],
            ['method' => 'GET', 'path' => '/get-threat-feeds', 'name' => 'Get Threat Feeds', 'auth' => true, 'category' => 'Threat Intel'],
            ['method' => 'GET', 'path' => '/get-threat-actors', 'name' => 'Get Threat Actors', 'auth' => true, 'category' => 'Threat Intel'],
            ['method' => 'GET', 'path' => '/get-iocs', 'name' => 'Get IOCs', 'auth' => true, 'category' => 'Threat Intel'],
            ['method' => 'GET', 'path' => '/get-vulnerabilities', 'name' => 'Get Vulnerabilities', 'auth' => true, 'category' => 'Threat Intel'],
            ['method' => 'POST', 'path' => '/block-ioc', 'name' => 'Block IOC', 'auth' => true, 'category' => 'Threat Intel'],
            ['method' => 'POST', 'path' => '/whitelist-ioc', 'name' => 'Whitelist IOC', 'auth' => true, 'category' => 'Threat Intel'],

            // Network Analytics Routes
            ['method' => 'GET', 'path' => '/network-analytics', 'name' => 'Network Analytics Dashboard', 'auth' => true, 'category' => 'Network'],
            ['method' => 'GET', 'path' => '/get-network-metrics', 'name' => 'Get Network Metrics', 'auth' => true, 'category' => 'Network'],
            ['method' => 'GET', 'path' => '/get-bandwidth-data', 'name' => 'Get Bandwidth Data', 'auth' => true, 'category' => 'Network'],
            ['method' => 'GET', 'path' => '/get-protocol-stats', 'name' => 'Get Protocol Stats', 'auth' => true, 'category' => 'Network'],
            ['method' => 'GET', 'path' => '/get-top-talkers', 'name' => 'Get Top Talkers', 'auth' => true, 'category' => 'Network'],
            ['method' => 'GET', 'path' => '/get-active-connections', 'name' => 'Get Active Connections', 'auth' => true, 'category' => 'Network'],
            ['method' => 'GET', 'path' => '/get-packet-activity', 'name' => 'Get Packet Activity', 'auth' => true, 'category' => 'Network'],
        ];

        // Add status check (all endpoints are active)
        foreach ($endpoints as &$endpoint) {
            $endpoint['status'] = 'active';
            $endpoint['full_path'] = MDIR . ltrim($endpoint['path'], '/');
        }

        return $endpoints;
    }

    /**
     * Get recent activity logs
     * 
     * @param int $limit Number of logs to return
     * @return array Activity logs
     */
    public function getRecentActivity($limit = 20) {
        $activities = [];

        // Get recent notifications as activity
        $sql = "SELECT n.id, n.message, n.type, n.created_at, u.name as user_name 
                FROM notifications n 
                LEFT JOIN users u ON n.user_id = u.id 
                ORDER BY n.created_at DESC 
                LIMIT ?";
        
        $result = $this->db->query($sql, 'i', [$limit]);
        
        if ($result) {
            foreach ($result as $row) {
                $activities[] = [
                    'type' => $row['type'] ?? 'info',
                    'message' => $row['message'],
                    'user' => $row['user_name'] ?? 'System',
                    'time' => $row['created_at']
                ];
            }
        }

        return $activities;
    }

    /**
     * Reset user password (admin function)
     * 
     * @param int $userId User ID
     * @param string $newPassword New password
     * @return bool Success status
     */
    public function resetUserPassword($userId, $newPassword) {
        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
        
        $sql = "UPDATE users SET password = ?, last_updated = NOW() WHERE id = ?";
        
        return $this->db->query($sql, 'si', [$hashedPassword, $userId]) !== false;
    }

    /**
     * Toggle user verification status
     * 
     * @param int $userId User ID
     * @return bool Success status
     */
    public function toggleUserVerification($userId) {
        $sql = "UPDATE users SET is_verified = NOT is_verified, last_updated = NOW() WHERE id = ?";
        
        return $this->db->query($sql, 'i', [$userId]) !== false;
    }
}

?>
