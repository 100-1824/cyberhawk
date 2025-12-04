<?php

/**
 * AuthService Class
 *
 * Purpose: Handles user authentication, registration, and verification
 * Replaces: handle_login(), handle_Register(), handle_verification(), logout_user(), handle_update_password()
 */
class AuthService {

    private $db;
    private $emailService;
    private $logManager;

    /**
     * Constructor
     */
    public function __construct() {
        $this->db = new DatabaseHelper();
        $this->emailService = new EmailService();
        $this->logManager = new LogManager();
    }

    /**
     * Handle user login
     *
     * @return void Redirects or renders view
     */
    public function login() {
        // Start session if not already started
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $error = '';

        // Validation
        if (!$email || !$password) {
            $error = "Email and password are required.";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = "Invalid email format.";
        } else {
            // Check user exists
            $sql = "SELECT id, name, email, password, role, is_verified FROM users WHERE email = ?";
            $result = $this->db->query($sql, 's', [$email]);

            if ($result === false) {
                $error = "Database error. Please try again.";
            } elseif (count($result) === 0) {
                $error = "No user found with this email.";
            } else {
                $user = $result[0];

                // Check if verified
                if ($user['is_verified'] == 0) {
                    $error = "Your account is not verified. Check your email.";
                    require 'app/views/pages/login.php';
                    return;
                }

                // Verify password
                if (password_verify($password, $user['password'])) {
                    // Successful login
                    $this->createSession($user, $email);

                    // Clear all logs
                    $this->clearAllLogs();

                    header("Location: " . MDIR . "dashboard");
                    exit;
                } else {
                    $error = "Invalid email or password.";
                }
            }
        }

        // If login failed, show login page with error
        require 'app/views/pages/login.php';
    }

    /**
     * Create user session
     *
     * @param array $user User data
     * @param string $email User email
     */
    private function createSession($user, $email) {
        // Regenerate session ID for security
        session_regenerate_id(true);

        // Set session variables
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_name'] = $user['name'];
        $_SESSION['user_role'] = $user['role'];

        // Set session cookie
        $sessionId = session_id();

        // Check if we're on HTTPS or HTTP
        $isSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
                    || $_SERVER['SERVER_PORT'] == 443;

        setcookie('session_id', $sessionId, [
            'expires' => time() + (86400 * 30), // 30 days
            'path' => '/',
            'secure' => $isSecure,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);

        // Store session in database
        // First, delete any existing sessions for this user
        $this->db->query("DELETE FROM user_sessions WHERE email = ?", 's', [$email]);

        // Insert new session
        $this->db->query(
            "INSERT INTO user_sessions (email, session, created_at) VALUES (?, ?, NOW())",
            'ss',
            [$email, $sessionId]
        );
    }

    /**
     * Handle user registration
     *
     * @return void Redirects or renders view
     */
    public function register() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo "Method Not Allowed";
            exit;
        }

        $name = trim($_POST['name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $role = 'user';

        // Validation
        if (!$name || !$email || !$password) {
            return get_register_view("All fields are required.");
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return get_register_view("Invalid email format.");
        }

        if (strlen($password) < 6) {
            return get_register_view("Password must be at least 6 characters.");
        }

        // Check if email already exists
        $rows = $this->db->query("SELECT id FROM users WHERE email = ?", 's', [$email]);

        if ($rows && count($rows) > 0) {
            return get_register_view("Email already registered.");
        }

        // Generate verification code
        $verification_code = random_int(100000, 999999);
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        // Insert user with is_verified = 0
        $inserted = $this->db->query(
            "INSERT INTO users (name, email, password, role, verification_code, is_verified)
             VALUES (?, ?, ?, ?, ?, 0)",
            'sssss',
            [$name, $email, $hashedPassword, $role, $verification_code]
        );

        if (!$inserted) {
            return get_register_view("Failed to register. Try again.");
        }

        // Send verification email
        if (!$this->emailService->sendVerificationEmail($email, $name, $verification_code)) {
            return get_register_view("Could not send verification email. Contact admin.");
        }

        // Store email in session for verification page
        $_SESSION['pending_email'] = $email;

        header("Location: " . MDIR . "verify");
        exit;
    }

    /**
     * Handle email verification
     *
     * @return void Redirects or renders view
     */
    public function verify() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        if (!isset($_SESSION['pending_email'])) {
            echo "Unauthorized!";
            exit;
        }

        $email = $_SESSION['pending_email'];
        $code = trim($_POST['code'] ?? '');

        if (!$code) {
            return get_verify_page("Enter the code.");
        }

        $row = $this->db->query(
            "SELECT id, verification_code FROM users WHERE email = ?",
            's',
            [$email]
        );

        if (!$row || count($row) === 0) {
            return get_verify_page("Account not found.");
        }

        $user = $row[0];

        if ($user['verification_code'] != $code) {
            return get_verify_page("Invalid verification code.");
        }

        // Update user as verified
        $this->db->query(
            "UPDATE users SET is_verified = 1, verification_code = NULL WHERE email = ?",
            's',
            [$email]
        );

        unset($_SESSION['pending_email']);
        $_SESSION['success'] = "Your email is verified! You can now login.";

        header("Location: " . MDIR . "login");
        exit;
    }

    /**
     * Handle user logout
     *
     * @return void Redirects to login
     */
    public function logout() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $userId = $_SESSION['user_id'] ?? null;

        // Stop traffic sniffer if running
        $this->stopTrafficSniffer();

        // Clear logs
        $this->logManager->clearAllLogs();

        // Delete session from database
        if ($userId) {
            $sql = "SELECT email FROM users WHERE id = ?";
            $result = $this->db->query($sql, 'i', [$userId]);

            if ($result && count($result) > 0) {
                $email = $result[0]['email'];
                $this->db->query("DELETE FROM user_sessions WHERE email = ?", 's', [$email]);
            }
        }

        // Destroy PHP session
        session_destroy();
        setcookie('session_id', '', time() - 3600, '/', '', false, true);

        header("Location: " . MDIR . "login");
        exit;
    }

    /**
     * Update user password
     *
     * @return void JSON response
     */
    public function updatePassword() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        header('Content-Type: application/json');

        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['error' => 1, 'message' => 'Unauthorized']);
            exit;
        }

        $userId = $_SESSION['user_id'];
        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        // Validation
        if (!$currentPassword || !$newPassword || !$confirmPassword) {
            echo json_encode(['error' => 1, 'message' => 'All fields are required']);
            exit;
        }

        if ($newPassword !== $confirmPassword) {
            echo json_encode(['error' => 1, 'message' => 'New passwords do not match']);
            exit;
        }

        if (strlen($newPassword) < 6) {
            echo json_encode(['error' => 1, 'message' => 'Password must be at least 6 characters']);
            exit;
        }

        // Get current password from database
        $result = $this->db->query("SELECT password FROM users WHERE id = ?", 'i', [$userId]);

        if (!$result || count($result) === 0) {
            echo json_encode(['error' => 1, 'message' => 'User not found']);
            exit;
        }

        $user = $result[0];

        // Verify current password
        if (!password_verify($currentPassword, $user['password'])) {
            echo json_encode(['error' => 1, 'message' => 'Current password is incorrect']);
            exit;
        }

        // Hash new password and update
        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
        $updated = $this->db->query(
            "UPDATE users SET password = ?, last_updated = NOW() WHERE id = ?",
            'si',
            [$hashedPassword, $userId]
        );

        if ($updated) {
            echo json_encode(['error' => 0, 'message' => 'Password updated successfully']);
        } else {
            echo json_encode(['error' => 1, 'message' => 'Failed to update password']);
        }
        exit;
    }

    /**
     * Clear all log files
     */
    private function clearAllLogs() {
        $dataDir = DIR . 'assets/data/';

        $logFiles = [
            'alert.json',
            'pid_sniffer.json',
            'qurantine.json',
            'ransomware_activity.json',
            'ransomware_threats.json',
            'ransomware_stats.json',
            'scan_pid.json',
            'scan_progress.json',
            'scan_results.json',
            'traffic_log.json',
            'malware_reports.json',
            'malware_stats.json',
            'scan_queue.json',
            'malware_scan_progress.json'
        ];

        foreach ($logFiles as $file) {
            $filePath = $dataDir . $file;
            if (file_exists($filePath)) {
                file_put_contents($filePath, json_encode([], JSON_PRETTY_PRINT));
            }
        }
    }

    /**
     * Stop traffic sniffer process
     */
    private function stopTrafficSniffer() {
        $pidFile = DIR . 'assets/data/pid_sniffer.json';

        if (!file_exists($pidFile)) {
            return;
        }

        $pidData = json_decode(file_get_contents($pidFile), true);

        if (isset($pidData['sniffer_pid']) && isset($pidData['predict_pid'])) {
            $snifferPid = $pidData['sniffer_pid'];
            $predictPid = $pidData['predict_pid'];

            try {
                if (stripos(PHP_OS, 'WIN') === 0) {
                    // Windows
                    exec("powershell -Command \"Stop-Process -Id $snifferPid -Force\"");
                    exec("powershell -Command \"Stop-Process -Id $predictPid -Force\"");
                } else {
                    // Linux/Unix
                    exec("kill -9 $snifferPid");
                    exec("kill -9 $predictPid");
                }

                unlink($pidFile);
            } catch (Exception $e) {
                error_log("Failed to stop traffic sniffer: " . $e->getMessage());
            }
        }
    }
}

?>
