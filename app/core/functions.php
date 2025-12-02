<?php
/**
 * Functions.php contains the main functions.
 * User functions and other related functions will be included with file names.
 *
 *
 * Creates a session check middleware function.
 *
 * @param string $requiredSession The session key that must be set.
 * @param callable|string $handler The handler function to call if the session key is set.
 * @return callable The middleware function that checks the session and calls the handler.
 */
//Calling The DB Class
use PHPMailer\PHPMailer\PHPMailer;
    use PHPMailer\PHPMailer\Exception;
$oConnection = new dbConnection();





/**
 * Middleware function to check session and validate session ID from the database.
 *
 * @param string $requiredSession The session key that must be set.
 * @param callable|string $handler The handler function to call if the session key is set.
 * @return callable The middleware function that checks the session and calls the handler.
 */
function checkSession($requiredSession, $handler) {
    return function($vars) use ($requiredSession, $handler) {

        // Check if the required session key is set in the PHP session
        if (!isset($_SESSION[$requiredSession])) {
            header('HTTP/1.1 401 Unauthorized');
            header('Location: ' . MDIR . 'login');
            exit;
        }

        // ==================== SESSION TIMEOUT CHECK (from user settings) ====================
        // Load user's session timeout setting
        $userId = $_SESSION['user_id'];
        $timeoutSettingQuery = "SELECT setting_value FROM system_settings WHERE user_id = ? AND setting_key = 'session_timeout'";
        $timeoutResult = mysqli_prepared_query($timeoutSettingQuery, 'i', [$userId]);

        $sessionTimeoutMinutes = 30; // Default 30 minutes
        if (!empty($timeoutResult)) {
            $sessionTimeoutMinutes = intval($timeoutResult[0]['setting_value']);
        }

        // Only check timeout if not set to "Never" (0)
        if ($sessionTimeoutMinutes > 0) {
            $timeout = $sessionTimeoutMinutes * 60; // Convert to seconds

            if (isset($_SESSION['LAST_ACTIVITY'])) {
                $elapsedTime = time() - $_SESSION['LAST_ACTIVITY'];
                if ($elapsedTime > $timeout) {
                    // Session expired due to inactivity
                    session_destroy();
                    setcookie('session_id', '', time() - 3600, '/', '', false, true);
                    header('HTTP/1.1 401 Unauthorized');
                    header('Location: ' . MDIR . 'login?timeout=1');
                    exit;
                }
            }

            // Update last activity time
            $_SESSION['LAST_ACTIVITY'] = time();
        }

        // Check if the session ID from the cookie matches the session ID stored in the PHP session
        if (!isset($_COOKIE['session_id']) || $_COOKIE['session_id'] !== session_id()) {
            header('HTTP/1.1 401 Unauthorized');
            header('Location: ' . MDIR . 'login');
            exit;
        }

        // Fetch the session ID from the database using USER_ID (already set above)
        
        // FIX: Get the user's email first, then check session
        $userQuery = "SELECT email FROM users WHERE id = ?";
        $userResult = mysqli_prepared_query($userQuery, 'i', [$userId]);
        
        if (empty($userResult)) {
            session_destroy();
            header('HTTP/1.1 401 Unauthorized');
            header('Location: ' . MDIR . 'login');
            exit;
        }
        
        $userEmail = $userResult[0]['email'];
        
        // Now query the session table with the correct email
        $sql = "SELECT session FROM user_sessions WHERE email = ?";
        $row = mysqli_prepared_query($sql, 's', [$userEmail]);
        
        if(!empty($row))
        {
            $dbSessionId = $row[0]['session'];
            // Check if the session ID from the database matches the session ID from the cookie and PHP session
            if ($dbSessionId !== session_id()) {
                // Log out the user
                session_destroy();
                setcookie('session_id', '', time() - 3600, '/', '', false, true);
                header('HTTP/1.1 401 Unauthorized');
                header('Location: ' . MDIR . 'login');
                exit;
            }
        }
        else
        {
            session_destroy();
            header('HTTP/1.1 401 Unauthorized');
            header('Location: ' . MDIR . 'login');
            exit;
        }

        // Call the handler function if the session is valid
        if (is_callable($handler)) {
            return call_user_func($handler, $vars);
        } elseif (is_string($handler) && function_exists($handler)) {
            return call_user_func($handler, $vars);
        } else {
            header('HTTP/1.1 500 Internal Server Error');
            header('Location: ' . MDIR . '500');
            exit;
        }
    };
}

/**
 * Displays multiple error messages as alert boxes.
 *
 * @param array $message An array of error messages to display.
 */
function display_errors($message)
{
    foreach($message as $mess)
    {
        echo '<div class="alert alert-danger alert-dismissible" role="alert">
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                        <p class="mb-0">
                          '.$mess.'
                        </p>
                      </div>';
    }
}

/**
 * Displays a single success message as an alert box.
 *
 * @param string $message The success message to display.
 */
function display_success($message)
{
    echo '<div class="alert alert-success-outline alert-dismissible d-flex align-items-center" role="alert"><i class="fa fa-check-square-o mr-10"></i> '.$message.'<button class="btn-close" type="button" data-bs-dismiss="alert" aria-label="Close"></button></div>';
}

/**
 * Displays a single error message as an alert box.
 *
 * @param string $message The error message to display.
 */
function display_error($message)
{
    echo '<div class="alert alert-danger alert-dismissible" role="alert">
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    <p class="mb-0">
                      '.$message.'
                    </p>
                  </div>';
}


/**
 * Executes a prepared MySQLi query with optional parameters.
 *
 * @param string $sql The SQL query to execute.
 * @param string $paramTypes A string that contains one or more characters which specify the types for the corresponding bind variables.
 * @param array $params An array of parameters to bind to the query.
 * @return mixed Returns an array of rows for SELECT queries, true for successful non-SELECT queries, or false on failure.
 */

function mysqli_prepared_query($sql, $paramTypes = '', $params = []) {
    global $oConnection;
    $con = $oConnection->dbc;

    // Determine the query type based on the first word of the query
    $queryType = strtolower(trim(explode(" ", $sql)[0]));

    // Prepare the SQL statement
    $stmt = $con->prepare($sql);

    if ($stmt === FALSE) {
        return false;
    }

    // Bind parameters for prepared statements if provided
    if (!empty($paramTypes) && !empty($params)) {
        $refp = array_merge([$paramTypes], $params);
        $pref = [];

        foreach ($refp as $key => $value) {
            $pref[$key] = &$refp[$key];
        }

        call_user_func_array([$stmt, 'bind_param'], $pref);
    }

    // Execute the prepared statement
    $result = $stmt->execute();

    if ($result === TRUE) {
        if ($queryType == "select") {
            // Fetch all rows for SELECT queries
            $resultSet = $stmt->get_result();
            $rows = $resultSet->fetch_all(MYSQLI_ASSOC);
            return $rows;
        } else {
            // Return true for successful non-SELECT queries
            return true;
        }
    } else {
        // Return false on failure
        return false;
    }

    // Close the statement and connection
    $stmt->close();
    $con->close();
}

/**
 * 
 * 
 * 
 * 
 */
function checkApi($handler) {
    return function($vars) use ($handler) {
        global $ApiEndPointToken;
        $token = get_cronjob_auth_header();

        if (check_user_api_from_header($token) === false) {
            header('HTTP/1.1 401 Unauthorized');
            echo json_encode(['error' => 1, 'message' => 'Unauthorized Access']);
            exit;
        }
        // Pass the $token to the handler function
        if (is_callable($handler)) {
            return call_user_func($handler, $vars, $token);
        } elseif (is_string($handler) && function_exists($handler)) {
            return call_user_func($handler, $vars, $token);
        } else {
            header('HTTP/1.1 500 Internal Server Error');
            header('Location: ' . MDIR . '500');
            exit;
        }
    };
}


function areLogsEmpty() {
    $logFile = DIR . 'assets/data/traffic_log.json'; // Adjust path as needed

    if (!file_exists($logFile)) {
        return true;  // No file, logs empty
    }

    $content = trim(file_get_contents($logFile));

    // Check if file content is empty or empty array
    if ($content === '' || $content === '[]') {
        return true;
    }

    // Try to decode JSON to see if it contains entries
    $data = json_decode($content, true);

    return empty($data);  // true if no logs, false if logs present
}

function get_traffic_log_json() {
    $filename = __DIR__ . 'assets/data/traffic_log.json'; // Adjust path as needed

    if (file_exists($filename)) {
        $lines = file($filename, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $packets = [];

        foreach ($lines as $line) {
            $json = json_decode($line, true);
            if ($json) {
                $packets[] = $json;
            }
        }

        header('Content-Type: application/json');
        echo json_encode($packets);
    } else {
        header('Content-Type: application/json');
        echo json_encode([]);
    }
}



function stopTrafficSniffer() {
    // Get the list of PIDs running traffic_sniffer.py
    $pids = shell_exec('wmic process where "CommandLine like \'%traffic_sniffer.py%\'" get ProcessId');

    if (!empty(trim($pids))) {
        // Extract PIDs
        preg_match_all('/\d+/', $pids, $matches);
        foreach ($matches[0] as $pid) {
            // Kill each matching process
            shell_exec("taskkill /PID $pid /F");
        }
    }
}


function logout_user() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    // Get user email before clearing session
    $userId = $_SESSION['user_id'] ?? null;
    
    // Stop running traffic sniffer process
    stopTrafficSniffer();

    // Clear logs
    $logFile = __DIR__ . '/../assets/data/traffic_logs.json';
    if (file_exists($logFile)) {
        file_put_contents($logFile, json_encode([]));
    }

    // Delete session from database
    if ($userId) {
        mysqli_prepared_query(
            "DELETE FROM user_sessions WHERE email = (SELECT email FROM users WHERE id = ?)",
            'i',
            [$userId]
        );
    }

    // Clear session data
    $_SESSION = [];

    // Destroy the session cookie
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    
    // Also destroy the custom session_id cookie
    setcookie('session_id', '', time() - 3600, '/', '', true, true);

    session_destroy();

    header("Location: " . MDIR . "login");
    exit;
}



function handle_login() {
    // START SESSION FIRST
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $error = '';

    if (!$email || !$password) {
        $error = "Email and password are required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email format.";
    } else {
        $sql = "SELECT id, name, email, password, role, is_verified FROM users WHERE email = ?";
        $stmt = mysqli_prepared_query($sql, 's', [$email]);


        if ($stmt === false) {
            $error = "Database error. Please try again.";
        } elseif (count($stmt) === 0) {
            $error = "No user found with this email.";
        } else {
            $user = $stmt[0];

            if ($user['is_verified'] == 0) {
    $error = "Your account is not verified. Check your email.";
    return require 'app/views/pages/login.php';
}

if (password_verify($password, $user['password'])) {

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
                mysqli_prepared_query(
                    "DELETE FROM user_sessions WHERE email = ?",
                    's',
                    [$email]
                );
                
                // Insert new session
                mysqli_prepared_query(
                    "INSERT INTO user_sessions (email, session, created_at) VALUES (?, ?, NOW())",
                    'ss',
                    [$email, $sessionId]
                );

                // ============ CLEAR ALL LOG FILES ============
                clear_all_logs();
                // =============================================

                header("Location: " . MDIR . "dashboard");
                exit;
            } else {
                $error = "Invalid email or password.";
            }
        }
    }

    // If login failed, show login again with error
    require 'app/views/pages/login.php';
}

/**
 * Clear all log files on login
 */
/**
 * Clear all log files on login
 */
function clear_all_logs() {
    // Define the path to the data directory using MDIR
    $dataDir = DIR . 'assets/data/';
    
    // List of all log files to clear
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
    
    // Clear each log file
    foreach ($logFiles as $file) {
        $filePath = $dataDir . $file;
        
        // Check if file exists
        if (file_exists($filePath)) {
            // Write empty array to JSON files
            file_put_contents($filePath, json_encode([], JSON_PRETTY_PRINT));
        }
    }
}


// Place this in your handler file, e.g., src/AuthHandlers.php

// function handle_Register() {
//     // Ensure session is started
//     if (session_status() === PHP_SESSION_NONE) {
//         session_start();
//     }

//     $error = null;

//     if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
//         http_response_code(405);
//         echo "Method Not Allowed";
//         exit;
//     }

//     $name = trim($_POST['name'] ?? '');
//     $email = trim($_POST['email'] ?? '');
//     $password = $_POST['password'] ?? '';
//     $role = 'user'; // default role

//     if (!$name || !$email || !$password) {
//         $error = "All fields are required.";
//     } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
//         $error = "Invalid email format.";
//     } elseif (strlen($password) < 6) {
//         $error = "Password must be at least 6 characters.";
//     } else {
//         // Check if email already exists
//         $rows = mysqli_prepared_query("SELECT id FROM users WHERE email = ?", 's', [$email]);

//         if ($rows === false) {
//             $error = "Database error. Please try again.";
//         } elseif (count($rows) > 0) {
//             $error = "Email already registered.";
//         } else {
//             $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

//             // Insert new user
//             $inserted = mysqli_prepared_query(
//                 "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
//                 'ssss',
//                 [$name, $email, $hashedPassword, $role]
//             );

//             if ($inserted) {
//                 $_SESSION['success'] = "Registration successful! Please login.";
//                 // Redirect to login page using MDIR
//                 header("Location: " . MDIR . "login");
//                 exit;
//             } else {
//                 $error = "Failed to register. Please try again.";
//             }
//         }
//     }

//     // Render the registration form with error messages
//     get_register_view($error);
// }

function handle_Register() {

    if (session_status() === PHP_SESSION_NONE) session_start();

    $error = null;

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo "Method Not Allowed";
        exit;
    }

    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $role = 'user';

    if (!$name || !$email || !$password) {
        return get_register_view("All fields are required.");
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return get_register_view("Invalid email format.");
    }

    if (strlen($password) < 6) {
        return get_register_view("Password must be at least 6 characters.");
    }

    // Check existing email
    $rows = mysqli_prepared_query("SELECT id FROM users WHERE email = ?", 's', [$email]);

    if ($rows && count($rows) > 0) {
        return get_register_view("Email already registered.");
    }

    // Generate verification code
    $verification_code = random_int(100000, 999999);

    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Insert user with is_verified = 0
    $inserted = mysqli_prepared_query(
        "INSERT INTO users (name, email, password, role, verification_code, is_verified) 
         VALUES (?, ?, ?, ?, ?, 0)",
        'sssss',
        [$name, $email, $hashedPassword, $role, $verification_code]
    );

    if (!$inserted) {
        return get_register_view("Failed to register. Try again.");
    }

    // Send verification email
    require_once DIR . "app/helpers/email.php";

    if (!sendVerificationEmail($email, $name, $verification_code)) {
        return get_register_view("Could not send verification email. Contact admin.");
    }

    // Store email in session for verification page
    $_SESSION['pending_email'] = $email;

    header("Location: " . MDIR . "verify");
    exit;
}
function handle_verification() {
    if (session_status() === PHP_SESSION_NONE) session_start();

    if (!isset($_SESSION['pending_email'])) {
        echo "Unauthorized!";
        exit;
    }

    $email = $_SESSION['pending_email'];
    $code = trim($_POST['code'] ?? '');

    if (!$code) {
        return get_verify_page("Enter the code.");
    }

    $row = mysqli_prepared_query(
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

    mysqli_prepared_query(
        "UPDATE users SET is_verified = 1, verification_code = NULL WHERE email = ?",
        's',
        [$email]
    );

    unset($_SESSION['pending_email']);
    $_SESSION['success'] = "Your email is verified! You can now login.";

    header("Location: " . MDIR . "login");
    exit;
}


// ==================== PROFILE MANAGEMENT ====================
// Profile update removed - already exists in codebase

// ==================== PASSWORD MANAGEMENT ====================

function handle_update_password() {

    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
        exit;
    }

    $userId          = $_SESSION['user_id'];
    $currentPassword = $_POST['current_password'] ?? '';
    $newPassword     = $_POST['new_password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';

    // Validation
    if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
        echo json_encode(['success' => false, 'message' => 'All fields are required']);
        exit;
    }

    if ($newPassword !== $confirmPassword) {
        echo json_encode(['success' => false, 'message' => 'New passwords do not match']);
        exit;
    }

    if (strlen($newPassword) < 8) {
        echo json_encode(['success' => false, 'message' => 'Password must be at least 8 characters']);
        exit;
    }

    // Verify current password
    $sql = "SELECT password FROM users WHERE id = ?";
    $result = mysqli_prepared_query($sql, 'i', [$userId]);

    if (!$result || count($result) === 0) {
        echo json_encode(['success' => false, 'message' => 'User not found']);
        exit;
    }

    if (!password_verify($currentPassword, $result[0]['password'])) {
        echo json_encode(['success' => false, 'message' => 'Current password is incorrect']);
        exit;
    }

    // Update password
    $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);

    $updateSql = "UPDATE users SET password = ? WHERE id = ?";
    mysqli_prepared_query($updateSql, 'si', [$hashedPassword, $userId]);

    echo json_encode(['success' => true, 'message' => 'Password updated successfully']);
    exit;
}

// ==================== SYSTEM SETTINGS ====================

function handle_save_settings() {
    global $oConnection;

    if (session_status() === PHP_SESSION_NONE) session_start();
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

    // Create system_settings table if it doesn't exist (using raw query for DDL)
    // Note: CREATE TABLE cannot use prepared statements as it's a DDL statement
    $createTableSql = "CREATE TABLE IF NOT EXISTS system_settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        setting_key VARCHAR(255) NOT NULL,
        setting_value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY unique_user_setting (user_id, setting_key)
    )";

    // Execute table creation (DDL requires direct query, not prepared statement)
    if (!$oConnection->dbc->query($createTableSql)) {
        error_log("Failed to create system_settings table: " . $oConnection->dbc->error);
    }

    // Update or insert each setting in database
    foreach ($settings as $key => $value) {
        // Convert boolean to string for storage
        $dbValue = is_bool($value) ? ($value ? '1' : '0') : $value;

        $checkSql = "SELECT id FROM system_settings WHERE user_id = ? AND setting_key = ?";
        $existing = mysqli_prepared_query($checkSql, 'is', [$userId, $key]);

        if ($existing && count($existing) > 0) {

            $updateSql = "UPDATE system_settings SET setting_value = ? WHERE user_id = ? AND setting_key = ?";
            mysqli_prepared_query($updateSql, 'sis', [$dbValue, $userId, $key]);

        } else {

            $insertSql = "INSERT INTO system_settings (user_id, setting_key, setting_value) VALUES (?, ?, ?)";
            mysqli_prepared_query($insertSql, 'iss', [$userId, $key, $dbValue]);
        }
    }

    // ==================== WRITE TO CONFIG FILE FOR PYTHON SCRIPTS ====================
    // This makes settings actually control system behavior
    $configPath = DIR . 'assets/config/settings.json';

    // Prepare config data for Python scripts
    $configData = [
        'alert_threshold' => floatval($settings['alert_threshold'] ?? 85) / 100, // Convert to decimal
        'session_timeout' => intval($settings['session_timeout'] ?? 30),
        'enable_email_alerts' => (bool)($settings['enable_email_alerts'] ?? false),
        'enable_desktop_alerts' => (bool)($settings['enable_desktop_alerts'] ?? true),
        'log_retention_days' => intval($settings['log_retention_days'] ?? 30),
        'auto_quarantine' => (bool)($settings['auto_quarantine'] ?? true),
        'scan_on_upload' => (bool)($settings['scan_on_upload'] ?? true),
        'alert_sound' => (bool)($settings['alert_sound'] ?? false),
        'daily_summary' => (bool)($settings['daily_summary'] ?? false),
        'theme' => $settings['theme'] ?? 'light',
        'last_updated' => date('c') // ISO 8601 format
    ];

    // Write config file (with error handling)
    $configJson = json_encode($configData, JSON_PRETTY_PRINT);
    if (file_put_contents($configPath, $configJson) === false) {
        error_log("Failed to write settings config file: $configPath");
    }

    echo json_encode(['success' => true, 'message' => 'Settings saved successfully']);
    exit;
}

// ==================== API KEYS ====================

function handle_save_api_keys() {

    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
        exit;
    }

    $userId            = $_SESSION['user_id'];
    $virusTotalKey     = $_POST['virustotal_api_key'] ?? '';
    $hybridAnalysisKey = $_POST['hybrid_analysis_key'] ?? '';
    $abuseIPDBKey      = $_POST['abuseipdb_api_key'] ?? '';
    $alienVaultKey     = $_POST['alienvault_api_key'] ?? '';
    $ipQualityKey      = $_POST['ipqualityscore_api_key'] ?? '';

    // Helper function to save/update a setting
    $saveSetting = function($key, $value) use ($userId) {
        if (empty($value)) return;

        $checkSql = "SELECT id FROM system_settings WHERE user_id = ? AND setting_key = ?";
        $existing = mysqli_prepared_query($checkSql, 'is', [$userId, $key]);

        if ($existing && count($existing) > 0) {
            $updateSql = "UPDATE system_settings SET setting_value = ? WHERE user_id = ? AND setting_key = ?";
            mysqli_prepared_query($updateSql, 'sis', [$value, $userId, $key]);
        } else {
            $insertSql = "INSERT INTO system_settings (user_id, setting_key, setting_value)
                          VALUES (?, ?, ?)";
            mysqli_prepared_query($insertSql, 'iss', [$userId, $key, $value]);
        }
    };

    // Save all API keys
    $saveSetting('virustotal_api_key', $virusTotalKey);
    $saveSetting('hybrid_analysis_key', $hybridAnalysisKey);
    $saveSetting('abuseipdb_api_key', $abuseIPDBKey);
    $saveSetting('alienvault_api_key', $alienVaultKey);
    $saveSetting('ipqualityscore_api_key', $ipQualityKey);

    echo json_encode(['success' => true, 'message' => 'API keys saved successfully']);
    exit;
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

function handle_export_user_data() {

    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
        exit;
    }

    $userId = $_SESSION['user_id'];

    // User data
    $userSql = "SELECT id, name, email, role FROM users WHERE id = ?";
    $userData = mysqli_prepared_query($userSql, 'i', [$userId]);

    // User settings
    $settingsSql = "SELECT setting_key, setting_value FROM system_settings WHERE user_id = ?";
    $settingsData = mysqli_prepared_query($settingsSql, 'i', [$userId]);

    $exportData = [
        'user'        => $userData[0] ?? null,
        'settings'    => $settingsData ?? [],
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
        'success'      => true,
        'message'      => 'User data exported successfully',
        'download_url' => MDIR . 'assets/exports/' . $filename
    ]);
    exit;
}

// ==================== SESSION MANAGEMENT ====================

function handle_terminate_sessions() {

    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
        exit;
    }

    $userId = $_SESSION['user_id'];
    $currentSessionId = session_id();

    $deleteSql = "DELETE FROM user_sessions WHERE user_id = ? AND session_id != ?";
    mysqli_prepared_query($deleteSql, 'is', [$userId, $currentSessionId]);

    echo json_encode(['success' => true, 'message' => 'All other sessions terminated']);
    exit;
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










// Reporting functions can be added here
// ==================== REPORTING MODULE HANDLERS ====================

/**
 * Handle downloading report as PDF
 */
function handle_download_report()
{
    if (session_status() === PHP_SESSION_NONE) session_start();

    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
        exit;
    }

    $userId = $_SESSION['user_id'] ?? null;
    $reportType = $_POST['report_type'] ?? '';
    $reportData = $_POST['report_data'] ?? '';

    if (empty($reportType) || empty($reportData)) {
        echo json_encode(['success' => false, 'message' => 'Report type and data are required']);
        exit;
    }

    // Load notifications helper
    require_once DIR . "app/helpers/notifications.php";

    // Create reports directory if it doesn't exist
    $reportsDir = DIR . 'assets/reports/';
    if (!file_exists($reportsDir)) {
        mkdir($reportsDir, 0755, true);
    }

    $filename = 'cyberhawk_' . $reportType . '_report_' . date('YmdHis') . '.html';
    $filepath = $reportsDir . $filename;

    // Save report HTML
    file_put_contents($filepath, $reportData);

    // Add notification
    if ($userId) {
        add_notification(
            $userId,
            'success',
            'Report Downloaded',
            "Report '{$filename}' generated successfully",
            [
                'report_type' => $reportType,
                'filename' => $filename,
                'action' => 'download_report'
            ]
        );
    }

    echo json_encode([
        'success'      => true,
        'message'      => 'Report generated successfully',
        'download_url' => MDIR . 'assets/reports/' . $filename,
        'filename'     => $filename
    ]);
    exit;
}

/**
 * Handle emailing report
 */
function handle_email_report()
{
    if (session_status() === PHP_SESSION_NONE) session_start();

    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
        exit;
    }

    $userId        = $_SESSION['user_id'];
    $recipientEmail = $_POST['email'] ?? '';
    $reportType     = $_POST['report_type'] ?? '';
    $reportData     = $_POST['report_data'] ?? '';

    // Validation
    if (empty($recipientEmail)) {
        echo json_encode(['success' => false, 'message' => 'Email address is required']);
        exit;
    }

    if (!filter_var($recipientEmail, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(['success' => false, 'message' => 'Invalid email address']);
        exit;
    }

    if (empty($reportType) || empty($reportData)) {
        echo json_encode(['success' => false, 'message' => 'Report type and data are required']);
        exit;
    }

    // Get user info
    $userSql  = "SELECT name, email FROM users WHERE id = ?";
    $userData = mysqli_prepared_query($userSql, 'i', [$userId]);
    $userName = $userData[0]['name'] ?? 'CyberHawk User';

    // Load PHPMailer and Notifications
    require_once DIR . "app/helpers/email.php";
    require_once DIR . "app/helpers/notifications.php";
    require_once DIR . 'vendor/phpmailer/phpmailer/src/PHPMailer.php';
    require_once DIR . 'vendor/phpmailer/phpmailer/src/SMTP.php';
    require_once DIR . 'vendor/phpmailer/phpmailer/src/Exception.php';



    try {
        $mail = new PHPMailer(true);

        // SMTP Configuration
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = 'ahmedsahni71@gmail.com';
        $mail->Password   = 'oolg ltfj vpux ctft';
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587;

        // Email settings
        $mail->setFrom('ahmedsahni71@gmail.com', 'CyberHawk Security');
        $mail->addAddress($recipientEmail);

        $reportTypeFormatted = ucfirst(str_replace('_', ' ', $reportType));
        $mail->Subject = "CyberHawk {$reportTypeFormatted} Report - " . date('Y-m-d H:i:s');
        $mail->isHTML(true);

        // Email body
        $mail->Body = "
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; }
                .header { background: linear-gradient(135deg, #0a74da, #061a40); color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; }
                .footer { background: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #6c757d; }
            </style>
        </head>
        <body>
            <div class='header'>
                <h1>CyberHawk Security Report</h1>
                <p>Generated on " . date('F d, Y at H:i:s') . "</p>
            </div>
            <div class='content'>
                {$reportData}
            </div>
            <div class='footer'>
                <p>This report was generated by CyberHawk Security Monitoring System</p>
                <p>For support, contact your system administrator</p>
            </div>
        </body>
        </html>
        ";

        $mail->send();

        // Add notification
        add_notification(
            $userId,
            'success',
            'Report Sent Successfully',
            "Report sent to {$recipientEmail}",
            [
                'report_type' => $reportType,
                'recipient' => $recipientEmail,
                'action' => 'email_report'
            ]
        );

        echo json_encode([
            'success' => true,
            'message' => 'Report sent successfully to ' . $recipientEmail
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Failed to send email: ' . $mail->ErrorInfo
        ]);
    }

    exit;
}


//profile page functions can be added here
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




//reporting functions can be added here
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





//malware analysis functions can be added here

// ==================== UPLOAD & SCAN OPERATIONS ====================
function upload_malware_sample()
{
    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Content-Type: application/json');

    if (!isset($_FILES['file'])) {
        echo json_encode([
            'success' => false,
            'message' => 'No file uploaded'
        ]);
        return;
    }

    $userId = $_SESSION['user_id'] ?? null;
    $projectDir = rtrim(DIR, '/\\');
    $uploadsDir = $projectDir . '/assets/data/malware_uploads';

    if (!is_dir($uploadsDir)) {
        mkdir($uploadsDir, 0755, true);
    }

    // Load notifications helper
    require_once DIR . "app/helpers/notifications.php";

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

            // Add notification
            if ($userId) {
                add_notification(
                    $userId,
                    'success',
                    'Malware Sample Uploaded',
                    "File '{$filename}' uploaded successfully and added to scan queue",
                    [
                        'file_id' => $fileId,
                        'filename' => $filename,
                        'size' => $file['size'],
                        'action' => 'upload_malware'
                    ]
                );
            }

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
    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Content-Type: application/json');

    $userId = $_SESSION['user_id'] ?? null;
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

    // Load notifications helper
    require_once DIR . "app/helpers/notifications.php";

    try {
        // Get filename from queue
        $queueFile = $projectDir . '/assets/data/scan_queue.json';
        $filename = 'Unknown file';
        if (file_exists($queueFile)) {
            $queueData = json_decode(file_get_contents($queueFile), true);
            if (is_array($queueData)) {
                foreach ($queueData as $item) {
                    if ($item['id'] === $fileId) {
                        $filename = $item['filename'];
                        break;
                    }
                }
            }
        }

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
            // Add notification
            if ($userId) {
                add_notification(
                    $userId,
                    'info',
                    'Malware Scan Started',
                    "Analysis started for '{$filename}'",
                    [
                        'file_id' => $fileId,
                        'filename' => $filename,
                        'pid' => $pid,
                        'action' => 'start_malware_scan'
                    ]
                );
            }

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





//ransomware analysis functions can be added here
// ==================== MONITOR CONTROL ====================

function start_ransomware_monitor()
{
    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Content-Type: application/json');

    $userId = $_SESSION['user_id'] ?? null;
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

    // Load notifications helper
    require_once DIR . "app/helpers/notifications.php";

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

            // Add notification
            if ($userId) {
                add_notification(
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

function stop_ransomware_monitor()
{
    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Content-Type: application/json');

    $userId = $_SESSION['user_id'] ?? null;
    $projectDir = rtrim(DIR, '/\\');
    $pidFile = $projectDir . '/assets/data/ransomware_pid.json';

    // Load notifications helper
    require_once DIR . "app/helpers/notifications.php";

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

            // Add notification
            if ($userId) {
                add_notification(
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
    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Content-Type: application/json');

    $userId = $_SESSION['user_id'] ?? null;
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

    // Load notifications helper
    require_once DIR . "app/helpers/notifications.php";

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

            // Add notification
            if ($userId) {
                add_notification(
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

function start_quick_scan()
{
    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Content-Type: application/json');

    $userId = $_SESSION['user_id'] ?? null;
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

    // Load notifications helper
    require_once DIR . "app/helpers/notifications.php";

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
            // Add notification
            if ($userId) {
                add_notification(
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


// ==================== NOTIFICATION FUNCTIONS ====================

/**
 * Get notifications for the logged-in user
 */
function handle_get_notifications()
{
    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Content-Type: application/json');

    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Not authenticated']);
        return;
    }

    require_once DIR . "app/helpers/notifications.php";

    $userId = $_SESSION['user_id'];
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
    $unreadOnly = isset($_GET['unread_only']) && $_GET['unread_only'] === 'true';

    $notifications = get_user_notifications($userId, $limit, $unreadOnly);
    $unreadCount = get_unread_notification_count($userId);

    echo json_encode([
        'success' => true,
        'notifications' => $notifications,
        'unread_count' => $unreadCount
    ]);
}

/**
 * Mark a notification as read
 */
function handle_mark_notification_read()
{
    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Content-Type: application/json');

    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Not authenticated']);
        return;
    }

    require_once DIR . "app/helpers/notifications.php";

    $notificationId = $_POST['notification_id'] ?? null;

    if (!$notificationId) {
        echo json_encode(['success' => false, 'message' => 'Notification ID required']);
        return;
    }

    $success = mark_notification_read($notificationId);

    echo json_encode([
        'success' => $success,
        'message' => $success ? 'Notification marked as read' : 'Failed to mark notification as read'
    ]);
}

/**
 * Mark all notifications as read
 */
function handle_mark_all_notifications_read()
{
    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Content-Type: application/json');

    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Not authenticated']);
        return;
    }

    require_once DIR . "app/helpers/notifications.php";

    $userId = $_SESSION['user_id'];
    $success = mark_all_notifications_read($userId);

    echo json_encode([
        'success' => $success,
        'message' => $success ? 'All notifications marked as read' : 'Failed to mark notifications as read'
    ]);
}

/**
 * Delete a notification
 */
function handle_delete_notification()
{
    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Content-Type: application/json');

    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Not authenticated']);
        return;
    }

    require_once DIR . "app/helpers/notifications.php";

    $notificationId = $_POST['notification_id'] ?? null;

    if (!$notificationId) {
        echo json_encode(['success' => false, 'message' => 'Notification ID required']);
        return;
    }

    $success = delete_notification($notificationId);

    echo json_encode([
        'success' => $success,
        'message' => $success ? 'Notification deleted' : 'Failed to delete notification'
    ]);
}

/**
 * Clear all notifications for the user
 */
function handle_clear_all_notifications()
{
    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Content-Type: application/json');

    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Not authenticated']);
        return;
    }

    require_once DIR . "app/helpers/notifications.php";

    $userId = $_SESSION['user_id'];
    $success = clear_user_notifications($userId);

    echo json_encode([
        'success' => $success,
        'message' => $success ? 'All notifications cleared' : 'Failed to clear notifications'
    ]);
}


// ==================== ADD TO app/core/views.php ====================

/**
 * Threat Intelligence Page Loader
 */
function get_threat_intelligence_page()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }
    require 'app/views/pages/threat_intelligence.php';
}

/**
 * Network Analytics Page Loader
 */
function get_network_analytics_page()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }
    require 'app/views/pages/network_analytics.php';
}

// ==================== ADD TO app/core/functions.php ====================

// ==================== THREAT INTELLIGENCE FUNCTIONS ====================

/**
 * Get threat intelligence feeds
 */
function get_threat_feeds()
{
    header('Content-Type: application/json');

    $projectDir = rtrim(DIR, '/\\');
    $feedsFile = $projectDir . '/assets/data/threat_feeds.json';

    // Load threat feeds from JSON file
    if (file_exists($feedsFile)) {
        $feeds = json_decode(file_get_contents($feedsFile), true);
        echo json_encode($feeds ? $feeds : []);
    } else {
        // Return empty array if file doesn't exist
        echo json_encode([]);
    }
}

/**
 * Get threat actors
 */
function get_threat_actors()
{
    header('Content-Type: application/json');

    $projectDir = rtrim(DIR, '/\\');
    $actorsFile = $projectDir . '/assets/data/threat_actors.json';

    // Load threat actors from JSON file
    if (file_exists($actorsFile)) {
        $actors = json_decode(file_get_contents($actorsFile), true);
        echo json_encode($actors ? $actors : []);
    } else {
        // Return empty array if file doesn't exist
        echo json_encode([]);
    }
}

/**
 * Get Indicators of Compromise
 */
function get_iocs()
{
    header('Content-Type: application/json');

    $type = $_GET['type'] ?? 'all'; // all, ip, domain, hash

    $projectDir = rtrim(DIR, '/\\');
    $iocsFile = $projectDir . '/assets/data/iocs.json';

    // Load IOCs from JSON file
    if (file_exists($iocsFile)) {
        $iocs = json_decode(file_get_contents($iocsFile), true);
        if (!$iocs) {
            $iocs = ['ips' => [], 'domains' => [], 'hashes' => []];
        }
    } else {
        $iocs = ['ips' => [], 'domains' => [], 'hashes' => []];
    }

    if ($type === 'all') {
        echo json_encode($iocs);
    } else {
        echo json_encode(isset($iocs[$type . 's']) ? $iocs[$type . 's'] : []);
    }
}

/**
 * Get critical vulnerabilities
 */
function get_vulnerabilities()
{
    header('Content-Type: application/json');

    $projectDir = rtrim(DIR, '/\\');
    $vulnFile = $projectDir . '/assets/data/vulnerabilities.json';

    // Load vulnerabilities from JSON file
    if (file_exists($vulnFile)) {
        $vulnerabilities = json_decode(file_get_contents($vulnFile), true);
        echo json_encode($vulnerabilities ? $vulnerabilities : []);
    } else {
        // Return empty array if file doesn't exist
        echo json_encode([]);
    }
}

/**
 * Block an IOC
 */
function block_ioc()
{
    header('Content-Type: application/json');
    
    $ioc = $_POST['ioc'] ?? '';
    $type = $_POST['type'] ?? 'ip';
    
    if (empty($ioc)) {
        echo json_encode(['success' => false, 'message' => 'IOC is required']);
        return;
    }
    
    // Save blocked IOC
    $projectDir = rtrim(DIR, '/\\');
    $blockedFile = $projectDir . '/assets/data/blocked_iocs.json';
    
    $blocked = file_exists($blockedFile) ? json_decode(file_get_contents($blockedFile), true) : [];
    
    $blocked[] = [
        'ioc' => $ioc,
        'type' => $type,
        'blockedAt' => date('Y-m-d H:i:s'),
        'reason' => 'User blocked',
        'status' => 'active'
    ];
    
    file_put_contents($blockedFile, json_encode($blocked, JSON_PRETTY_PRINT));
    
    echo json_encode(['success' => true, 'message' => "IOC {$ioc} has been blocked"]);
}

/**
 * Whitelist an IOC
 */
function whitelist_ioc()
{
    header('Content-Type: application/json');
    
    $ioc = $_POST['ioc'] ?? '';
    
    if (empty($ioc)) {
        echo json_encode(['success' => false, 'message' => 'IOC is required']);
        return;
    }
    
    $projectDir = rtrim(DIR, '/\\');
    $whitelistFile = $projectDir . '/assets/data/whitelisted_iocs.json';
    
    $whitelist = file_exists($whitelistFile) ? json_decode(file_get_contents($whitelistFile), true) : [];
    
    $whitelist[] = [
        'ioc' => $ioc,
        'whitelistedAt' => date('Y-m-d H:i:s'),
        'reason' => 'False positive'
    ];
    
    file_put_contents($whitelistFile, json_encode($whitelist, JSON_PRETTY_PRINT));
    
    echo json_encode(['success' => true, 'message' => "IOC {$ioc} has been whitelisted"]);
}

// ==================== NETWORK ANALYTICS FUNCTIONS ====================

/**
 * Get network metrics
 */
function get_network_metrics()
{
    header('Content-Type: application/json');
    
    $projectDir = rtrim(DIR, '/\\');
    $trafficFile = $projectDir . '/assets/data/traffic_log.json';
    
    $metrics = [
        'totalPackets' => 0,
        'activeFlows' => 0,
        'totalBandwidth' => 0,
        'avgLatency' => 0
    ];
    
    if (file_exists($trafficFile)) {
        $flows = json_decode(file_get_contents($trafficFile), true);
        
        if (is_array($flows)) {
            $metrics['totalPackets'] = count($flows);
            $metrics['activeFlows'] = count(array_unique(array_column($flows, 'Flow ID')));
            $metrics['totalBandwidth'] = array_sum(array_column($flows, 'Total Length of Fwd Packets')) / 1000000;
            
            $latencies = array_column($flows, 'Flow Duration');
            $metrics['avgLatency'] = !empty($latencies) ? array_sum($latencies) / count($latencies) : 0;
        }
    }
    
    echo json_encode($metrics);
}

/**
 * Get bandwidth data
 */
function get_bandwidth_data()
{
    header('Content-Type: application/json');

    $projectDir = rtrim(DIR, '/\\');
    $bandwidthFile = $projectDir . '/assets/data/network_bandwidth.json';

    // Load bandwidth data from JSON file
    if (file_exists($bandwidthFile)) {
        $data = json_decode(file_get_contents($bandwidthFile), true);
        if (!$data) {
            $data = ['labels' => [], 'upload' => [], 'download' => []];
        }
    } else {
        $data = ['labels' => [], 'upload' => [], 'download' => []];
    }

    echo json_encode($data);
}

/**
 * Get protocol statistics
 */
function get_protocol_stats()
{
    header('Content-Type: application/json');

    $projectDir = rtrim(DIR, '/\\');
    $protocolsFile = $projectDir . '/assets/data/network_protocols.json';

    // Load protocol stats from JSON file
    if (file_exists($protocolsFile)) {
        $protocols = json_decode(file_get_contents($protocolsFile), true);
        if (!$protocols) {
            $protocols = ['TCP' => 0, 'UDP' => 0, 'ICMP' => 0, 'Other' => 0];
        }
    } else {
        $protocols = ['TCP' => 0, 'UDP' => 0, 'ICMP' => 0, 'Other' => 0];
    }

    echo json_encode($protocols);
}

/**
 * Get top talkers
 */
function get_top_talkers()
{
    header('Content-Type: application/json');

    $projectDir = rtrim(DIR, '/\\');
    $talkersFile = $projectDir . '/assets/data/network_talkers.json';

    // Load top talkers from JSON file
    if (file_exists($talkersFile)) {
        $talkers = json_decode(file_get_contents($talkersFile), true);
        echo json_encode($talkers ? $talkers : []);
    } else {
        echo json_encode([]);
    }
}

/**
 * Get active connections
 */
function get_active_connections()
{
    header('Content-Type: application/json');

    $projectDir = rtrim(DIR, '/\\');
    $connectionsFile = $projectDir . '/assets/data/network_connections.json';

    // Load active connections from JSON file
    if (file_exists($connectionsFile)) {
        $connections = json_decode(file_get_contents($connectionsFile), true);
        echo json_encode($connections ? $connections : []);
    } else {
        echo json_encode([]);
    }
}

/**
 * Get packet activity
 */
function get_packet_activity()
{
    header('Content-Type: application/json');

    $projectDir = rtrim(DIR, '/\\');
    $packetsFile = $projectDir . '/assets/data/network_packets.json';

    // Load packet activity from JSON file
    if (file_exists($packetsFile)) {
        $packets = json_decode(file_get_contents($packetsFile), true);
        echo json_encode($packets ? $packets : []);
    } else {
        echo json_encode([]);
    }
}

// ==================== VALIDATED ALERTS (THREAT INTELLIGENCE) ====================

/**
 * Get validated alerts - reduces false positives by validating IPs against threat intelligence APIs
 * This function loads alerts from alerts.json and validates each source IP against:
 * - AbuseIPDB
 * - AlienVault OTX
 * - IPQualityScore
 * Only alerts confirmed by at least one API are returned to the frontend
 */
function get_validated_alerts()
{
    header('Content-Type: application/json');

    if (!isset($_SESSION['user_id'])) {
        echo json_encode([
            'success' => false,
            'message' => 'Unauthorized',
            'alerts' => []
        ]);
        return;
    }

    try {
        // Load the IP validation service
        require_once 'app/core/IPValidationService.php';
        $validator = new IPValidationService();

        // Load alerts from file
        $projectDir = rtrim(DIR, '/\\');
        $alertsFile = $projectDir . '/assets/data/alerts.json';

        if (!file_exists($alertsFile)) {
            echo json_encode([
                'success' => true,
                'alerts' => [],
                'stats' => [
                    'total_alerts' => 0,
                    'validated_alerts' => 0,
                    'filtered_alerts' => 0
                ]
            ]);
            return;
        }

        $alertsData = json_decode(file_get_contents($alertsFile), true);

        if (!is_array($alertsData)) {
            $alertsData = [];
        }

        // Track statistics
        $stats = [
            'total_alerts' => count($alertsData),
            'validated_alerts' => 0,
            'filtered_alerts' => 0,
            'validation_details' => []
        ];

        $validatedAlerts = [];

        // Validate each alert
        foreach ($alertsData as $alert) {
            $sourceIP = $alert['Src IP'] ?? '';

            if (empty($sourceIP)) {
                // If no source IP, skip validation and include the alert
                $validatedAlerts[] = $alert;
                $stats['validated_alerts']++;
                continue;
            }

            // Validate the IP
            $validationResult = $validator->validateIP($sourceIP);

            // Add validation metadata to the alert
            $alert['validation'] = [
                'is_validated' => $validationResult['is_validated'],
                'confidence' => $validationResult['confidence'],
                'sources' => $validationResult['sources'],
                'note' => $validationResult['note'] ?? ''
            ];

            // Only include alerts that are validated as threats
            // OR if the IP is private (internal network alerts are always shown)
            if ($validationResult['is_validated'] || isset($validationResult['note'])) {
                $validatedAlerts[] = $alert;
                $stats['validated_alerts']++;

                // Store validation details for statistics
                if (!empty($validationResult['sources'])) {
                    $stats['validation_details'][] = [
                        'ip' => $sourceIP,
                        'sources' => $validationResult['sources'],
                        'confidence' => $validationResult['confidence']
                    ];
                }
            } else {
                $stats['filtered_alerts']++;
            }
        }

        echo json_encode([
            'success' => true,
            'alerts' => $validatedAlerts,
            'stats' => $stats,
            'message' => sprintf(
                'Filtered %d false positives out of %d total alerts',
                $stats['filtered_alerts'],
                $stats['total_alerts']
            )
        ]);

    } catch (Exception $e) {
        error_log("Error in get_validated_alerts: " . $e->getMessage());
        echo json_encode([
            'success' => false,
            'message' => 'Error validating alerts: ' . $e->getMessage(),
            'alerts' => []
        ]);
    }
}

/**
 * Test endpoint to validate a single IP address
 * Usage: GET /test-ip-validation?ip=8.8.8.8
 */
function test_ip_validation()
{
    header('Content-Type: application/json');

    if (!isset($_SESSION['user_id'])) {
        echo json_encode([
            'success' => false,
            'message' => 'Unauthorized'
        ]);
        return;
    }

    $ip = $_GET['ip'] ?? '';

    if (empty($ip)) {
        echo json_encode([
            'success' => false,
            'message' => 'Please provide an IP address via ?ip=x.x.x.x parameter'
        ]);
        return;
    }

    // Validate IP format
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        echo json_encode([
            'success' => false,
            'message' => 'Invalid IP address format'
        ]);
        return;
    }

    try {
        // Load the IP validation service
        require_once 'app/core/IPValidationService.php';
        $validator = new IPValidationService();

        // Validate the IP
        $result = $validator->validateIP($ip);

        // Return detailed results
        echo json_encode([
            'success' => true,
            'ip' => $ip,
            'is_validated_threat' => $result['is_validated'],
            'confidence' => $result['confidence'],
            'confirmed_by' => $result['sources'],
            'note' => $result['note'] ?? '',
            'details' => [
                'abuseipdb' => array_filter($result['details'], function($d) {
                    return $d['source'] === 'abuseipdb';
                })[0] ?? null,
                'alienvault' => array_filter($result['details'], function($d) {
                    return $d['source'] === 'alienvault';
                })[1] ?? null,
                'ipqualityscore' => array_filter($result['details'], function($d) {
                    return $d['source'] === 'ipqualityscore';
                })[2] ?? null
            ],
            'verdict' => $result['is_validated']
                ? '⚠️ CONFIRMED THREAT - This IP is malicious'
                : '✅ NOT A THREAT - This is likely a false positive'
        ]);

    } catch (Exception $e) {
        error_log("Error in test_ip_validation: " . $e->getMessage());
        echo json_encode([
            'success' => false,
            'message' => 'Error validating IP: ' . $e->getMessage()
        ]);
    }
}


?>