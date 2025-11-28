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

        // Check if the session ID from the cookie matches the session ID stored in the PHP session
        if (!isset($_COOKIE['session_id']) || $_COOKIE['session_id'] !== session_id()) {
            header('HTTP/1.1 401 Unauthorized');
            header('Location: ' . MDIR . 'login');
            exit;
        }

        // Fetch the session ID from the database using USER_ID
        $userId = $_SESSION['user_id'];
        
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

// ==================== SETTINGS MODULE HANDLERS ====================

/**
 * Handle password update
 */
function handle_update_password() {
    if (session_status() === PHP_SESSION_NONE) session_start();

    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
        exit;
    }

    $userId = $_SESSION['user_id'];
    $currentPassword = $_POST['current_password'] ?? '';
    $newPassword = $_POST['new_password'] ?? '';
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

    // Add notification
    add_notification(
        $userId,
        'Password Changed',
        'Your password has been updated successfully',
        'success',
        'bi-shield-check'
    );

    echo json_encode(['success' => true, 'message' => 'Password updated successfully']);
    exit;
}

/**
 * Handle saving system settings
 */
function handle_save_settings() {
    if (session_status() === PHP_SESSION_NONE) session_start();

    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
        exit;
    }

    $userId = $_SESSION['user_id'];
    $settings = $_POST['settings'] ?? [];

    if (empty($settings)) {
        echo json_encode(['success' => false, 'message' => 'No settings provided']);
        exit;
    }

    // Update or insert each setting
    foreach ($settings as $key => $value) {
        // Check if setting exists
        $checkSql = "SELECT id FROM system_settings WHERE user_id = ? AND setting_key = ?";
        $existing = mysqli_prepared_query($checkSql, 'is', [$userId, $key]);

        if ($existing && count($existing) > 0) {
            // Update existing setting
            $updateSql = "UPDATE system_settings SET setting_value = ? WHERE user_id = ? AND setting_key = ?";
            mysqli_prepared_query($updateSql, 'sis', [$value, $userId, $key]);
        } else {
            // Insert new setting
            $insertSql = "INSERT INTO system_settings (user_id, setting_key, setting_value) VALUES (?, ?, ?)";
            mysqli_prepared_query($insertSql, 'iss', [$userId, $key, $value]);
        }
    }

    // Add notification
    add_notification(
        $userId,
        'Settings Updated',
        'Your system settings have been saved successfully',
        'success',
        'bi-check-circle'
    );

    echo json_encode(['success' => true, 'message' => 'Settings saved successfully']);
    exit;
}

/**
 * Handle saving API keys
 */
function handle_save_api_keys() {
    if (session_status() === PHP_SESSION_NONE) session_start();

    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
        exit;
    }

    $userId = $_SESSION['user_id'];
    $virusTotalKey = $_POST['virustotal_api_key'] ?? '';
    $hybridAnalysisKey = $_POST['hybrid_analysis_key'] ?? '';

    // Save VirusTotal API key
    if (!empty($virusTotalKey)) {
        $checkSql = "SELECT id FROM system_settings WHERE user_id = ? AND setting_key = 'virustotal_api_key'";
        $existing = mysqli_prepared_query($checkSql, 'i', [$userId]);

        if ($existing && count($existing) > 0) {
            $updateSql = "UPDATE system_settings SET setting_value = ? WHERE user_id = ? AND setting_key = 'virustotal_api_key'";
            mysqli_prepared_query($updateSql, 'si', [$virusTotalKey, $userId]);
        } else {
            $insertSql = "INSERT INTO system_settings (user_id, setting_key, setting_value) VALUES (?, 'virustotal_api_key', ?)";
            mysqli_prepared_query($insertSql, 'is', [$userId, $virusTotalKey]);
        }
    }

    // Save Hybrid Analysis API key
    if (!empty($hybridAnalysisKey)) {
        $checkSql = "SELECT id FROM system_settings WHERE user_id = ? AND setting_key = 'hybrid_analysis_key'";
        $existing = mysqli_prepared_query($checkSql, 'i', [$userId]);

        if ($existing && count($existing) > 0) {
            $updateSql = "UPDATE system_settings SET setting_value = ? WHERE user_id = ? AND setting_key = 'hybrid_analysis_key'";
            mysqli_prepared_query($updateSql, 'si', [$hybridAnalysisKey, $userId]);
        } else {
            $insertSql = "INSERT INTO system_settings (user_id, setting_key, setting_value) VALUES (?, 'hybrid_analysis_key', ?)";
            mysqli_prepared_query($insertSql, 'is', [$userId, $hybridAnalysisKey]);
        }
    }

    // Add notification
    add_notification(
        $userId,
        'API Keys Updated',
        'Your API keys have been saved successfully',
        'success',
        'bi-key'
    );

    echo json_encode(['success' => true, 'message' => 'API keys saved successfully']);
    exit;
}

/**
 * Handle clearing all logs
 */
function handle_clear_all_logs() {
    if (session_status() === PHP_SESSION_NONE) session_start();

    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
        exit;
    }

    $dataDir = DIR . 'assets/data/';
    $clearedFiles = [];

    // List of log files to clear
    $logFiles = [
        'traffic_log.json',
        'alerts.json',
        'ransomware_activity.json',
        'malware_reports.json'
    ];

    foreach ($logFiles as $file) {
        $filePath = $dataDir . $file;
        if (file_exists($filePath)) {
            file_put_contents($filePath, json_encode([], JSON_PRETTY_PRINT));
            $clearedFiles[] = $file;
        }
    }

    // Add notification
    $userId = $_SESSION['user_id'];
    add_notification(
        $userId,
        'Logs Cleared',
        'All system logs have been cleared successfully',
        'warning',
        'bi-trash'
    );

    echo json_encode([
        'success' => true,
        'message' => 'All logs cleared successfully',
        'cleared_files' => $clearedFiles
    ]);
    exit;
}

/**
 * Handle exporting user data (GDPR compliance)
 */
function handle_export_user_data() {
    if (session_status() === PHP_SESSION_NONE) session_start();

    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
        exit;
    }

    $userId = $_SESSION['user_id'];

    // Get user data
    $userSql = "SELECT id, name, email, role FROM users WHERE id = ?";
    $userData = mysqli_prepared_query($userSql, 'i', [$userId]);

    // Get user settings
    $settingsSql = "SELECT setting_key, setting_value FROM system_settings WHERE user_id = ?";
    $settingsData = mysqli_prepared_query($settingsSql, 'i', [$userId]);

    $exportData = [
        'user' => $userData[0] ?? null,
        'settings' => $settingsData ?? [],
        'export_date' => date('Y-m-d H:i:s')
    ];

    // Create export file
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
 * Handle terminating user sessions
 */
function handle_terminate_sessions() {
    if (session_status() === PHP_SESSION_NONE) session_start();

    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
        exit;
    }

    $userId = $_SESSION['user_id'];

    // Delete all sessions for this user (except current)
    $currentSessionId = session_id();
    $deleteSql = "DELETE FROM user_sessions WHERE user_id = ? AND session_id != ?";
    mysqli_prepared_query($deleteSql, 'is', [$userId, $currentSessionId]);

    echo json_encode(['success' => true, 'message' => 'All other sessions terminated']);
    exit;
}

/**
 * Handle account deletion
 */
function handle_delete_account() {
    if (session_status() === PHP_SESSION_NONE) session_start();

    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
        exit;
    }

    $userId = $_SESSION['user_id'];
    $password = $_POST['password'] ?? '';

    if (empty($password)) {
        echo json_encode(['success' => false, 'message' => 'Password required to delete account']);
        exit;
    }

    // Verify password
    $sql = "SELECT password FROM users WHERE id = ?";
    $result = mysqli_prepared_query($sql, 'i', [$userId]);

    if (!$result || count($result) === 0) {
        echo json_encode(['success' => false, 'message' => 'User not found']);
        exit;
    }

    if (!password_verify($password, $result[0]['password'])) {
        echo json_encode(['success' => false, 'message' => 'Incorrect password']);
        exit;
    }

    // Delete user data
    mysqli_prepared_query("DELETE FROM system_settings WHERE user_id = ?", 'i', [$userId]);
    mysqli_prepared_query("DELETE FROM user_sessions WHERE user_id = ?", 'i', [$userId]);
    mysqli_prepared_query("DELETE FROM users WHERE id = ?", 'i', [$userId]);

    // Destroy session
    session_destroy();

    echo json_encode(['success' => true, 'message' => 'Account deleted successfully']);
    exit;
}

/**
 * Get user statistics for profile
 */
function handle_get_user_stats() {
    if (session_status() === PHP_SESSION_NONE) session_start();

    header('Content-Type: application/json');

    $userId = $_SESSION['user_id'];

    // Get user registration date
    $userSql = "SELECT DATE(created_at) as join_date FROM users WHERE id = ?";
    $userData = mysqli_prepared_query($userSql, 'i', [$userId]);

    $joinDate = $userData[0]['join_date'] ?? date('Y-m-d');
    $daysActive = (strtotime('now') - strtotime($joinDate)) / (60 * 60 * 24);

    // Count data from JSON files
    $dataDir = DIR . 'assets/data/';

    $alertsFile = $dataDir . 'alerts.json';
    $alertsCount = 0;
    if (file_exists($alertsFile)) {
        $alerts = json_decode(file_get_contents($alertsFile), true);
        $alertsCount = is_array($alerts) ? count($alerts) : 0;
    }

    $malwareFile = $dataDir . 'malware_reports.json';
    $scansCount = 0;
    if (file_exists($malwareFile)) {
        $malware = json_decode(file_get_contents($malwareFile), true);
        $scansCount = is_array($malware) ? count($malware) : 0;
    }

    $quarantineFile = $dataDir . 'quarantine.json';
    $quarantineCount = 0;
    if (file_exists($quarantineFile)) {
        $quarantine = json_decode(file_get_contents($quarantineFile), true);
        $quarantineCount = is_array($quarantine) ? count($quarantine) : 0;
    }

    $stats = [
        'scans' => $scansCount,
        'alerts' => $alertsCount,
        'quarantined' => $quarantineCount,
        'days_active' => (int)$daysActive
    ];

    echo json_encode(['success' => true, 'stats' => $stats]);
    exit;
}

// ==================== NOTIFICATION SYSTEM ====================

/**
 * Add a notification for user actions
 */
function add_notification($userId, $title, $message, $type = 'info', $icon = 'bi-info-circle') {
    $projectDir = rtrim(DIR, '/\\');
    $notificationsFile = $projectDir . '/assets/data/user_notifications.json';

    // Load existing notifications
    $notifications = [];
    if (file_exists($notificationsFile)) {
        $data = json_decode(file_get_contents($notificationsFile), true);
        $notifications = is_array($data) ? $data : [];
    }

    // Create new notification
    $notification = [
        'id' => uniqid('notif_', true),
        'user_id' => $userId,
        'title' => $title,
        'message' => $message,
        'type' => $type, // success, info, warning, danger
        'icon' => $icon,
        'timestamp' => date('Y-m-d H:i:s'),
        'read' => false
    ];

    // Add to beginning of array (newest first)
    array_unshift($notifications, $notification);

    // Keep only last 100 notifications
    $notifications = array_slice($notifications, 0, 100);

    // Save notifications
    file_put_contents($notificationsFile, json_encode($notifications, JSON_PRETTY_PRINT));

    return $notification;
}

/**
 * Get user notifications
 */
function get_user_notifications() {
    if (session_status() === PHP_SESSION_NONE) session_start();

    header('Content-Type: application/json');

    $userId = $_SESSION['user_id'];
    $projectDir = rtrim(DIR, '/\\');
    $notificationsFile = $projectDir . '/assets/data/user_notifications.json';

    $notifications = [];
    if (file_exists($notificationsFile)) {
        $allNotifications = json_decode(file_get_contents($notificationsFile), true);

        // Filter by user ID
        if (is_array($allNotifications)) {
            $notifications = array_filter($allNotifications, function($notif) use ($userId) {
                return isset($notif['user_id']) && $notif['user_id'] == $userId;
            });
            $notifications = array_values($notifications); // Re-index array
        }
    }

    echo json_encode($notifications);
    exit;
}

/**
 * Mark notification as read
 */
function mark_notification_read() {
    if (session_status() === PHP_SESSION_NONE) session_start();

    header('Content-Type: application/json');

    $notificationId = $_POST['notification_id'] ?? null;

    if (!$notificationId) {
        echo json_encode(['success' => false, 'message' => 'Notification ID required']);
        exit;
    }

    $projectDir = rtrim(DIR, '/\\');
    $notificationsFile = $projectDir . '/assets/data/user_notifications.json';

    if (file_exists($notificationsFile)) {
        $notifications = json_decode(file_get_contents($notificationsFile), true);

        if (is_array($notifications)) {
            foreach ($notifications as &$notif) {
                if ($notif['id'] === $notificationId) {
                    $notif['read'] = true;
                    break;
                }
            }

            file_put_contents($notificationsFile, json_encode($notifications, JSON_PRETTY_PRINT));
            echo json_encode(['success' => true]);
            exit;
        }
    }

    echo json_encode(['success' => false]);
    exit;
}

// ==================== REPORTING MODULE HANDLERS ====================

/**
 * Handle downloading report as PDF
 */
function handle_download_report() {
    if (session_status() === PHP_SESSION_NONE) session_start();

    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
        exit;
    }

    $reportType = $_POST['report_type'] ?? '';
    $reportData = $_POST['report_data'] ?? '';

    if (empty($reportType) || empty($reportData)) {
        echo json_encode(['success' => false, 'message' => 'Report type and data are required']);
        exit;
    }

    // Create reports directory if it doesn't exist
    $reportsDir = DIR . 'assets/reports/';
    if (!file_exists($reportsDir)) {
        mkdir($reportsDir, 0755, true);
    }

    $filename = 'cyberhawk_' . $reportType . '_report_' . date('YmdHis') . '.html';
    $filepath = $reportsDir . $filename;

    // Save report HTML
    file_put_contents($filepath, $reportData);

    echo json_encode([
        'success' => true,
        'message' => 'Report generated successfully',
        'download_url' => MDIR . 'assets/reports/' . $filename,
        'filename' => $filename
    ]);
    exit;
}

/**
 * Handle emailing report
 */
function handle_email_report() {
    if (session_status() === PHP_SESSION_NONE) session_start();

    header('Content-Type: application/json');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['success' => false, 'message' => 'Invalid request method']);
        exit;
    }

    $userId = $_SESSION['user_id'];
    $recipientEmail = $_POST['email'] ?? '';
    $reportType = $_POST['report_type'] ?? '';
    $reportData = $_POST['report_data'] ?? '';

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
    $userSql = "SELECT name, email FROM users WHERE id = ?";
    $userData = mysqli_prepared_query($userSql, 'i', [$userId]);
    $userName = $userData[0]['name'] ?? 'CyberHawk User';

    // Load PHPMailer
    require_once DIR . "app/helpers/email.php";
    require_once DIR . 'vendor/phpmailer/phpmailer/src/PHPMailer.php';
    require_once DIR . 'vendor/phpmailer/phpmailer/src/SMTP.php';
    require_once DIR . 'vendor/phpmailer/phpmailer/src/Exception.php';

    use PHPMailer\PHPMailer\PHPMailer;
    use PHPMailer\PHPMailer\Exception;

    try {
        $mail = new PHPMailer(true);

        // SMTP Configuration
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com';
        $mail->SMTPAuth = true;
        $mail->Username = 'ahmedsahni71@gmail.com';
        $mail->Password = 'cpfd ngib avzy zpwl';
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = 587;

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
            'Report Emailed',
            "Security report sent successfully to {$recipientEmail}",
            'success',
            'bi-envelope-check'
        );

        echo json_encode([
            'success' => true,
            'message' => 'Report sent successfully to ' . $recipientEmail
        ]);

    } catch (Exception $e) {
        // Add error notification
        add_notification(
            $userId,
            'Email Failed',
            "Failed to send report to {$recipientEmail}",
            'danger',
            'bi-exclamation-triangle'
        );

        echo json_encode([
            'success' => false,
            'message' => 'Failed to send email: ' . $mail->ErrorInfo
        ]);
    }

    exit;
}


?>