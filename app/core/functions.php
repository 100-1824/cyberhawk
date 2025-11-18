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
        $sql = "SELECT id, name, email, password, role FROM users WHERE email = ?";
        $stmt = mysqli_prepared_query($sql, 's', [$email]);

        if ($stmt === false) {
            $error = "Database error. Please try again.";
        } elseif (count($stmt) === 0) {
            $error = "No user found with this email.";
        } else {
            $user = $stmt[0];

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

function handle_Register() {
    // Ensure session is started
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    $error = null;

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo "Method Not Allowed";
        exit;
    }

    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $role = 'user'; // default role

    if (!$name || !$email || !$password) {
        $error = "All fields are required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email format.";
    } elseif (strlen($password) < 6) {
        $error = "Password must be at least 6 characters.";
    } else {
        // Check if email already exists
        $rows = mysqli_prepared_query("SELECT id FROM users WHERE email = ?", 's', [$email]);

        if ($rows === false) {
            $error = "Database error. Please try again.";
        } elseif (count($rows) > 0) {
            $error = "Email already registered.";
        } else {
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            // Insert new user
            $inserted = mysqli_prepared_query(
                "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
                'ssss',
                [$name, $email, $hashedPassword, $role]
            );

            if ($inserted) {
                $_SESSION['success'] = "Registration successful! Please login.";
                // Redirect to login page using MDIR
                header("Location: " . MDIR . "login");
                exit;
            } else {
                $error = "Failed to register. Please try again.";
            }
        }
    }

    // Render the registration form with error messages
    get_register_view($error);
}



?>