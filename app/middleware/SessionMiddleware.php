<?php

/**
 * SessionMiddleware Class
 *
 * Purpose: Handles session validation and timeout checking
 * Replaces: checkSession() function
 */
class SessionMiddleware {

    private $db;

    /**
     * Constructor
     */
    public function __construct() {
        $this->db = new DatabaseHelper();
    }

    /**
     * Handle middleware logic - check session validity
     *
     * @param callable $handler The handler to call if session is valid
     * @return callable Middleware function
     */
    public function handle($handler) {
        return function($vars) use ($handler) {
            // Check if the required session key is set in the PHP session
            if (!isset($_SESSION['user_id'])) {
                header('HTTP/1.1 401 Unauthorized');
                header('Location: ' . MDIR . 'login');
                exit;
            }

            // ==================== SESSION TIMEOUT CHECK ====================
            $userId = $_SESSION['user_id'];
            $this->checkSessionTimeout($userId);

            // Check if the session ID from the cookie matches the session ID stored in the PHP session
            if (!isset($_COOKIE['session_id']) || $_COOKIE['session_id'] !== session_id()) {
                header('HTTP/1.1 401 Unauthorized');
                header('Location: ' . MDIR . 'login');
                exit;
            }

            // Validate session from database
            $this->validateDatabaseSession($userId);

            // Call the handler function
            if (is_callable($handler)) {
                return call_user_func($handler, $vars);
            } elseif (is_array($handler) && count($handler) === 2) {
                // Handle [ControllerInstance, 'methodName'] format
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
     * Check session timeout based on user settings
     *
     * @param int $userId User ID
     */
    private function checkSessionTimeout($userId) {
        // Load user's session timeout setting
        $timeoutSettingQuery = "SELECT setting_value FROM system_settings WHERE user_id = ? AND setting_key = 'session_timeout'";
        $timeoutResult = $this->db->query($timeoutSettingQuery, 'i', [$userId]);

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
    }

    /**
     * Validate session exists in database
     *
     * @param int $userId User ID
     */
    private function validateDatabaseSession($userId) {
        // Get the user's email first
        $userQuery = "SELECT email FROM users WHERE id = ?";
        $userResult = $this->db->query($userQuery, 'i', [$userId]);

        if (empty($userResult)) {
            session_destroy();
            header('HTTP/1.1 401 Unauthorized');
            header('Location: ' . MDIR . 'login');
            exit;
        }

        $userEmail = $userResult[0]['email'];

        // Query the session table with the correct email
        $sql = "SELECT session FROM user_sessions WHERE email = ?";
        $row = $this->db->query($sql, 's', [$userEmail]);

        if (!empty($row)) {
            $dbSessionId = $row[0]['session'];
            // Check if the session ID from the database matches the session ID from the cookie and PHP session
            if ($dbSessionId !== session_id()) {
                session_destroy();
                setcookie('session_id', '', time() - 3600, '/', '', false, true);
                header('HTTP/1.1 401 Unauthorized');
                header('Location: ' . MDIR . 'login');
                exit;
            }
        } else {
            // No session found in database
            session_destroy();
            setcookie('session_id', '', time() - 3600, '/', '', false, true);
            header('HTTP/1.1 401 Unauthorized');
            header('Location: ' . MDIR . 'login');
            exit;
        }
    }
}

?>
