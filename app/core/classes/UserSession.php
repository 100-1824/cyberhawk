<?php

/**
 * UserSession Class
 *
 * Purpose: Tracks active user sessions for authentication and security.
 * This class wraps existing session-related functionality from functions.php
 */
class UserSession {

    // Attributes
    private $id;
    private $email;
    private $session;
    private $created_at;

    /**
     * Constructor
     * @param int $sessionId Optional session ID to load session data
     */
    public function __construct($sessionId = null) {
        if ($sessionId !== null) {
            $this->loadSession($sessionId);
        }
    }

    /**
     * Load session data from database
     */
    private function loadSession($sessionId) {
        $sql = "SELECT * FROM user_sessions WHERE id = ?";
        $result = mysqli_prepared_query($sql, 'i', [$sessionId]);

        if (!empty($result)) {
            $row = $result[0];
            $this->id = $row['id'];
            $this->email = $row['email'];
            $this->session = $row['session'];
            $this->created_at = $row['created_at'];
            return true;
        }
        return false;
    }

    /**
     * validateSession() - Verifies session validity
     * Uses checkSession() middleware from functions.php
     *
     * @return bool True if session is valid
     */
    public function validateSession() {
        return self::validateCurrentSession();
    }

    /**
     * terminateSession() - Ends the session
     * Wraps session termination logic from functions.php
     *
     * @param string $email User email
     * @return bool Success status
     */
    public function terminateSession($email) {
        $sql = "DELETE FROM user_sessions WHERE email = ?";
        return mysqli_prepared_query($sql, 's', [$email]) !== false;
    }

    /**
     * Create a new session for a user (used internally by handle_login())
     *
     * @param string $email User email
     * @param string $sessionId Session ID from PHP session
     * @return bool Success status
     */
    public static function createSession($email, $sessionId) {
        // First delete any existing sessions
        mysqli_prepared_query("DELETE FROM user_sessions WHERE email = ?", 's', [$email]);

        // Insert new session
        $sql = "INSERT INTO user_sessions (email, session, created_at) VALUES (?, ?, NOW())";
        return mysqli_prepared_query($sql, 'ss', [$email, $sessionId]) !== false;
    }

    /**
     * Validate current PHP session
     * This wraps the session validation logic from checkSession() in functions.php
     *
     * @return bool True if session is valid
     */
    public static function validateCurrentSession() {
        if (!isset($_SESSION['user_id']) || !isset($_COOKIE['session_id'])) {
            return false;
        }

        // Check if cookie matches PHP session
        if ($_COOKIE['session_id'] !== session_id()) {
            return false;
        }

        // Check session timeout
        if (isset($_SESSION['LAST_ACTIVITY'])) {
            $userId = $_SESSION['user_id'];

            // Get user's session timeout setting
            $timeoutSql = "SELECT setting_value FROM system_settings WHERE user_id = ? AND setting_key = 'session_timeout'";
            $timeoutResult = mysqli_prepared_query($timeoutSql, 'i', [$userId]);

            $sessionTimeoutMinutes = 30; // Default
            if (!empty($timeoutResult)) {
                $sessionTimeoutMinutes = intval($timeoutResult[0]['setting_value']);
            }

            if ($sessionTimeoutMinutes > 0) {
                $timeout = $sessionTimeoutMinutes * 60;
                $elapsedTime = time() - $_SESSION['LAST_ACTIVITY'];

                if ($elapsedTime > $timeout) {
                    return false;
                }
            }

            // Update last activity
            $_SESSION['LAST_ACTIVITY'] = time();
        }

        // Verify session exists in database
        $userSql = "SELECT email FROM users WHERE id = ?";
        $userResult = mysqli_prepared_query($userSql, 'i', [$_SESSION['user_id']]);

        if (empty($userResult)) {
            return false;
        }

        $userEmail = $userResult[0]['email'];
        $sessionSql = "SELECT session FROM user_sessions WHERE email = ?";
        $sessionResult = mysqli_prepared_query($sessionSql, 's', [$userEmail]);

        if (empty($sessionResult)) {
            return false;
        }

        $dbSessionId = $sessionResult[0]['session'];
        return ($dbSessionId === session_id());
    }

    /**
     * Get active sessions count for a user
     *
     * @param string $email User email
     * @return int Number of active sessions
     */
    public static function getActiveSessionsCount($email) {
        $sql = "SELECT COUNT(*) as count FROM user_sessions WHERE email = ?";
        $result = mysqli_prepared_query($sql, 's', [$email]);

        if (!empty($result)) {
            return (int)$result[0]['count'];
        }
        return 0;
    }

    /**
     * Terminate all sessions for a user
     * Wraps handle_terminate_sessions() functionality
     *
     * @param string $email User email
     * @return bool Success status
     */
    public static function terminateAllUserSessions($email) {
        $sql = "DELETE FROM user_sessions WHERE email = ?";
        return mysqli_prepared_query($sql, 's', [$email]) !== false;
    }

    // Getter methods
    public function getId() { return $this->id; }
    public function getEmail() { return $this->email; }
    public function getSession() { return $this->session; }
    public function getCreatedAt() { return $this->created_at; }
}

?>
