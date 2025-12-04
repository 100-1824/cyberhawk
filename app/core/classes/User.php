<?php

/**
 * User Class
 *
 * Purpose: Manages user accounts and authentication in the CyberHawk IDS system.
 * This class wraps existing user-related functions from functions.php
 */
class User {

    // Attributes
    private $id;
    private $name;
    private $email;
    private $password;
    private $role;
    private $profile_picture;
    private $phone;
    private $bio;
    private $created_at;
    private $last_updated;

    /**
     * Constructor
     * @param int $userId Optional user ID to load user data
     */
    public function __construct($userId = null) {
        if ($userId !== null) {
            $this->loadUser($userId);
        }
    }

    /**
     * Load user data from database
     */
    private function loadUser($userId) {
        $sql = "SELECT * FROM users WHERE id = ?";
        $result = mysqli_prepared_query($sql, 'i', [$userId]);

        if (!empty($result)) {
            $row = $result[0];
            $this->id = $row['id'];
            $this->name = $row['name'];
            $this->email = $row['email'];
            $this->password = $row['password'];
            $this->role = $row['role'];
            $this->profile_picture = $row['profile_picture'] ?? '';
            $this->phone = $row['phone'] ?? '';
            $this->bio = $row['bio'] ?? '';
            $this->created_at = $row['created_at'];
            $this->last_updated = $row['last_updated'] ?? $row['created_at'];
            return true;
        }
        return false;
    }

    /**
     * login() - Authenticates user credentials
     * Wraps handle_login() from functions.php
     */
    public function login() {
        return handle_login();
    }

    /**
     * logout() - Ends user session
     * Wraps logout_user() from functions.php
     */
    public function logout() {
        return logout_user();
    }

    /**
     * updateProfile() - Updates user profile information
     * Wraps update_profile() from functions.php
     */
    public function updateProfile() {
        return update_profile();
    }

    /**
     * changePassword() - Changes user password
     * Wraps change_password() from functions.php
     */
    public function changePassword() {
        return change_password();
    }

    /**
     * Upload profile picture
     * Wraps upload_profile_picture() from functions.php
     */
    public function uploadProfilePicture() {
        return upload_profile_picture();
    }

    /**
     * Delete profile picture
     * Wraps delete_profile_picture() from functions.php
     */
    public function deleteProfilePicture() {
        return delete_profile_picture();
    }

    /**
     * Terminate all user sessions
     * Wraps handle_terminate_sessions() from functions.php
     */
    public function terminateAllSessions() {
        return handle_terminate_sessions();
    }

    /**
     * Delete user account
     * Wraps handle_delete_account() from functions.php
     */
    public function deleteAccount() {
        return handle_delete_account();
    }

    /**
     * Get user statistics
     * Wraps get_user_statistics_data() from functions.php
     */
    public function getUserStats() {
        if ($this->id) {
            return get_user_statistics_data($this->id);
        }
        return null;
    }

    /**
     * Export user data
     * Wraps handle_export_user_data() from functions.php
     */
    public function exportUserData() {
        return handle_export_user_data();
    }

    // Getter methods
    public function getId() { return $this->id; }
    public function getName() { return $this->name; }
    public function getEmail() { return $this->email; }
    public function getRole() { return $this->role; }
    public function getProfilePicture() { return $this->profile_picture; }
    public function getPhone() { return $this->phone; }
    public function getBio() { return $this->bio; }
    public function getCreatedAt() { return $this->created_at; }
    public function getLastUpdated() { return $this->last_updated; }

    /**
     * Get user sessions - Relationship: User has 0 to many UserSession instances
     */
    public function getUserSessions() {
        if ($this->email) {
            $sql = "SELECT * FROM user_sessions WHERE email = ? ORDER BY created_at DESC";
            return mysqli_prepared_query($sql, 's', [$this->email]);
        }
        return [];
    }

    /**
     * Get user settings - Relationship: User has 0 to many SystemSettings configurations
     */
    public function getUserSettings() {
        if ($this->id) {
            $settingsObj = new SystemSettings();
            return $settingsObj->getUserSettings($this->id);
        }
        return [];
    }
}

?>
