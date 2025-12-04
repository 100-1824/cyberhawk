<?php

/**
 * SystemSettings Class
 *
 * Purpose: Stores user-specific or system-wide configuration settings.
 * This class wraps existing settings functions from functions.php
 */
class SystemSettings {

    // Attributes
    private $id;
    private $user_id;
    private $setting_key;
    private $setting_value;
    private $updated_at;

    /**
     * Constructor
     * @param int $settingId Optional setting ID to load specific setting
     */
    public function __construct($settingId = null) {
        if ($settingId !== null) {
            $this->loadSetting($settingId);
        }
    }

    /**
     * Load setting data from database
     */
    private function loadSetting($settingId) {
        $sql = "SELECT * FROM system_settings WHERE id = ?";
        $result = mysqli_prepared_query($sql, 'i', [$settingId]);

        if (!empty($result)) {
            $row = $result[0];
            $this->id = $row['id'];
            $this->user_id = $row['user_id'];
            $this->setting_key = $row['setting_key'];
            $this->setting_value = $row['setting_value'];
            $this->updated_at = $row['updated_at'];
            return true;
        }
        return false;
    }

    /**
     * updateSetting() - Modifies setting value
     * Wraps the logic from handle_save_settings() in functions.php
     *
     * @param int $userId User ID
     * @param string $key Setting key
     * @param string $value Setting value
     * @return bool Success status
     */
    public function updateSetting($userId, $key, $value) {
        // Check if setting exists
        $checkSql = "SELECT id FROM system_settings WHERE user_id = ? AND setting_key = ?";
        $existing = mysqli_prepared_query($checkSql, 'is', [$userId, $key]);

        if (!empty($existing)) {
            // Update existing
            $updateSql = "UPDATE system_settings SET setting_value = ?, updated_at = NOW() WHERE user_id = ? AND setting_key = ?";
            return mysqli_prepared_query($updateSql, 'sis', [$value, $userId, $key]) !== false;
        } else {
            // Insert new
            $insertSql = "INSERT INTO system_settings (user_id, setting_key, setting_value) VALUES (?, ?, ?)";
            return mysqli_prepared_query($insertSql, 'iss', [$userId, $key, $value]) !== false;
        }
    }

    /**
     * getSetting() - Retrieves setting value
     *
     * @param int $userId User ID
     * @param string $key Setting key
     * @param string $defaultValue Default value if not found
     * @return string Setting value or default
     */
    public function getSetting($userId, $key, $defaultValue = null) {
        $sql = "SELECT setting_value FROM system_settings WHERE user_id = ? AND setting_key = ?";
        $result = mysqli_prepared_query($sql, 'is', [$userId, $key]);

        if (!empty($result)) {
            return $result[0]['setting_value'];
        }
        return $defaultValue;
    }

    /**
     * Get all settings for a user
     *
     * @param int $userId User ID
     * @return array Associative array of settings
     */
    public function getUserSettings($userId) {
        $sql = "SELECT setting_key, setting_value FROM system_settings WHERE user_id = ?";
        $result = mysqli_prepared_query($sql, 'i', [$userId]);

        $settings = [];
        if (!empty($result)) {
            foreach ($result as $row) {
                $settings[$row['setting_key']] = $row['setting_value'];
            }
        }
        return $settings;
    }

    /**
     * Save multiple settings
     * Wraps handle_save_settings() from functions.php
     */
    public static function saveSettings() {
        return handle_save_settings();
    }

    /**
     * Save API keys
     * Wraps handle_save_api_keys() from functions.php
     */
    public static function saveApiKeys() {
        return handle_save_api_keys();
    }

    /**
     * Export user settings as JSON
     *
     * @param int $userId User ID
     * @return string JSON encoded settings
     */
    public function exportSettings($userId) {
        $settings = $this->getUserSettings($userId);
        return json_encode($settings, JSON_PRETTY_PRINT);
    }

    // Getter methods
    public function getId() { return $this->id; }
    public function getUserId() { return $this->user_id; }
    public function getSettingKey() { return $this->setting_key; }
    public function getSettingValue() { return $this->setting_value; }
    public function getUpdatedAt() { return $this->updated_at; }
}

?>
