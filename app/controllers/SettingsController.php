<?php

/**
 * SettingsController Class
 *
 * Purpose: Handles settings management HTTP requests
 * Delegates business logic to SettingsService
 */
class SettingsController {

    private $settingsService;

    /**
     * Constructor
     */
    public function __construct() {
        $this->settingsService = new SettingsService();
    }

    /**
     * Show settings page
     *
     * @param array $vars Route variables
     * @return void
     */
    public function show($vars = []) {
        if (!isset($_SESSION['user_id'])) {
            header("Location: " . MDIR . "login");
            exit;
        }
        require 'app/views/pages/settings.php';
    }

    /**
     * Save settings
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function saveSettings($vars = []) {
        return $this->settingsService->saveSettings();
    }

    /**
     * Save API keys
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function saveApiKeys($vars = []) {
        return $this->settingsService->saveApiKeys();
    }

    /**
     * Get user statistics
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getUserStats($vars = []) {
        header('Content-Type: application/json');

        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['error' => 1, 'message' => 'Unauthorized']);
            exit;
        }

        $userId = $_SESSION['user_id'];
        $stats = $this->settingsService->getUserStats($userId);

        echo json_encode(['error' => 0, 'data' => $stats]);
        exit;
    }
}

?>
