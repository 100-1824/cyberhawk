<?php

/**
 * DashboardController Class
 *
 * Purpose: Handles dashboard page requests
 */
class DashboardController {

    private $db;

    /**
     * Constructor
     */
    public function __construct() {
        $this->db = new DatabaseHelper();
    }

    /**
     * Show dashboard page
     *
     * @param array $vars Route variables
     * @return void
     */
    public function show($vars = []) {
        if (!isset($_SESSION['user_id'])) {
            header("Location: " . MDIR . "login");
            exit;
        }
        require 'app/views/pages/dashboard.php';
    }

    /**
     * Get dashboard data (API endpoint)
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getData($vars = []) {
        header('Content-Type: application/json');

        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['error' => 1, 'message' => 'Unauthorized']);
            exit;
        }

        $userId = $_SESSION['user_id'];

        // Get user statistics
        $settingsService = new SettingsService();
        $stats = $settingsService->getUserStats($userId);

        echo json_encode(['error' => 0, 'data' => $stats]);
        exit;
    }
}

?>
