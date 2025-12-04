<?php

/**
 * NetworkAnalyticsController Class
 *
 * Purpose: Handles network analytics HTTP requests
 * Delegates business logic to NetworkAnalyticsService
 */
class NetworkAnalyticsController {

    private $networkService;

    /**
     * Constructor
     */
    public function __construct() {
        $this->networkService = new NetworkAnalyticsService();
    }

    /**
     * Show network analytics page
     *
     * @param array $vars Route variables
     * @return void
     */
    public function show($vars = []) {
        if (!isset($_SESSION['user_id'])) {
            header("Location: " . MDIR . "login");
            exit;
        }
        require 'app/views/pages/network_analytics.php';
    }

    /**
     * Get network metrics
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getMetrics($vars = []) {
        return $this->networkService->getNetworkMetrics();
    }

    /**
     * Get bandwidth data
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getBandwidthData($vars = []) {
        return $this->networkService->getBandwidthData();
    }

    /**
     * Get protocol statistics
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getProtocolStats($vars = []) {
        return $this->networkService->getProtocolStats();
    }

    /**
     * Get top talkers
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getTopTalkers($vars = []) {
        return $this->networkService->getTopTalkers();
    }

    /**
     * Get active connections
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getActiveConnections($vars = []) {
        return $this->networkService->getActiveConnections();
    }

    /**
     * Get packet activity
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getPacketActivity($vars = []) {
        return $this->networkService->getPacketActivity();
    }
}

?>
