<?php

/**
 * RansomwareController Class
 *
 * Purpose: Handles ransomware protection related HTTP requests
 * Delegates business logic to RansomwareService
 */
class RansomwareController {

    private $ransomwareService;

    /**
     * Constructor
     */
    public function __construct() {
        $this->ransomwareService = new RansomwareService();
    }

    /**
     * Show ransomware page
     *
     * @param array $vars Route variables
     * @return void
     */
    public function show($vars = []) {
        if (!isset($_SESSION['user_id'])) {
            header("Location: " . MDIR . "login");
            exit;
        }
        require 'app/views/pages/ransomware.php';
    }

    /**
     * Start ransomware monitor
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function startMonitor($vars = []) {
        return $this->ransomwareService->startMonitor();
    }

    /**
     * Stop ransomware monitor
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function stopMonitor($vars = []) {
        return $this->ransomwareService->stopMonitor();
    }

    /**
     * Get monitor status
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getStatus($vars = []) {
        return $this->ransomwareService->getStatus();
    }

    /**
     * Get ransomware activity
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getActivity($vars = []) {
        return $this->ransomwareService->getActivity();
    }

    /**
     * Get ransomware statistics
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getStats($vars = []) {
        return $this->ransomwareService->getStats();
    }

    /**
     * Check ransomware threats
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function checkThreats($vars = []) {
        return $this->ransomwareService->checkThreats();
    }

    /**
     * Get quarantined files
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getQuarantineFiles($vars = []) {
        return $this->ransomwareService->getQuarantineFiles();
    }

    /**
     * Get scan progress
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getScanProgress($vars = []) {
        return $this->ransomwareService->getScanProgress();
    }

    /**
     * Start full scan
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function startFullScan($vars = []) {
        return $this->ransomwareService->startFullScan();
    }

    /**
     * Start quick scan
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function startQuickScan($vars = []) {
        return $this->ransomwareService->startQuickScan();
    }

    /**
     * Isolate threats
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function isolateThreats($vars = []) {
        return $this->ransomwareService->isolateThreats();
    }

    /**
     * Restore quarantined file
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function restoreFile($vars = []) {
        return $this->ransomwareService->restoreFile();
    }

    /**
     * Delete quarantined file
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function deleteFile($vars = []) {
        return $this->ransomwareService->deleteFile();
    }

    /**
     * Update signatures
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function updateSignatures($vars = []) {
        return $this->ransomwareService->updateSignatures();
    }

    /**
     * Restore backup
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function restoreBackup($vars = []) {
        return $this->ransomwareService->restoreBackup();
    }
}

?>
