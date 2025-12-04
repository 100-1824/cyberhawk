<?php

/**
 * ReportingController Class
 *
 * Purpose: Handles reporting and analytics HTTP requests
 * Delegates business logic to ReportingService
 */
class ReportingController {

    private $reportingService;

    /**
     * Constructor
     */
    public function __construct() {
        $this->reportingService = new ReportingService();
    }

    /**
     * Show reporting page
     *
     * @param array $vars Route variables
     * @return void
     */
    public function show($vars = []) {
        if (!isset($_SESSION['user_id'])) {
            header("Location: " . MDIR . "login");
            exit;
        }
        require 'app/views/pages/reporting.php';
    }

    /**
     * Get reporting data
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getData($vars = []) {
        return $this->reportingService->getReportingData();
    }

    /**
     * Generate executive summary
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getExecutiveSummary($vars = []) {
        return $this->reportingService->generateExecutiveSummary();
    }

    /**
     * Get network statistics
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getNetworkStats($vars = []) {
        return $this->reportingService->getNetworkStatistics();
    }

    /**
     * Get threat timeline
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getThreatTimeline($vars = []) {
        return $this->reportingService->getThreatTimeline();
    }

    /**
     * Export report as PDF
     *
     * @param array $vars Route variables
     * @return void PDF file download
     */
    public function exportPDF($vars = []) {
        return $this->reportingService->exportPDF();
    }

    /**
     * Download report
     *
     * @param array $vars Route variables
     * @return void File download
     */
    public function downloadReport($vars = []) {
        return $this->reportingService->downloadReport();
    }

    /**
     * Email report
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function emailReport($vars = []) {
        return $this->reportingService->emailReport();
    }
}

?>
