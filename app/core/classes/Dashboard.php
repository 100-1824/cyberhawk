<?php

/**
 * Dashboard Class
 *
 * Purpose: Main user interface for monitoring and management.
 * This class wraps existing dashboard functions from functions.php
 */
class Dashboard {

    /**
     * displayMetrics() - Shows system performance metrics
     * Wraps get_network_statistics() and related functions from functions.php
     *
     * @return array System metrics
     */
    public function displayMetrics() {
        return [
            'network' => $this->getNetworkMetrics(),
            'bandwidth' => $this->getBandwidthData(),
            'protocols' => $this->getProtocolStats(),
            'connections' => $this->getActiveConnections()
        ];
    }

    /**
     * showAlerts() - Displays security alerts
     * Uses Alert class to display alerts
     *
     * @return array Recent alerts
     */
    public function showAlerts() {
        return Alert::getRecentAlerts(20);
    }

    /**
     * manageQuarantine() - Interface for quarantine management
     * Wraps get_quarantine_files() from functions.php
     *
     * @return array Quarantine files
     */
    public function manageQuarantine() {
        return get_quarantine_files();
    }

    /**
     * generateReports() - Creates security reports
     * Wraps report generation functions from functions.php
     *
     * @return array Report data
     */
    public function generateReports() {
        return [
            'reporting_data' => get_reporting_data(),
            'executive_summary' => generate_executive_summary(),
            'threat_timeline' => get_threat_timeline()
        ];
    }

    /**
     * Get network statistics
     * Wraps get_network_statistics() from functions.php
     */
    public function getNetworkStatistics() {
        return get_network_statistics();
    }

    /**
     * Get network metrics
     * Wraps get_network_metrics() from functions.php
     */
    public function getNetworkMetrics() {
        return get_network_metrics();
    }

    /**
     * Get bandwidth data
     * Wraps get_bandwidth_data() from functions.php
     */
    public function getBandwidthData() {
        return get_bandwidth_data();
    }

    /**
     * Get protocol statistics
     * Wraps get_protocol_stats() from functions.php
     */
    public function getProtocolStats() {
        return get_protocol_stats();
    }

    /**
     * Get top talkers
     * Wraps get_top_talkers() from functions.php
     */
    public function getTopTalkers() {
        return get_top_talkers();
    }

    /**
     * Get active connections
     * Wraps get_active_connections() from functions.php
     */
    public function getActiveConnections() {
        return get_active_connections();
    }

    /**
     * Get packet activity
     * Wraps get_packet_activity() from functions.php
     */
    public function getPacketActivity() {
        return get_packet_activity();
    }

    /**
     * Get user statistics
     * Wraps handle_get_user_stats() from functions.php
     */
    public function getUserStats() {
        return handle_get_user_stats();
    }

    /**
     * Get malware statistics
     * Wraps get_malware_stats() from functions.php
     */
    public function getMalwareStats() {
        return get_malware_stats();
    }

    /**
     * Get ransomware statistics
     * Wraps get_ransomware_stats() from functions.php
     */
    public function getRansomwareStats() {
        return get_ransomware_stats();
    }

    /**
     * Get threat feeds
     * Wraps get_threat_feeds() from functions.php
     */
    public function getThreatFeeds() {
        return get_threat_feeds();
    }

    /**
     * Get threat actors
     * Wraps get_threat_actors() from functions.php
     */
    public function getThreatActors() {
        return get_threat_actors();
    }

    /**
     * Get IOCs (Indicators of Compromise)
     * Wraps get_iocs() from functions.php
     */
    public function getIOCs() {
        return get_iocs();
    }

    /**
     * Get vulnerabilities
     * Wraps get_vulnerabilities() from functions.php
     */
    public function getVulnerabilities() {
        return get_vulnerabilities();
    }

    /**
     * Download report
     * Wraps handle_download_report() from functions.php
     */
    public function downloadReport() {
        return handle_download_report();
    }

    /**
     * Export report as PDF
     * Wraps export_report_pdf() from functions.php
     */
    public function exportReportPDF() {
        return export_report_pdf();
    }

    /**
     * Email report
     * Wraps handle_email_report() from functions.php
     */
    public function emailReport() {
        return handle_email_report();
    }

    /**
     * Clear all logs
     * Wraps handle_clear_all_logs() from functions.php
     */
    public function clearAllLogs() {
        return handle_clear_all_logs();
    }

    /**
     * Get comprehensive dashboard data
     *
     * @return array All dashboard data
     */
    public function getDashboardData() {
        return [
            'alerts' => $this->showAlerts(),
            'metrics' => $this->displayMetrics(),
            'malware_stats' => $this->getMalwareStats(),
            'ransomware_stats' => $this->getRansomwareStats(),
            'quarantine' => $this->manageQuarantine(),
            'user_stats' => $this->getUserStats()
        ];
    }
}

?>
