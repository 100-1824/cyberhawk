<?php

/**
 * ReportingService Class
 *
 * Purpose: Handles report generation, executive summaries, and export functionality
 * Replaces: get_reporting_data(), generate_executive_summary(), get_network_statistics(),
 *           get_threat_timeline(), export_report_pdf(), handle_download_report(), handle_email_report()
 */
class ReportingService {

    private $db;
    private $emailService;

    /**
     * Constructor
     */
    public function __construct() {
        $this->db = new DatabaseHelper();
        $this->emailService = new EmailService();
    }

    /**
     * Get comprehensive reporting data
     *
     * @return void JSON response
     */
    public function getReportingData() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $dataDir = $projectDir . '/assets/data';

        try {
            $data = [
                'ips_traffic' => $this->loadJsonFile($dataDir . '/traffic_log.json'),
                'alerts' => $this->loadJsonFile($dataDir . '/alerts.json'),
                'ransomware_stats' => $this->loadJsonFile($dataDir . '/ransomware_stats.json'),
                'ransomware_activity' => $this->loadJsonFile($dataDir . '/ransomware_activity.json'),
                'ransomware_threats' => $this->loadJsonFile($dataDir . '/ransomware_threats.json'),
                'malware_stats' => $this->loadJsonFile($dataDir . '/malware_stats.json'),
                'malware_reports' => $this->loadJsonFile($dataDir . '/malware_reports.json'),
                'timestamp' => date('Y-m-d H:i:s')
            ];

            echo json_encode($data);

        } catch (Exception $e) {
            echo json_encode([
                'success' => false,
                'message' => 'Error loading reporting data: ' . $e->getMessage()
            ]);
        }
    }

    /**
     * Generate executive summary report
     *
     * @return void JSON response
     */
    public function generateExecutiveSummary() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $dataDir = $projectDir . '/assets/data';

        try {
            // Load all data sources
            $trafficLog = $this->loadJsonFile($dataDir . '/traffic_log.json');
            $alerts = $this->loadJsonFile($dataDir . '/alerts.json');
            $ransomwareStats = $this->loadJsonFile($dataDir . '/ransomware_stats.json');
            $malwareStats = $this->loadJsonFile($dataDir . '/malware_stats.json');

            // Calculate metrics
            $totalFlows = count($trafficLog);
            $totalAlerts = count($alerts);
            $malwareDetected = $malwareStats['malware_detected'] ?? 0;
            $ransomwareBlocked = $ransomwareStats['threats_detected'] ?? 0;
            $threatRate = $totalFlows > 0 ? ($totalAlerts / $totalFlows) * 100 : 0;

            // Analyze attack types
            $attackTypes = [];
            foreach ($alerts as $alert) {
                $type = $alert['Attack Type'] ?? 'Unknown';
                $attackTypes[$type] = ($attackTypes[$type] ?? 0) + 1;
            }

            // Analyze protocols
            $protocols = [];
            foreach ($trafficLog as $flow) {
                $proto = $this->getProtocolName($flow['Protocol'] ?? 0);
                $protocols[$proto] = ($protocols[$proto] ?? 0) + 1;
            }

            $summary = [
                'success' => true,
                'metrics' => [
                    'total_flows' => $totalFlows,
                    'total_alerts' => $totalAlerts,
                    'malware_detected' => $malwareDetected,
                    'ransomware_blocked' => $ransomwareBlocked,
                    'threat_rate' => round($threatRate, 2)
                ],
                'attack_types' => $attackTypes,
                'protocols' => $protocols,
                'threat_level' => $this->getThreatLevel($threatRate),
                'recommendations' => $this->generateRecommendations($threatRate, $totalAlerts, $malwareDetected),
                'generated_at' => date('Y-m-d H:i:s')
            ];

            echo json_encode($summary);

        } catch (Exception $e) {
            echo json_encode([
                'success' => false,
                'message' => 'Error generating summary: ' . $e->getMessage()
            ]);
        }
    }

    /**
     * Get network statistics for reporting
     *
     * @return void JSON response
     */
    public function getNetworkStatistics() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $trafficLog = $this->loadJsonFile($projectDir . '/assets/data/traffic_log.json');

        try {
            // Calculate statistics
            $totalFlows = count($trafficLog);
            $uniqueSources = [];
            $uniqueDestinations = [];
            $protocols = [];
            $ports = [];

            foreach ($trafficLog as $flow) {
                $uniqueSources[$flow['Src IP'] ?? 'unknown'] = true;
                $uniqueDestinations[$flow['Dst IP'] ?? 'unknown'] = true;

                $proto = $this->getProtocolName($flow['Protocol'] ?? 0);
                $protocols[$proto] = ($protocols[$proto] ?? 0) + 1;

                $dstPort = $flow['Dst Port'] ?? 0;
                $ports[$dstPort] = ($ports[$dstPort] ?? 0) + 1;
            }

            // Get top ports
            arsort($ports);
            $topPorts = array_slice($ports, 0, 10, true);

            $stats = [
                'success' => true,
                'total_flows' => $totalFlows,
                'unique_sources' => count($uniqueSources),
                'unique_destinations' => count($uniqueDestinations),
                'protocols' => $protocols,
                'top_ports' => $topPorts
            ];

            echo json_encode($stats);

        } catch (Exception $e) {
            echo json_encode([
                'success' => false,
                'message' => 'Error calculating statistics: ' . $e->getMessage()
            ]);
        }
    }

    /**
     * Get threat timeline for reporting
     *
     * @return void JSON response
     */
    public function getThreatTimeline() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $alerts = $this->loadJsonFile($projectDir . '/assets/data/alerts.json');

        try {
            // Group alerts by hour
            $timeline = [];

            foreach ($alerts as $alert) {
                $timestamp = $alert['Timestamp'] ?? null;
                if (!$timestamp) continue;

                $hour = date('Y-m-d H:00', strtotime($timestamp));
                $timeline[$hour] = ($timeline[$hour] ?? 0) + 1;
            }

            ksort($timeline);

            echo json_encode([
                'success' => true,
                'timeline' => $timeline
            ]);

        } catch (Exception $e) {
            echo json_encode([
                'success' => false,
                'message' => 'Error generating timeline: ' . $e->getMessage()
            ]);
        }
    }

    /**
     * Export report as PDF (uses browser print-to-PDF)
     *
     * @return void JSON response
     */
    public function exportPDF() {
        header('Content-Type: application/json');

        echo json_encode([
            'success' => false,
            'message' => 'Please use the Print to PDF feature in your browser for PDF export.'
        ]);
    }

    /**
     * Download report
     *
     * @return void JSON response or file download
     */
    public function downloadReport() {
        if (session_status() === PHP_SESSION_NONE) session_start();

        header('Content-Type: application/json');

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            echo json_encode(['success' => false, 'message' => 'Invalid request method']);
            exit;
        }

        $userId = $_SESSION['user_id'] ?? null;
        $reportType = $_POST['report_type'] ?? '';
        $reportData = $_POST['report_data'] ?? '';

        if (empty($reportType) || empty($reportData)) {
            echo json_encode(['success' => false, 'message' => 'Report type and data are required']);
            exit;
        }

        try {
            $filename = 'cyberhawk_' . $reportType . '_' . date('Y-m-d_His') . '.json';
            $filepath = DIR . 'assets/data/reports/' . $filename;

            // Create reports directory if it doesn't exist
            if (!is_dir(DIR . 'assets/data/reports')) {
                mkdir(DIR . 'assets/data/reports', 0755, true);
            }

            file_put_contents($filepath, $reportData);

            // Return download URL
            echo json_encode([
                'success' => true,
                'message' => 'Report generated successfully',
                'download_url' => MDIR . 'assets/data/reports/' . $filename,
                'filename' => $filename
            ]);

        } catch (Exception $e) {
            echo json_encode([
                'success' => false,
                'message' => 'Error generating report: ' . $e->getMessage()
            ]);
        }
    }

    /**
     * Email report to user
     *
     * @return void JSON response
     */
    public function emailReport() {
        if (session_status() === PHP_SESSION_NONE) session_start();

        header('Content-Type: application/json');

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            echo json_encode(['success' => false, 'message' => 'Invalid request method']);
            exit;
        }

        $userId = $_SESSION['user_id'] ?? null;
        $email = $_POST['email'] ?? '';
        $reportType = $_POST['report_type'] ?? '';
        $reportData = $_POST['report_data'] ?? '';

        if (empty($email) || empty($reportType) || empty($reportData)) {
            echo json_encode(['success' => false, 'message' => 'Email, report type, and data are required']);
            exit;
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            echo json_encode(['success' => false, 'message' => 'Invalid email address']);
            exit;
        }

        try {
            // Get user name
            $userName = $_SESSION['user_name'] ?? 'CyberHawk User';

            // Create email body
            $subject = 'CyberHawk Security Report - ' . ucfirst($reportType);
            $body = "
                <h2>CyberHawk Security Report</h2>
                <p>Hello <strong>$userName</strong>,</p>
                <p>Your requested <strong>" . ucfirst($reportType) . " Report</strong> is attached below.</p>
                <h3>Report Summary:</h3>
                <pre style='background-color: #f5f5f5; padding: 15px; border-radius: 5px;'>$reportData</pre>
                <p>Generated on: " . date('Y-m-d H:i:s') . "</p>
                <hr>
                <p><small>This is an automated report from CyberHawk IDS.</small></p>
            ";

            // Send email
            $sent = $this->emailService->sendEmail($email, $userName, $subject, $body);

            if ($sent) {
                echo json_encode([
                    'success' => true,
                    'message' => 'Report sent successfully to ' . $email
                ]);
            } else {
                echo json_encode([
                    'success' => false,
                    'message' => 'Failed to send email. Please try again.'
                ]);
            }

        } catch (Exception $e) {
            echo json_encode([
                'success' => false,
                'message' => 'Error sending email: ' . $e->getMessage()
            ]);
        }
    }

    // ==================== PRIVATE HELPER METHODS ====================

    /**
     * Load JSON file
     *
     * @param string $filePath Path to JSON file
     * @return array JSON data as array
     */
    private function loadJsonFile($filePath) {
        if (!file_exists($filePath)) {
            return [];
        }

        try {
            $content = file_get_contents($filePath);
            if (empty($content)) {
                return [];
            }

            $data = json_decode($content, true);
            return is_array($data) ? $data : [];

        } catch (Exception $e) {
            return [];
        }
    }

    /**
     * Get protocol name from protocol number
     *
     * @param int $proto Protocol number
     * @return string Protocol name
     */
    private function getProtocolName($proto) {
        $proto = (int)$proto;

        switch ($proto) {
            case 6:
                return 'TCP';
            case 17:
                return 'UDP';
            case 1:
                return 'ICMP';
            default:
                return 'Other';
        }
    }

    /**
     * Determine threat level
     *
     * @param float $threatRate Threat rate percentage
     * @return array Threat level information
     */
    private function getThreatLevel($threatRate) {
        if ($threatRate > 10) {
            return [
                'level' => 'HIGH',
                'color' => 'danger',
                'message' => 'Significant threat activity detected. Immediate action recommended.'
            ];
        } elseif ($threatRate > 5) {
            return [
                'level' => 'MEDIUM',
                'color' => 'warning',
                'message' => 'Moderate threat activity. Continue monitoring.'
            ];
        } else {
            return [
                'level' => 'LOW',
                'color' => 'success',
                'message' => 'Security posture is good. Maintain current practices.'
            ];
        }
    }

    /**
     * Generate security recommendations
     *
     * @param float $threatRate Threat rate percentage
     * @param int $alertCount Number of alerts
     * @param int $malwareCount Number of malware detections
     * @return array List of recommendations
     */
    private function generateRecommendations($threatRate, $alertCount, $malwareCount) {
        $recommendations = [];

        if ($threatRate > 10) {
            $recommendations[] = "Implement stricter firewall rules to reduce attack surface";
            $recommendations[] = "Review and update intrusion detection signatures";
            $recommendations[] = "Consider enabling additional security modules";
        }

        if ($alertCount > 50) {
            $recommendations[] = "High alert volume detected - review alert thresholds";
            $recommendations[] = "Investigate top source IPs for potential false positives";
        }

        if ($malwareCount > 0) {
            $recommendations[] = "Malware detected - ensure all systems are updated";
            $recommendations[] = "Run full system scans on affected endpoints";
            $recommendations[] = "Review and update anti-malware signatures";
        }

        if (empty($recommendations)) {
            $recommendations[] = "Continue monitoring - no critical issues detected";
            $recommendations[] = "Maintain regular backup schedules";
            $recommendations[] = "Keep security software up to date";
        }

        return $recommendations;
    }
}

?>
