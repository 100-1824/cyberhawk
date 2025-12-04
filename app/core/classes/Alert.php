<?php

/**
 * Alert Class
 *
 * Purpose: Represents a security threat detection alert.
 * This class wraps existing alert functions from functions.php
 */
class Alert {

    // Attributes
    private $id;
    private $timestamp;
    private $srcIP;
    private $attackType;
    private $confidence;
    private $severity;
    private $dstIP;
    private $protocol;
    private $details;

    // Severity constants
    const SEVERITY_CRITICAL = 'critical';
    const SEVERITY_HIGH = 'high';
    const SEVERITY_MEDIUM = 'medium';
    const SEVERITY_LOW = 'low';

    /**
     * Constructor
     * @param int $alertId Optional alert ID to load alert data
     */
    public function __construct($alertId = null) {
        if ($alertId !== null) {
            $this->loadAlert($alertId);
        }
    }

    /**
     * Load alert data from database or JSON file
     */
    private function loadAlert($alertId) {
        // Try loading from database first (if table exists)
        $sql = "SELECT * FROM alerts WHERE id = ?";
        $result = mysqli_prepared_query($sql, 'i', [$alertId]);

        if (!empty($result)) {
            $row = $result[0];
            $this->id = $row['id'];
            $this->timestamp = $row['timestamp'];
            $this->srcIP = $row['src_ip'];
            $this->dstIP = $row['dst_ip'] ?? '';
            $this->attackType = $row['attack_type'];
            $this->confidence = $row['confidence'];
            $this->severity = $row['severity'];
            $this->protocol = $row['protocol'] ?? '';
            $this->details = $row['details'] ?? '';
            return true;
        }
        return false;
    }

    /**
     * generateAlert() - Creates and stores the alert
     *
     * @param array $alertData Alert data (srcIP, attackType, confidence, severity, etc.)
     * @return bool Success status
     */
    public function generateAlert($alertData) {
        $this->srcIP = $alertData['srcIP'] ?? '';
        $this->dstIP = $alertData['dstIP'] ?? '';
        $this->attackType = $alertData['attackType'] ?? '';
        $this->confidence = $alertData['confidence'] ?? 0;
        $this->severity = $alertData['severity'] ?? self::SEVERITY_MEDIUM;
        $this->protocol = $alertData['protocol'] ?? '';
        $this->details = $alertData['details'] ?? '';
        $this->timestamp = date('Y-m-d H:i:s');

        // Save to JSON file (existing behavior)
        $projectDir = rtrim(DIR, '/\\');
        $alertFile = $projectDir . '/assets/data/alert.json';

        $alerts = [];
        if (file_exists($alertFile)) {
            $content = file_get_contents($alertFile);
            $alerts = json_decode($content, true) ?: [];
        }

        $alertEntry = [
            'timestamp' => $this->timestamp,
            'src_ip' => $this->srcIP,
            'dst_ip' => $this->dstIP,
            'attack_type' => $this->attackType,
            'confidence' => $this->confidence,
            'severity' => $this->severity,
            'protocol' => $this->protocol,
            'details' => $this->details
        ];

        $alerts[] = $alertEntry;
        file_put_contents($alertFile, json_encode($alerts, JSON_PRETTY_PRINT));

        // Also try to insert into database if table exists
        $sql = "INSERT INTO alerts (timestamp, src_ip, dst_ip, attack_type, confidence, severity, protocol, details)
                VALUES (NOW(), ?, ?, ?, ?, ?, ?, ?)";
        mysqli_prepared_query($sql, 'sssdsss', [
            $this->srcIP,
            $this->dstIP,
            $this->attackType,
            $this->confidence,
            $this->severity,
            $this->protocol,
            $this->details
        ]);

        return true;
    }

    /**
     * Get validated alerts
     * Wraps get_validated_alerts() from functions.php
     *
     * @return array Array of validated alerts
     */
    public static function getValidatedAlerts() {
        return get_validated_alerts();
    }

    /**
     * Get threat timeline
     * Wraps get_threat_timeline() from functions.php
     *
     * @return array Timeline of threats
     */
    public static function getThreatTimeline() {
        return get_threat_timeline();
    }

    /**
     * Load alerts from JSON file
     *
     * @return array Array of alerts
     */
    public static function loadAlertsFromFile() {
        $projectDir = rtrim(DIR, '/\\');
        $alertFile = $projectDir . '/assets/data/alert.json';

        if (file_exists($alertFile)) {
            $content = file_get_contents($alertFile);
            return json_decode($content, true) ?: [];
        }
        return [];
    }

    /**
     * Get recent alerts
     *
     * @param int $limit Number of alerts to retrieve
     * @return array Array of alerts
     */
    public static function getRecentAlerts($limit = 10) {
        $alerts = self::loadAlertsFromFile();
        return array_slice(array_reverse($alerts), 0, $limit);
    }

    /**
     * Get alerts by severity
     *
     * @param string $severity Severity level
     * @return array Filtered alerts
     */
    public static function getAlertsBySeverity($severity) {
        $alerts = self::loadAlertsFromFile();
        return array_filter($alerts, function($alert) use ($severity) {
            return ($alert['severity'] ?? '') === $severity;
        });
    }

    /**
     * Get alert statistics
     *
     * @return array Statistics array
     */
    public static function getAlertStatistics() {
        $alerts = self::loadAlertsFromFile();

        $stats = [
            'total' => count($alerts),
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0
        ];

        foreach ($alerts as $alert) {
            $severity = $alert['severity'] ?? 'medium';
            if (isset($stats[$severity])) {
                $stats[$severity]++;
            }
        }

        return $stats;
    }

    // Getter methods
    public function getId() { return $this->id; }
    public function getTimestamp() { return $this->timestamp; }
    public function getSrcIP() { return $this->srcIP; }
    public function getDstIP() { return $this->dstIP; }
    public function getAttackType() { return $this->attackType; }
    public function getConfidence() { return $this->confidence; }
    public function getSeverity() { return $this->severity; }
    public function getProtocol() { return $this->protocol; }
    public function getDetails() { return $this->details; }
}

?>
