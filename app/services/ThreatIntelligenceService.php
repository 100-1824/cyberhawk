<?php

/**
 * ThreatIntelligenceService Class
 *
 * Purpose: Handles threat intelligence feeds, threat actors, IOCs, and vulnerabilities
 * Replaces: get_threat_feeds(), get_threat_actors(), get_iocs(),
 *           get_vulnerabilities(), block_ioc(), whitelist_ioc()
 */
class ThreatIntelligenceService {

    private $db;

    /**
     * Constructor
     */
    public function __construct() {
        $this->db = new DatabaseHelper();
    }

    /**
     * Get threat intelligence feeds
     *
     * @return void JSON response
     */
    public function getThreatFeeds() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $feedsFile = $projectDir . '/assets/data/threat_feeds.json';

        // Load threat feeds from JSON file
        if (file_exists($feedsFile)) {
            $feeds = json_decode(file_get_contents($feedsFile), true);
            echo json_encode($feeds ? $feeds : []);
        } else {
            // Return empty array if file doesn't exist
            echo json_encode([]);
        }
    }

    /**
     * Get threat actors
     *
     * @return void JSON response
     */
    public function getThreatActors() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $actorsFile = $projectDir . '/assets/data/threat_actors.json';

        // Load threat actors from JSON file
        if (file_exists($actorsFile)) {
            $actors = json_decode(file_get_contents($actorsFile), true);
            echo json_encode($actors ? $actors : []);
        } else {
            // Return empty array if file doesn't exist
            echo json_encode([]);
        }
    }

    /**
     * Get Indicators of Compromise (IOCs)
     *
     * @return void JSON response
     */
    public function getIOCs() {
        header('Content-Type: application/json');

        $type = $_GET['type'] ?? 'all'; // all, ip, domain, hash

        $projectDir = rtrim(DIR, '/\\');
        $iocsFile = $projectDir . '/assets/data/iocs.json';

        // Load IOCs from JSON file
        if (file_exists($iocsFile)) {
            $iocs = json_decode(file_get_contents($iocsFile), true);
            if (!$iocs) {
                $iocs = ['ips' => [], 'domains' => [], 'hashes' => []];
            }
        } else {
            $iocs = ['ips' => [], 'domains' => [], 'hashes' => []];
        }

        if ($type === 'all') {
            echo json_encode($iocs);
        } else {
            echo json_encode(isset($iocs[$type . 's']) ? $iocs[$type . 's'] : []);
        }
    }

    /**
     * Get critical vulnerabilities
     *
     * @return void JSON response
     */
    public function getVulnerabilities() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $vulnFile = $projectDir . '/assets/data/vulnerabilities.json';

        // Load vulnerabilities from JSON file
        if (file_exists($vulnFile)) {
            $vulnerabilities = json_decode(file_get_contents($vulnFile), true);
            echo json_encode($vulnerabilities ? $vulnerabilities : []);
        } else {
            // Return empty array if file doesn't exist
            echo json_encode([]);
        }
    }

    /**
     * Block an Indicator of Compromise
     *
     * @return void JSON response
     */
    public function blockIOC() {
        header('Content-Type: application/json');

        $ioc = $_POST['ioc'] ?? '';
        $type = $_POST['type'] ?? 'ip';

        if (empty($ioc)) {
            echo json_encode(['success' => false, 'message' => 'IOC is required']);
            return;
        }

        // Save blocked IOC
        $projectDir = rtrim(DIR, '/\\');
        $blockedFile = $projectDir . '/assets/data/blocked_iocs.json';

        $blocked = file_exists($blockedFile) ? json_decode(file_get_contents($blockedFile), true) : [];

        $blocked[] = [
            'ioc' => $ioc,
            'type' => $type,
            'blockedAt' => date('Y-m-d H:i:s'),
            'reason' => 'User blocked',
            'status' => 'active'
        ];

        file_put_contents($blockedFile, json_encode($blocked, JSON_PRETTY_PRINT));

        echo json_encode(['success' => true, 'message' => "IOC {$ioc} has been blocked"]);
    }

    /**
     * Whitelist an Indicator of Compromise
     *
     * @return void JSON response
     */
    public function whitelistIOC() {
        header('Content-Type: application/json');

        $ioc = $_POST['ioc'] ?? '';

        if (empty($ioc)) {
            echo json_encode(['success' => false, 'message' => 'IOC is required']);
            return;
        }

        $projectDir = rtrim(DIR, '/\\');
        $whitelistFile = $projectDir . '/assets/data/whitelisted_iocs.json';

        $whitelist = file_exists($whitelistFile) ? json_decode(file_get_contents($whitelistFile), true) : [];

        $whitelist[] = [
            'ioc' => $ioc,
            'whitelistedAt' => date('Y-m-d H:i:s'),
            'reason' => 'False positive'
        ];

        file_put_contents($whitelistFile, json_encode($whitelist, JSON_PRETTY_PRINT));

        echo json_encode(['success' => true, 'message' => "IOC {$ioc} has been whitelisted"]);
    }
}

?>
