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
     * Uses Python script to block IP via null routing and hosts file
     *
     * @return void JSON response
     */
    public function blockIOC() {
        header('Content-Type: application/json');

        $ioc = $_POST['ioc'] ?? '';
        $type = $_POST['type'] ?? 'ip';
        $reason = $_POST['reason'] ?? 'User blocked via Threat Intelligence';

        if (empty($ioc)) {
            echo json_encode(['success' => false, 'message' => 'IOC is required']);
            return;
        }

        $projectDir = rtrim(DIR, '/\\');
        
        // For IP type, use the Python blocker script
        if ($type === 'ip') {
            $pythonScript = $projectDir . '/app/scripts/ip_blocker.py';
            $pythonPath = $projectDir . '/fyp/Scripts/python.exe';
            
            // Fallback to system python if venv python doesn't exist
            if (!file_exists($pythonPath)) {
                $pythonPath = 'python';
            }
            
            // Escape the IP and reason for shell
            $escapedIoc = escapeshellarg($ioc);
            $escapedReason = escapeshellarg($reason);
            
            // Execute the Python script
            $command = "\"{$pythonPath}\" \"{$pythonScript}\" block --ip {$escapedIoc} --reason {$escapedReason} --json 2>&1";
            $output = shell_exec($command);
            
            // Parse the JSON response from Python
            $result = json_decode($output, true);
            
            if ($result && isset($result['success']) && $result['success']) {
                // Also save to blocked_iocs.json for tracking
                $blockedFile = $projectDir . '/assets/data/blocked_iocs.json';
                $blocked = file_exists($blockedFile) ? json_decode(file_get_contents($blockedFile), true) : [];
                
                // Check if already in the list
                $alreadyBlocked = false;
                foreach ($blocked as $item) {
                    if ($item['ioc'] === $ioc) {
                        $alreadyBlocked = true;
                        break;
                    }
                }
                
                if (!$alreadyBlocked) {
                    $blocked[] = [
                        'ioc' => $ioc,
                        'type' => $type,
                        'blockedAt' => date('Y-m-d H:i:s'),
                        'reason' => $reason,
                        'status' => 'active',
                        'systemBlocked' => true,
                        'methods' => $result['methods'] ?? []
                    ];
                    file_put_contents($blockedFile, json_encode($blocked, JSON_PRETTY_PRINT));
                }
                
                echo json_encode([
                    'success' => true, 
                    'message' => "IP {$ioc} has been blocked at system level",
                    'details' => $result
                ]);
            } else {
                // If Python script failed, still save to JSON but mark as not system blocked
                $blockedFile = $projectDir . '/assets/data/blocked_iocs.json';
                $blocked = file_exists($blockedFile) ? json_decode(file_get_contents($blockedFile), true) : [];
                
                $blocked[] = [
                    'ioc' => $ioc,
                    'type' => $type,
                    'blockedAt' => date('Y-m-d H:i:s'),
                    'reason' => $reason,
                    'status' => 'pending',
                    'systemBlocked' => false,
                    'error' => $result['error'] ?? $output ?? 'Unknown error'
                ];
                file_put_contents($blockedFile, json_encode($blocked, JSON_PRETTY_PRINT));
                
                echo json_encode([
                    'success' => false, 
                    'message' => "Failed to block IP at system level. Saved for manual blocking.",
                    'error' => $result['error'] ?? $output ?? 'Unknown error',
                    'note' => 'Run XAMPP/Apache as Administrator to enable system-level IP blocking'
                ]);
            }
        } else {
            // For non-IP types (domains, hashes), just save to JSON
            $blockedFile = $projectDir . '/assets/data/blocked_iocs.json';
            $blocked = file_exists($blockedFile) ? json_decode(file_get_contents($blockedFile), true) : [];
            
            $blocked[] = [
                'ioc' => $ioc,
                'type' => $type,
                'blockedAt' => date('Y-m-d H:i:s'),
                'reason' => $reason,
                'status' => 'active'
            ];
            
            file_put_contents($blockedFile, json_encode($blocked, JSON_PRETTY_PRINT));
            echo json_encode(['success' => true, 'message' => "IOC {$ioc} has been blocked"]);
        }
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

    /**
     * Unblock an Indicator of Compromise
     * Uses Python script to remove null route and hosts file entry
     *
     * @return void JSON response
     */
    public function unblockIOC() {
        header('Content-Type: application/json');

        $ioc = $_POST['ioc'] ?? '';

        if (empty($ioc)) {
            echo json_encode(['success' => false, 'message' => 'IOC is required']);
            return;
        }

        $projectDir = rtrim(DIR, '/\\');
        $pythonScript = $projectDir . '/app/scripts/ip_blocker.py';
        $pythonPath = $projectDir . '/fyp/Scripts/python.exe';
        
        // Fallback to system python if venv python doesn't exist
        if (!file_exists($pythonPath)) {
            $pythonPath = 'python';
        }
        
        // Execute unblock command
        $escapedIoc = escapeshellarg($ioc);
        $command = "\"{$pythonPath}\" \"{$pythonScript}\" unblock --ip {$escapedIoc} --json 2>&1";
        $output = shell_exec($command);
        
        $result = json_decode($output, true);
        
        // Remove from blocked_iocs.json
        $blockedFile = $projectDir . '/assets/data/blocked_iocs.json';
        if (file_exists($blockedFile)) {
            $blocked = json_decode(file_get_contents($blockedFile), true);
            $blocked = array_filter($blocked, function($item) use ($ioc) {
                return $item['ioc'] !== $ioc;
            });
            file_put_contents($blockedFile, json_encode(array_values($blocked), JSON_PRETTY_PRINT));
        }
        
        echo json_encode([
            'success' => true, 
            'message' => "IP {$ioc} has been unblocked",
            'details' => $result
        ]);
    }

    /**
     * Get all blocked IOCs
     *
     * @return void JSON response
     */
    public function getBlockedIOCs() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $blockedFile = $projectDir . '/assets/data/blocked_iocs.json';

        if (file_exists($blockedFile)) {
            $blocked = json_decode(file_get_contents($blockedFile), true);
            echo json_encode(['success' => true, 'blocked' => $blocked ? $blocked : []]);
        } else {
            echo json_encode(['success' => true, 'blocked' => []]);
        }
    }
}

?>
