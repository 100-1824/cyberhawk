<?php
/**
 * IP Validation Service
 * Validates IPs against multiple threat intelligence APIs to reduce false positives
 *
 * Supported APIs:
 * - AbuseIPDB
 * - AlienVault OTX
 * - IPQualityScore
 */

class IPValidationService
{
    private $abuseIPDB_key;
    private $alienVault_key;
    private $ipQuality_key;
    private $cacheFile;
    private $cacheExpiry = 3600; // Cache results for 1 hour
    private $cache = [];

    /**
     * Constructor
     */
    public function __construct()
    {
        // Load API keys from settings
        $this->loadAPIKeys();

        // Initialize cache
        $projectDir = rtrim(DIR, '/\\');
        $this->cacheFile = $projectDir . '/assets/data/ip_validation_cache.json';
        $this->loadCache();
    }

    /**
     * Load API keys from database or config
     */
    private function loadAPIKeys()
    {
        // Initialize with default values (will be used if database lookup fails)
        $this->abuseIPDB_key = '856f7c63bf4d0a05daa8a735281b58783d4e2264192b720ed87ba4cb2d4701cdaeb968ee02352465';
        $this->alienVault_key = 'ea8f1f4c26a19094e0e9ce1e4a4c35868bbd8a4167bfa72bad0daac1cef69bc4';
        $this->ipQuality_key = '4wlszArEp8w221zs8pgIf7uZftNKroYH';

        // Try to load from database (system_settings table)
        if (isset($_SESSION['user_id'])) {
            $userId = $_SESSION['user_id'];

            try {
                // Load AbuseIPDB key
                $query = "SELECT setting_value FROM system_settings
                          WHERE user_id = ? AND setting_key = 'abuseipdb_api_key'";
                $result = mysqli_prepared_query($query, 'i', [$userId]);
                if (!empty($result) && !empty($result[0]['setting_value'])) {
                    $this->abuseIPDB_key = $result[0]['setting_value'];
                }

                // Load AlienVault key
                $query = "SELECT setting_value FROM system_settings
                          WHERE user_id = ? AND setting_key = 'alienvault_api_key'";
                $result = mysqli_prepared_query($query, 'i', [$userId]);
                if (!empty($result) && !empty($result[0]['setting_value'])) {
                    $this->alienVault_key = $result[0]['setting_value'];
                }

                // Load IPQualityScore key
                $query = "SELECT setting_value FROM system_settings
                          WHERE user_id = ? AND setting_key = 'ipqualityscore_api_key'";
                $result = mysqli_prepared_query($query, 'i', [$userId]);
                if (!empty($result) && !empty($result[0]['setting_value'])) {
                    $this->ipQuality_key = $result[0]['setting_value'];
                }
            } catch (Exception $e) {
                error_log("Failed to load API keys from database: " . $e->getMessage());
                // Will use default keys initialized above
            }
        }
    }

    /**
     * Load cache from file
     */
    private function loadCache()
    {
        if (file_exists($this->cacheFile)) {
            try {
                $data = json_decode(file_get_contents($this->cacheFile), true);
                if (is_array($data)) {
                    $this->cache = $data;
                }
            } catch (Exception $e) {
                $this->cache = [];
            }
        }
    }

    /**
     * Save cache to file
     */
    private function saveCache()
    {
        try {
            // Ensure directory exists
            $dir = dirname($this->cacheFile);
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
            }

            file_put_contents($this->cacheFile, json_encode($this->cache, JSON_PRETTY_PRINT));
        } catch (Exception $e) {
            error_log("Failed to save IP validation cache: " . $e->getMessage());
        }
    }

    /**
     * Get cached result for an IP
     */
    private function getCachedResult($ip)
    {
        if (isset($this->cache[$ip])) {
            $cached = $this->cache[$ip];

            // Check if cache is still valid
            if (time() - $cached['timestamp'] < $this->cacheExpiry) {
                return $cached['result'];
            }

            // Cache expired, remove it
            unset($this->cache[$ip]);
        }

        return null;
    }

    /**
     * Cache result for an IP
     */
    private function cacheResult($ip, $result)
    {
        $this->cache[$ip] = [
            'timestamp' => time(),
            'result' => $result
        ];

        // Clean old cache entries (older than 24 hours)
        foreach ($this->cache as $cachedIP => $data) {
            if (time() - $data['timestamp'] > 86400) {
                unset($this->cache[$cachedIP]);
            }
        }

        $this->saveCache();
    }

    /**
     * Validate IP using AbuseIPDB
     * Returns: ['is_threat' => bool, 'confidence' => int (0-100), 'source' => string]
     */
    private function checkAbuseIPDB($ip)
    {
        if (empty($this->abuseIPDB_key)) {
            return ['is_threat' => false, 'confidence' => 0, 'source' => 'abuseipdb', 'error' => 'No API key'];
        }

        try {
            $url = "https://api.abuseipdb.com/api/v2/check?ipAddress=" . urlencode($ip);

            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Key: ' . $this->abuseIPDB_key,
                'Accept: application/json'
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200) {
                $data = json_decode($response, true);

                if (isset($data['data'])) {
                    $abuseScore = $data['data']['abuseConfidenceScore'] ?? 0;
                    $isThreat = $abuseScore > 50; // Consider threats with >50% confidence

                    return [
                        'is_threat' => $isThreat,
                        'confidence' => $abuseScore,
                        'source' => 'abuseipdb',
                        'reports' => $data['data']['totalReports'] ?? 0
                    ];
                }
            }

            return ['is_threat' => false, 'confidence' => 0, 'source' => 'abuseipdb', 'error' => 'API error'];

        } catch (Exception $e) {
            error_log("AbuseIPDB check failed for $ip: " . $e->getMessage());
            return ['is_threat' => false, 'confidence' => 0, 'source' => 'abuseipdb', 'error' => $e->getMessage()];
        }
    }

    /**
     * Validate IP using AlienVault OTX
     * Returns: ['is_threat' => bool, 'confidence' => int (0-100), 'source' => string]
     */
    private function checkAlienVault($ip)
    {
        if (empty($this->alienVault_key)) {
            return ['is_threat' => false, 'confidence' => 0, 'source' => 'alienvault', 'error' => 'No API key'];
        }

        try {
            $url = "https://otx.alienvault.com/api/v1/indicators/IPv4/" . urlencode($ip) . "/general";

            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'X-OTX-API-KEY: ' . $this->alienVault_key
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200) {
                $data = json_decode($response, true);

                // Check pulse count and reputation
                $pulseCount = $data['pulse_info']['count'] ?? 0;

                // If IP appears in multiple threat pulses, it's likely malicious
                $isThreat = $pulseCount > 0;
                $confidence = min(100, $pulseCount * 20); // Scale confidence based on pulse count

                return [
                    'is_threat' => $isThreat,
                    'confidence' => $confidence,
                    'source' => 'alienvault',
                    'pulses' => $pulseCount
                ];
            }

            return ['is_threat' => false, 'confidence' => 0, 'source' => 'alienvault', 'error' => 'API error'];

        } catch (Exception $e) {
            error_log("AlienVault check failed for $ip: " . $e->getMessage());
            return ['is_threat' => false, 'confidence' => 0, 'source' => 'alienvault', 'error' => $e->getMessage()];
        }
    }

    /**
     * Validate IP using IPQualityScore
     * Returns: ['is_threat' => bool, 'confidence' => int (0-100), 'source' => string]
     */
    private function checkIPQualityScore($ip)
    {
        if (empty($this->ipQuality_key)) {
            return ['is_threat' => false, 'confidence' => 0, 'source' => 'ipqualityscore', 'error' => 'No API key'];
        }

        try {
            $url = "https://ipqualityscore.com/api/json/ip/" . $this->ipQuality_key . "/" . urlencode($ip);

            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200) {
                $data = json_decode($response, true);

                if (isset($data['fraud_score'])) {
                    $fraudScore = $data['fraud_score'];
                    $isVPN = $data['vpn'] ?? false;
                    $isProxy = $data['proxy'] ?? false;
                    $isTor = $data['tor'] ?? false;
                    $isBot = $data['bot_status'] ?? false;

                    // Consider it a threat if fraud score > 75 or if it's a proxy/VPN/Tor with high fraud
                    $isThreat = $fraudScore > 75 ||
                               (($isVPN || $isProxy || $isTor) && $fraudScore > 50);

                    return [
                        'is_threat' => $isThreat,
                        'confidence' => $fraudScore,
                        'source' => 'ipqualityscore',
                        'vpn' => $isVPN,
                        'proxy' => $isProxy,
                        'tor' => $isTor,
                        'bot' => $isBot
                    ];
                }
            }

            return ['is_threat' => false, 'confidence' => 0, 'source' => 'ipqualityscore', 'error' => 'API error'];

        } catch (Exception $e) {
            error_log("IPQualityScore check failed for $ip: " . $e->getMessage());
            return ['is_threat' => false, 'confidence' => 0, 'source' => 'ipqualityscore', 'error' => $e->getMessage()];
        }
    }

    /**
     * Validate an IP address against all APIs
     * Returns: [
     *   'is_validated' => bool,
     *   'confidence' => int (0-100),
     *   'sources' => array of sources that confirmed the threat,
     *   'details' => array of all API responses
     * ]
     */
    public function validateIP($ip)
    {
        // Skip validation for private IPs
        if ($this->isPrivateIP($ip)) {
            return [
                'is_validated' => true, // Allow private IPs through (they're internal)
                'confidence' => 0,
                'sources' => [],
                'details' => [],
                'note' => 'Private IP - skipped validation'
            ];
        }

        // Check cache first
        $cached = $this->getCachedResult($ip);
        if ($cached !== null) {
            return $cached;
        }

        // Query all APIs in parallel (simulate with sequential for now)
        $results = [];
        $results[] = $this->checkAbuseIPDB($ip);
        $results[] = $this->checkAlienVault($ip);
        $results[] = $this->checkIPQualityScore($ip);

        // Aggregate results
        $confirmedSources = [];
        $totalConfidence = 0;
        $apiCount = 0;

        foreach ($results as $result) {
            if (!isset($result['error'])) {
                $apiCount++;
                if ($result['is_threat']) {
                    $confirmedSources[] = $result['source'];
                    $totalConfidence += $result['confidence'];
                }
            }
        }

        // Calculate average confidence
        $avgConfidence = $apiCount > 0 ? intval($totalConfidence / $apiCount) : 0;

        // Determine if the IP is validated as malicious
        // Require at least ONE API to confirm it as a threat
        $isValidated = count($confirmedSources) > 0;

        $result = [
            'is_validated' => $isValidated,
            'confidence' => $avgConfidence,
            'sources' => $confirmedSources,
            'details' => $results
        ];

        // Cache the result
        $this->cacheResult($ip, $result);

        return $result;
    }

    /**
     * Check if IP is private/internal
     */
    private function isPrivateIP($ip)
    {
        $private_ranges = [
            ['10.0.0.0', '10.255.255.255'],
            ['172.16.0.0', '172.31.255.255'],
            ['192.168.0.0', '192.168.255.255'],
            ['127.0.0.0', '127.255.255.255'],
            ['169.254.0.0', '169.254.255.255']
        ];

        $ip_long = ip2long($ip);
        if ($ip_long === false) {
            return false;
        }

        foreach ($private_ranges as $range) {
            if ($ip_long >= ip2long($range[0]) && $ip_long <= ip2long($range[1])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Validate multiple IPs in batch
     * Returns: array of IP => validation result
     */
    public function validateBatch($ips)
    {
        $results = [];

        foreach ($ips as $ip) {
            $results[$ip] = $this->validateIP($ip);
        }

        return $results;
    }

    /**
     * Clear the validation cache
     */
    public function clearCache()
    {
        $this->cache = [];
        $this->saveCache();
    }
}
