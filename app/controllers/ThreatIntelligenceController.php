<?php

/**
 * ThreatIntelligenceController Class
 *
 * Purpose: Handles threat intelligence HTTP requests
 * Delegates business logic to ThreatIntelligenceService
 */
class ThreatIntelligenceController {

    private $threatService;

    /**
     * Constructor
     */
    public function __construct() {
        $this->threatService = new ThreatIntelligenceService();
    }

    /**
     * Show threat intelligence page
     *
     * @param array $vars Route variables
     * @return void
     */
    public function show($vars = []) {
        if (!isset($_SESSION['user_id'])) {
            header("Location: " . MDIR . "login");
            exit;
        }
        require 'app/views/pages/threat_intelligence.php';
    }

    /**
     * Get threat feeds
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getThreatFeeds($vars = []) {
        return $this->threatService->getThreatFeeds();
    }

    /**
     * Get threat actors
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getThreatActors($vars = []) {
        return $this->threatService->getThreatActors();
    }

    /**
     * Get Indicators of Compromise (IOCs)
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getIOCs($vars = []) {
        return $this->threatService->getIOCs();
    }

    /**
     * Get vulnerabilities
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getVulnerabilities($vars = []) {
        return $this->threatService->getVulnerabilities();
    }

    /**
     * Block an IOC
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function blockIOC($vars = []) {
        return $this->threatService->blockIOC();
    }

    /**
     * Whitelist an IOC
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function whitelistIOC($vars = []) {
        return $this->threatService->whitelistIOC();
    }
}

?>
