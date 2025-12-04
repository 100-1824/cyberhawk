<?php

/**
 * NetworkAnalyticsService Class
 *
 * Purpose: Handles network traffic analysis, metrics, bandwidth monitoring, and connection tracking
 * Replaces: get_network_metrics(), get_bandwidth_data(), get_protocol_stats(),
 *           get_top_talkers(), get_active_connections(), get_packet_activity()
 */
class NetworkAnalyticsService {

    private $db;
    private $logManager;

    /**
     * Constructor
     */
    public function __construct() {
        $this->db = new DatabaseHelper();
        $this->logManager = new LogManager();
    }

    /**
     * Get network metrics
     *
     * @return void JSON response
     */
    public function getNetworkMetrics() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $trafficFile = $projectDir . '/assets/data/traffic_log.json';

        $metrics = [
            'totalPackets' => 0,
            'activeFlows' => 0,
            'totalBandwidth' => 0,
            'avgLatency' => 0
        ];

        if (file_exists($trafficFile)) {
            $flows = json_decode(file_get_contents($trafficFile), true);

            if (is_array($flows)) {
                $metrics['totalPackets'] = count($flows);
                $metrics['activeFlows'] = count(array_unique(array_column($flows, 'Flow ID')));
                $metrics['totalBandwidth'] = array_sum(array_column($flows, 'Total Length of Fwd Packets')) / 1000000;

                $latencies = array_column($flows, 'Flow Duration');
                $metrics['avgLatency'] = !empty($latencies) ? array_sum($latencies) / count($latencies) : 0;
            }
        }

        echo json_encode($metrics);
    }

    /**
     * Get bandwidth data
     *
     * @return void JSON response
     */
    public function getBandwidthData() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $bandwidthFile = $projectDir . '/assets/data/network_bandwidth.json';

        // Load bandwidth data from JSON file
        if (file_exists($bandwidthFile)) {
            $data = json_decode(file_get_contents($bandwidthFile), true);
            if (!$data) {
                $data = ['labels' => [], 'upload' => [], 'download' => []];
            }
        } else {
            $data = ['labels' => [], 'upload' => [], 'download' => []];
        }

        echo json_encode($data);
    }

    /**
     * Get protocol statistics
     *
     * @return void JSON response
     */
    public function getProtocolStats() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $protocolsFile = $projectDir . '/assets/data/network_protocols.json';

        // Load protocol stats from JSON file
        if (file_exists($protocolsFile)) {
            $protocols = json_decode(file_get_contents($protocolsFile), true);
            if (!$protocols) {
                $protocols = ['TCP' => 0, 'UDP' => 0, 'ICMP' => 0, 'Other' => 0];
            }
        } else {
            $protocols = ['TCP' => 0, 'UDP' => 0, 'ICMP' => 0, 'Other' => 0];
        }

        echo json_encode($protocols);
    }

    /**
     * Get top talkers (hosts with most traffic)
     *
     * @return void JSON response
     */
    public function getTopTalkers() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $talkersFile = $projectDir . '/assets/data/network_talkers.json';

        // Load top talkers from JSON file
        if (file_exists($talkersFile)) {
            $talkers = json_decode(file_get_contents($talkersFile), true);
            echo json_encode($talkers ? $talkers : []);
        } else {
            echo json_encode([]);
        }
    }

    /**
     * Get active network connections
     *
     * @return void JSON response
     */
    public function getActiveConnections() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $connectionsFile = $projectDir . '/assets/data/network_connections.json';

        // Load active connections from JSON file
        if (file_exists($connectionsFile)) {
            $connections = json_decode(file_get_contents($connectionsFile), true);
            echo json_encode($connections ? $connections : []);
        } else {
            echo json_encode([]);
        }
    }

    /**
     * Get packet activity
     *
     * @return void JSON response
     */
    public function getPacketActivity() {
        header('Content-Type: application/json');

        $projectDir = rtrim(DIR, '/\\');
        $packetsFile = $projectDir . '/assets/data/network_packets.json';

        // Load packet activity from JSON file
        if (file_exists($packetsFile)) {
            $packets = json_decode(file_get_contents($packetsFile), true);
            echo json_encode($packets ? $packets : []);
        } else {
            echo json_encode([]);
        }
    }
}

?>
