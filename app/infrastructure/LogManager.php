<?php

/**
 * LogManager Class
 *
 * Purpose: Manages traffic logs and log file operations
 * Replaces: areLogsEmpty(), get_traffic_log_json(), clear_traffic_logs() functions
 */
class LogManager {

    private $logFilePath;

    /**
     * Constructor
     */
    public function __construct() {
        $this->logFilePath = DIR . 'assets/data/traffic_log.json';
    }

    /**
     * Check if logs are empty
     *
     * @return bool True if logs are empty, false otherwise
     */
    public function areLogsEmpty() {
        if (!file_exists($this->logFilePath)) {
            return true;
        }

        $content = trim(file_get_contents($this->logFilePath));

        if ($content === '' || $content === '[]') {
            return true;
        }

        $data = json_decode($content, true);
        return empty($data);
    }

    /**
     * Get traffic logs as JSON
     *
     * @return array Traffic log data
     */
    public function getTrafficLogsJson() {
        if (!file_exists($this->logFilePath)) {
            return [];
        }

        $content = file_get_contents($this->logFilePath);
        $data = json_decode($content, true);

        return $data ?: [];
    }

    /**
     * Clear all traffic logs
     *
     * @return bool True on success, false on failure
     */
    public function clearTrafficLogs() {
        return file_put_contents($this->logFilePath, json_encode([])) !== false;
    }

    /**
     * Clear all logs (wrapper for clearTrafficLogs)
     *
     * @return bool True on success, false on failure
     */
    public function clearAllLogs() {
        return $this->clearTrafficLogs();
    }

    /**
     * Write logs to file
     *
     * @param array $data Log data to write
     * @return bool True on success, false on failure
     */
    public function writeLogs($data) {
        return file_put_contents($this->logFilePath, json_encode($data, JSON_PRETTY_PRINT)) !== false;
    }

    /**
     * Append log entry
     *
     * @param array $entry Log entry to append
     * @return bool True on success, false on failure
     */
    public function appendLog($entry) {
        $logs = $this->getTrafficLogsJson();
        $logs[] = $entry;
        return $this->writeLogs($logs);
    }

    /**
     * Get log file path
     *
     * @return string Log file path
     */
    public function getLogFilePath() {
        return $this->logFilePath;
    }
}

?>
