-- ============================================================================
-- CyberHawk Database Schema
-- ============================================================================
-- Project: AI-Powered Intrusion Detection and Prevention System
-- Institution: COMSATS University Islamabad, Wah Campus
-- Authors: M Ahmed (CIIT/SP22-BSE-055/WAH), Hassan Javed (CIIT/SP22-BSE-057/WAH)
-- Supervisor: Dr. Kashif Ayyub
-- Date: November 2025
-- ============================================================================

-- Create database
CREATE DATABASE IF NOT EXISTS `cyberhawk` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `cyberhawk`;

-- ============================================================================
-- USER MANAGEMENT TABLES
-- ============================================================================

-- Users table - Stores user account information
CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL COMMENT 'Full name of the user',
  `email` varchar(255) NOT NULL COMMENT 'Email address (unique login identifier)',
  `password` varchar(255) NOT NULL COMMENT 'Bcrypt hashed password',
  `role` varchar(50) NOT NULL DEFAULT 'user' COMMENT 'User role: admin, user, analyst',
  `profile_picture` varchar(255) DEFAULT NULL COMMENT 'Path to profile picture',
  `phone` varchar(20) DEFAULT NULL COMMENT 'Contact phone number',
  `bio` text DEFAULT NULL COMMENT 'User biography/description',
  `is_verified` tinyint(1) DEFAULT 0 COMMENT 'Email verification status',
  `verification_token` varchar(255) DEFAULT NULL COMMENT 'Email verification token',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp() COMMENT 'Account creation timestamp',
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  KEY `idx_role` (`role`),
  KEY `idx_verified` (`is_verified`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='User accounts and authentication';

-- Roles and Permissions table - Defines role-based access control
CREATE TABLE IF NOT EXISTS `roles_permissions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `role` varchar(50) NOT NULL COMMENT 'Role name: admin, user, analyst',
  `permission` varchar(100) NOT NULL COMMENT 'Permission identifier',
  `description` text DEFAULT NULL COMMENT 'Permission description',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `role_permission` (`role`, `permission`),
  KEY `idx_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Role-based access control';

-- Default permissions
INSERT INTO `roles_permissions` (`role`, `permission`, `description`) VALUES
('admin', 'view_dashboard', 'Access system dashboard'),
('admin', 'manage_users', 'Create, edit, delete users'),
('admin', 'view_ids', 'View intrusion detection logs'),
('admin', 'manage_ids', 'Start/stop IDS monitoring'),
('admin', 'view_malware', 'View malware analysis reports'),
('admin', 'scan_malware', 'Upload and scan files'),
('admin', 'view_ransomware', 'View ransomware detection logs'),
('admin', 'manage_ransomware', 'Configure ransomware protection'),
('admin', 'generate_reports', 'Generate security reports'),
('admin', 'manage_settings', 'Configure system settings'),
('user', 'view_dashboard', 'Access system dashboard'),
('user', 'view_ids', 'View intrusion detection logs'),
('user', 'view_malware', 'View malware analysis reports'),
('user', 'scan_malware', 'Upload and scan files'),
('user', 'view_ransomware', 'View ransomware detection logs'),
('user', 'generate_reports', 'Generate security reports');

-- System Settings table - Stores user-specific and global settings
CREATE TABLE IF NOT EXISTS `system_settings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL COMMENT 'User ID (NULL for global settings)',
  `setting_key` varchar(255) NOT NULL COMMENT 'Setting identifier',
  `setting_value` text DEFAULT NULL COMMENT 'Setting value (JSON supported)',
  `setting_type` varchar(50) DEFAULT 'string' COMMENT 'Data type: string, int, bool, json',
  `description` text DEFAULT NULL COMMENT 'Setting description',
  `is_global` tinyint(1) DEFAULT 0 COMMENT '1 for system-wide settings',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_setting` (`user_id`, `setting_key`),
  KEY `idx_setting_key` (`setting_key`),
  KEY `idx_is_global` (`is_global`),
  FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='User and system settings';

-- Notifications table - Stores in-app notifications
CREATE TABLE IF NOT EXISTS `notifications` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL COMMENT 'Recipient user ID',
  `type` varchar(50) NOT NULL COMMENT 'Notification type: alert, info, warning, success',
  `title` varchar(255) NOT NULL COMMENT 'Notification title',
  `message` text NOT NULL COMMENT 'Notification message',
  `icon` varchar(50) DEFAULT 'bell' COMMENT 'Icon identifier',
  `color` varchar(20) DEFAULT 'primary' COMMENT 'Bootstrap color class',
  `is_read` tinyint(1) DEFAULT 0 COMMENT 'Read status',
  `link` varchar(255) DEFAULT NULL COMMENT 'Optional action link',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_is_read` (`is_read`),
  KEY `idx_created_at` (`created_at`),
  FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='User notifications';

-- ============================================================================
-- INTRUSION DETECTION SYSTEM (IDS) TABLES
-- ============================================================================

-- IDS Alerts table - Stores detected network intrusions
CREATE TABLE IF NOT EXISTS `ids_alerts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `alert_type` varchar(100) NOT NULL COMMENT 'Attack type: DoS, DDoS, Port Scan, Brute Force, etc.',
  `severity` enum('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'medium',
  `source_ip` varchar(45) NOT NULL COMMENT 'Attacker IP address',
  `source_port` int(11) DEFAULT NULL,
  `destination_ip` varchar(45) NOT NULL COMMENT 'Target IP address',
  `destination_port` int(11) DEFAULT NULL,
  `protocol` varchar(20) DEFAULT NULL COMMENT 'TCP, UDP, ICMP, etc.',
  `confidence_score` decimal(5,2) DEFAULT NULL COMMENT 'ML model confidence (0-100)',
  `packet_count` int(11) DEFAULT NULL COMMENT 'Number of packets in flow',
  `byte_count` bigint(20) DEFAULT NULL COMMENT 'Total bytes transferred',
  `flow_duration` decimal(10,3) DEFAULT NULL COMMENT 'Flow duration in seconds',
  `description` text DEFAULT NULL COMMENT 'Detailed alert description',
  `detection_method` varchar(100) DEFAULT 'ml_model' COMMENT 'Detection method: ml_model, signature, anomaly',
  `is_blocked` tinyint(1) DEFAULT 0 COMMENT 'Whether the threat was blocked',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_alert_type` (`alert_type`),
  KEY `idx_severity` (`severity`),
  KEY `idx_source_ip` (`source_ip`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Intrusion detection alerts';

-- Traffic Logs table - Stores network flow data
CREATE TABLE IF NOT EXISTS `traffic_logs` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `flow_id` varchar(64) NOT NULL COMMENT 'Unique flow identifier',
  `source_ip` varchar(45) NOT NULL,
  `source_port` int(11) NOT NULL,
  `destination_ip` varchar(45) NOT NULL,
  `destination_port` int(11) NOT NULL,
  `protocol` varchar(20) NOT NULL COMMENT 'TCP, UDP, ICMP',
  `packet_count` int(11) DEFAULT 0,
  `byte_count` bigint(20) DEFAULT 0,
  `flow_duration` decimal(10,3) DEFAULT 0.000 COMMENT 'Duration in seconds',
  `flags` varchar(50) DEFAULT NULL COMMENT 'TCP flags: SYN, ACK, FIN, etc.',
  `is_anomaly` tinyint(1) DEFAULT 0 COMMENT 'Flagged as anomalous',
  `features_json` text DEFAULT NULL COMMENT 'Extracted ML features (JSON)',
  `timestamp` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `flow_id` (`flow_id`),
  KEY `idx_source_ip` (`source_ip`),
  KEY `idx_protocol` (`protocol`),
  KEY `idx_timestamp` (`timestamp`),
  KEY `idx_is_anomaly` (`is_anomaly`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Network traffic flow logs';

-- ============================================================================
-- MALWARE ANALYSIS TABLES
-- ============================================================================

-- Malware Samples table - Stores uploaded files for analysis
CREATE TABLE IF NOT EXISTS `malware_samples` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL COMMENT 'User who uploaded the sample',
  `filename` varchar(255) NOT NULL COMMENT 'Original filename',
  `file_path` varchar(500) NOT NULL COMMENT 'Storage path on server',
  `file_size` bigint(20) NOT NULL COMMENT 'File size in bytes',
  `file_type` varchar(100) DEFAULT NULL COMMENT 'MIME type',
  `md5_hash` varchar(32) NOT NULL COMMENT 'MD5 checksum',
  `sha1_hash` varchar(40) NOT NULL COMMENT 'SHA-1 checksum',
  `sha256_hash` varchar(64) NOT NULL COMMENT 'SHA-256 checksum',
  `entropy` decimal(5,3) DEFAULT NULL COMMENT 'Shannon entropy score',
  `scan_status` enum('pending', 'scanning', 'completed', 'failed') DEFAULT 'pending',
  `is_malicious` tinyint(1) DEFAULT NULL COMMENT 'Final verdict: 1=malware, 0=clean',
  `threat_level` enum('clean', 'suspicious', 'malicious', 'critical') DEFAULT NULL,
  `uploaded_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `sha256_hash` (`sha256_hash`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_scan_status` (`scan_status`),
  KEY `idx_is_malicious` (`is_malicious`),
  FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Uploaded malware samples';

-- Malware Reports table - Stores analysis results
CREATE TABLE IF NOT EXISTS `malware_reports` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sample_id` int(11) NOT NULL COMMENT 'Reference to malware_samples',
  `virustotal_detections` int(11) DEFAULT NULL COMMENT 'Number of AV engines detecting threat',
  `virustotal_total` int(11) DEFAULT NULL COMMENT 'Total AV engines queried',
  `malware_family` varchar(255) DEFAULT NULL COMMENT 'Identified malware family',
  `threat_names` text DEFAULT NULL COMMENT 'Threat names from different engines (JSON)',
  `behavior_analysis` text DEFAULT NULL COMMENT 'Behavioral analysis results (JSON)',
  `static_analysis` text DEFAULT NULL COMMENT 'Static analysis results (JSON)',
  `api_responses` longtext DEFAULT NULL COMMENT 'Full API responses (JSON)',
  `recommendation` text DEFAULT NULL COMMENT 'Security recommendations',
  `analyzed_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_sample_id` (`sample_id`),
  FOREIGN KEY (`sample_id`) REFERENCES `malware_samples` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Malware analysis reports';

-- ============================================================================
-- RANSOMWARE DETECTION TABLES
-- ============================================================================

-- Ransomware Detections table - Stores ransomware detection events
CREATE TABLE IF NOT EXISTS `ransomware_detections` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `file_path` varchar(500) NOT NULL COMMENT 'Path of detected file',
  `filename` varchar(255) NOT NULL COMMENT 'File name',
  `detection_type` varchar(100) NOT NULL COMMENT 'high_entropy, suspicious_extension, ransom_note',
  `entropy_score` decimal(5,3) DEFAULT NULL COMMENT 'File entropy if applicable',
  `file_extension` varchar(50) DEFAULT NULL COMMENT 'File extension',
  `threat_level` enum('low', 'medium', 'high', 'critical') DEFAULT 'medium',
  `is_quarantined` tinyint(1) DEFAULT 0 COMMENT 'Whether file was quarantined',
  `quarantine_path` varchar(500) DEFAULT NULL COMMENT 'Path in quarantine folder',
  `process_name` varchar(255) DEFAULT NULL COMMENT 'Process that modified the file',
  `process_id` int(11) DEFAULT NULL COMMENT 'PID of the process',
  `details` text DEFAULT NULL COMMENT 'Additional detection details (JSON)',
  `detected_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_detection_type` (`detection_type`),
  KEY `idx_threat_level` (`threat_level`),
  KEY `idx_is_quarantined` (`is_quarantined`),
  KEY `idx_detected_at` (`detected_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Ransomware detection events';

-- Quarantine table - Stores quarantined files
CREATE TABLE IF NOT EXISTS `quarantine_files` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `detection_id` int(11) DEFAULT NULL COMMENT 'Reference to ransomware_detections',
  `original_path` varchar(500) NOT NULL COMMENT 'Original file location',
  `quarantine_path` varchar(500) NOT NULL COMMENT 'Current quarantine location',
  `filename` varchar(255) NOT NULL,
  `file_size` bigint(20) DEFAULT NULL,
  `file_hash` varchar(64) DEFAULT NULL COMMENT 'SHA-256 hash',
  `reason` text DEFAULT NULL COMMENT 'Reason for quarantine',
  `status` enum('quarantined', 'restored', 'deleted') DEFAULT 'quarantined',
  `quarantined_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `restored_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_detection_id` (`detection_id`),
  KEY `idx_status` (`status`),
  FOREIGN KEY (`detection_id`) REFERENCES `ransomware_detections` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Quarantined files';

-- Monitored Paths table - Stores paths being monitored for ransomware
CREATE TABLE IF NOT EXISTS `monitored_paths` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `path` varchar(500) NOT NULL COMMENT 'Directory path to monitor',
  `is_active` tinyint(1) DEFAULT 1 COMMENT 'Monitoring status',
  `priority` enum('low', 'medium', 'high') DEFAULT 'medium' COMMENT 'Monitoring priority',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_is_active` (`is_active`),
  FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Ransomware monitoring paths';

-- ============================================================================
-- REPORTING AND ANALYTICS TABLES
-- ============================================================================

-- Security Reports table - Stores generated reports
CREATE TABLE IF NOT EXISTS `security_reports` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL COMMENT 'User who generated the report',
  `report_type` varchar(100) NOT NULL COMMENT 'executive_summary, detailed_analysis, network_stats',
  `report_title` varchar(255) NOT NULL,
  `date_from` date NOT NULL COMMENT 'Report start date',
  `date_to` date NOT NULL COMMENT 'Report end date',
  `format` varchar(20) DEFAULT 'html' COMMENT 'html, pdf, json',
  `file_path` varchar(500) DEFAULT NULL COMMENT 'Path to generated file',
  `content` longtext DEFAULT NULL COMMENT 'Report content (HTML/JSON)',
  `statistics` text DEFAULT NULL COMMENT 'Report statistics (JSON)',
  `generated_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_report_type` (`report_type`),
  KEY `idx_generated_at` (`generated_at`),
  FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Generated security reports';

-- ============================================================================
-- AUDIT AND LOGGING TABLES
-- ============================================================================

-- Audit Log table - Tracks user actions and system events
CREATE TABLE IF NOT EXISTS `audit_log` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL COMMENT 'User who performed the action',
  `action_type` varchar(100) NOT NULL COMMENT 'login, logout, scan, delete, etc.',
  `action_description` text NOT NULL COMMENT 'Detailed description',
  `ip_address` varchar(45) DEFAULT NULL COMMENT 'User IP address',
  `user_agent` varchar(500) DEFAULT NULL COMMENT 'Browser user agent',
  `resource_type` varchar(100) DEFAULT NULL COMMENT 'Type of resource affected',
  `resource_id` int(11) DEFAULT NULL COMMENT 'ID of affected resource',
  `status` enum('success', 'failed', 'error') DEFAULT 'success',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_action_type` (`action_type`),
  KEY `idx_created_at` (`created_at`),
  FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Audit trail and activity log';

-- ============================================================================
-- ML MODEL MANAGEMENT TABLES
-- ============================================================================

-- ML Models table - Tracks machine learning models
CREATE TABLE IF NOT EXISTS `ml_models` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `model_name` varchar(255) NOT NULL COMMENT 'Model identifier',
  `model_type` varchar(100) NOT NULL COMMENT 'ids, malware, ransomware',
  `model_version` varchar(50) NOT NULL COMMENT 'Version number',
  `algorithm` varchar(100) DEFAULT NULL COMMENT 'DNN, Random Forest, etc.',
  `accuracy` decimal(5,2) DEFAULT NULL COMMENT 'Model accuracy (%)',
  `precision_score` decimal(5,2) DEFAULT NULL,
  `recall_score` decimal(5,2) DEFAULT NULL,
  `f1_score` decimal(5,2) DEFAULT NULL,
  `training_dataset` varchar(255) DEFAULT NULL COMMENT 'Training dataset name',
  `model_path` varchar(500) NOT NULL COMMENT 'Path to model file',
  `is_active` tinyint(1) DEFAULT 0 COMMENT 'Currently active model',
  `training_date` timestamp NOT NULL DEFAULT current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_model_type` (`model_type`),
  KEY `idx_is_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Machine learning models';

-- ============================================================================
-- DEFAULT ADMIN USER
-- ============================================================================

-- Create default admin user
-- Username: admin@cyberhawk.com
-- Password: Admin@123 (should be changed after first login)
-- Password hash generated with: password_hash('Admin@123', PASSWORD_BCRYPT)
INSERT INTO `users` (`name`, `email`, `password`, `role`, `is_verified`) VALUES
('System Administrator', 'admin@cyberhawk.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin', 1);

-- ============================================================================
-- INDEXES FOR PERFORMANCE OPTIMIZATION
-- ============================================================================

-- Additional composite indexes for common queries
CREATE INDEX idx_alert_severity_time ON ids_alerts(severity, created_at);
CREATE INDEX idx_traffic_protocol_time ON traffic_logs(protocol, timestamp);
CREATE INDEX idx_sample_status_user ON malware_samples(scan_status, user_id);
CREATE INDEX idx_detection_level_time ON ransomware_detections(threat_level, detected_at);

-- ============================================================================
-- VIEWS FOR REPORTING
-- ============================================================================

-- View: Recent Security Events (Last 24 hours)
CREATE OR REPLACE VIEW v_recent_security_events AS
SELECT
    'IDS Alert' AS event_type,
    alert_type AS event_name,
    severity,
    source_ip,
    created_at AS event_time
FROM ids_alerts
WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
UNION ALL
SELECT
    'Malware Detection' AS event_type,
    malware_family AS event_name,
    CASE
        WHEN threat_level = 'critical' THEN 'critical'
        WHEN threat_level = 'malicious' THEN 'high'
        WHEN threat_level = 'suspicious' THEN 'medium'
        ELSE 'low'
    END AS severity,
    NULL AS source_ip,
    uploaded_at AS event_time
FROM malware_samples
WHERE uploaded_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    AND is_malicious = 1
UNION ALL
SELECT
    'Ransomware Detection' AS event_type,
    detection_type AS event_name,
    threat_level AS severity,
    NULL AS source_ip,
    detected_at AS event_time
FROM ransomware_detections
WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
ORDER BY event_time DESC;

-- View: Dashboard Statistics
CREATE OR REPLACE VIEW v_dashboard_stats AS
SELECT
    (SELECT COUNT(*) FROM ids_alerts WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) AS alerts_24h,
    (SELECT COUNT(*) FROM malware_samples WHERE is_malicious = 1 AND uploaded_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) AS malware_24h,
    (SELECT COUNT(*) FROM ransomware_detections WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) AS ransomware_24h,
    (SELECT COUNT(*) FROM quarantine_files WHERE status = 'quarantined') AS quarantined_files,
    (SELECT COUNT(*) FROM users) AS total_users,
    (SELECT COUNT(*) FROM traffic_logs WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)) AS traffic_last_hour;

-- ============================================================================
-- STORED PROCEDURES
-- ============================================================================

-- Procedure to clean old logs (keep last 30 days)
DELIMITER $$
CREATE PROCEDURE sp_cleanup_old_logs()
BEGIN
    DELETE FROM traffic_logs WHERE timestamp < DATE_SUB(NOW(), INTERVAL 30 DAY);
    DELETE FROM audit_log WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);
    DELETE FROM ids_alerts WHERE created_at < DATE_SUB(NOW(), INTERVAL 60 DAY);
END$$
DELIMITER ;

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Trigger: Create notification when high-severity alert is detected
DELIMITER $$
CREATE TRIGGER tr_ids_alert_notification
AFTER INSERT ON ids_alerts
FOR EACH ROW
BEGIN
    IF NEW.severity IN ('high', 'critical') THEN
        INSERT INTO notifications (user_id, type, title, message, icon, color)
        SELECT
            id,
            'alert',
            CONCAT('Critical IDS Alert: ', NEW.alert_type),
            CONCAT('Detected attack from ', NEW.source_ip, ' targeting ', NEW.destination_ip),
            'shield-exclamation',
            'danger'
        FROM users WHERE role = 'admin';
    END IF;
END$$
DELIMITER ;

-- Trigger: Create notification when malware is detected
DELIMITER $$
CREATE TRIGGER tr_malware_notification
AFTER UPDATE ON malware_samples
FOR EACH ROW
BEGIN
    IF NEW.is_malicious = 1 AND OLD.is_malicious IS NULL THEN
        INSERT INTO notifications (user_id, type, title, message, icon, color)
        VALUES (
            NEW.user_id,
            'warning',
            'Malware Detected',
            CONCAT('File "', NEW.filename, '" has been identified as malicious'),
            'bug',
            'danger'
        );
    END IF;
END$$
DELIMITER ;

-- ============================================================================
-- GRANTS AND PERMISSIONS
-- ============================================================================

-- Create application user (use in production)
-- CREATE USER 'cyberhawk_app'@'localhost' IDENTIFIED BY 'YourSecurePasswordHere';
-- GRANT SELECT, INSERT, UPDATE, DELETE ON cyberhawk.* TO 'cyberhawk_app'@'localhost';
-- FLUSH PRIVILEGES;

-- ============================================================================
-- DATABASE INITIALIZATION COMPLETE
-- ============================================================================
--
-- Default admin credentials:
-- Email: admin@cyberhawk.com
-- Password: Admin@123
--
-- IMPORTANT: Change the admin password after first login!
--
-- To restore this schema:
-- mysql -u root -p < schema.sql
--
-- ============================================================================
