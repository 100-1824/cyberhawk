-- ============================================================================
-- CyberHawk Database Initialization Script
-- ============================================================================
-- This script creates all necessary tables for the CyberHawk application
-- ============================================================================

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";

-- ============================================================================
-- Users Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('user','admin') DEFAULT 'user',
  `is_verified` tinyint(1) DEFAULT 0,
  `verification_token` varchar(255) DEFAULT NULL,
  `reset_token` varchar(255) DEFAULT NULL,
  `reset_token_expiry` datetime DEFAULT NULL,
  `profile_picture` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- Sessions Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS `sessions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `session_token` varchar(255) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `expires_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `sessions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- Notifications Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS `notifications` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `type` enum('info','warning','danger','success') DEFAULT 'info',
  `is_read` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `notifications_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- System Settings Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS `system_settings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `setting_key` varchar(100) NOT NULL,
  `setting_value` text,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `setting_key` (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- Threat Logs Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS `threat_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL,
  `threat_type` varchar(50) NOT NULL,
  `severity` enum('low','medium','high','critical') DEFAULT 'medium',
  `source_ip` varchar(45) DEFAULT NULL,
  `destination_ip` varchar(45) DEFAULT NULL,
  `description` text,
  `status` enum('detected','blocked','resolved') DEFAULT 'detected',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `threat_logs_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- Malware Scans Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS `malware_scans` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL,
  `file_name` varchar(255) NOT NULL,
  `file_hash` varchar(64) NOT NULL,
  `file_size` bigint(20) DEFAULT NULL,
  `scan_result` enum('clean','suspicious','malicious') DEFAULT 'clean',
  `threat_name` varchar(100) DEFAULT NULL,
  `scan_details` text,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `malware_scans_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- Reports Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS `reports` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL,
  `report_type` varchar(50) NOT NULL,
  `report_data` longtext,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `reports_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- Create Default Admin User
-- ============================================================================
-- Password: admin@123 (hashed with bcrypt)
INSERT INTO `users` (`name`, `email`, `password`, `role`, `is_verified`, `created_at`) 
VALUES (
    'Administrator',
    'admin@gmail.com',
    '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
    'admin',
    1,
    NOW()
) ON DUPLICATE KEY UPDATE role = 'admin', is_verified = 1;

-- ============================================================================
-- Insert Default System Settings
-- ============================================================================
INSERT INTO `system_settings` (`setting_key`, `setting_value`) VALUES
('app_name', 'CyberHawk'),
('app_version', '1.0.0'),
('email_notifications', 'true'),
('threat_auto_block', 'false'),
('scan_on_upload', 'true')
ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value);

-- ============================================================================
-- Done
-- ============================================================================
