-- ============================================================================
-- CyberHawk System Settings Table
-- ============================================================================
-- This table stores user-configurable system settings that control
-- CyberHawk's behavior including alert thresholds, timeouts, and preferences.
-- ============================================================================

CREATE TABLE IF NOT EXISTS `system_settings` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `setting_key` VARCHAR(255) NOT NULL,
    `setting_value` TEXT,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY `unique_user_setting` (`user_id`, `setting_key`),
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_setting_key` (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Insert default settings for existing users (optional)
-- ============================================================================
-- Uncomment the lines below if you want to populate default settings
-- for user_id = 1 (change user_id as needed)

-- INSERT INTO `system_settings` (`user_id`, `setting_key`, `setting_value`) VALUES
-- (1, 'alert_threshold', '85'),
-- (1, 'session_timeout', '30'),
-- (1, 'enable_email_alerts', '0'),
-- (1, 'enable_desktop_alerts', '1'),
-- (1, 'log_retention_days', '30'),
-- (1, 'auto_quarantine', '1'),
-- (1, 'scan_on_upload', '1'),
-- (1, 'alert_sound', '0'),
-- (1, 'daily_summary', '0'),
-- (1, 'theme', 'light')
-- ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value);

-- ============================================================================
-- Verify table creation
-- ============================================================================
-- Run this to verify the table was created successfully:
-- SHOW TABLES LIKE 'system_settings';
-- DESCRIBE system_settings;
