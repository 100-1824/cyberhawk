-- ============================================================================
-- CyberHawk Admin User Setup
-- ============================================================================
-- Run this SQL to create the admin user for the CyberHawk admin panel.
-- Credentials: admin@gmail.com / admin@123
-- ============================================================================

-- Create admin user
-- Password is hashed using PHP's password_hash with PASSWORD_DEFAULT
-- The password 'admin@123' hashes to the value below
INSERT INTO `users` (`name`, `email`, `password`, `role`, `is_verified`, `created_at`) 
VALUES (
    'Administrator',
    'admin@gmail.com',
    '$2y$10$YourHashedPasswordHere',
    'admin',
    1,
    NOW()
) ON DUPLICATE KEY UPDATE role = 'admin', is_verified = 1;

-- ============================================================================
-- IMPORTANT: The password hash above is a placeholder!
-- ============================================================================
-- You need to generate the correct hash for 'admin@123' using PHP:
-- 
-- Run this PHP code to get the correct hash:
-- <?php echo password_hash('admin@123', PASSWORD_DEFAULT); ?>
--
-- OR run this command:
-- php -r "echo password_hash('admin@123', PASSWORD_DEFAULT) . PHP_EOL;"
--
-- Then replace '$2y$10$YourHashedPasswordHere' with the generated hash.
-- ============================================================================

-- Alternative: Use this PHP script to insert the admin user directly
-- Create a file called 'create_admin.php' in the cyberhawk root and run it:
--
-- <?php
-- require_once 'routes/routes.php';
-- 
-- $db = new DatabaseHelper();
-- $password = password_hash('admin@123', PASSWORD_DEFAULT);
-- 
-- $sql = "INSERT INTO users (name, email, password, role, is_verified, created_at) 
--         VALUES (?, ?, ?, 'admin', 1, NOW())
--         ON DUPLICATE KEY UPDATE role = 'admin', is_verified = 1, password = ?";
-- 
-- $result = $db->query($sql, 'ssss', ['Administrator', 'admin@gmail.com', $password, $password]);
-- 
-- if ($result !== false) {
--     echo "Admin user created/updated successfully!\n";
--     echo "Email: admin@gmail.com\n";
--     echo "Password: admin@123\n";
-- } else {
--     echo "Failed to create admin user.\n";
-- }
-- ?>
-- ============================================================================
