<?php
/**
 * Create Admin User Script
 * 
 * This script creates the admin user for CyberHawk admin panel.
 * Run this once to set up the admin account.
 */

// Load the application
require_once __DIR__ . '/routes/routes.php';

$db = new DatabaseHelper();

// Admin credentials
$name = 'Administrator';
$email = 'admin@gmail.com';
$password = 'admin@123';
$role = 'admin';

// Hash the password
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

// Check if admin already exists
$existingUser = $db->query("SELECT id FROM users WHERE email = ?", 's', [$email]);

if ($existingUser && count($existingUser) > 0) {
    // Update existing user to admin
    $sql = "UPDATE users SET name = ?, password = ?, role = 'admin', is_verified = 1 WHERE email = ?";
    $result = $db->query($sql, 'sss', [$name, $hashedPassword, $email]);
    
    if ($result !== false) {
        echo "Admin user updated successfully!\n";
    } else {
        echo "Failed to update admin user.\n";
        exit(1);
    }
} else {
    // Insert new admin user
    $sql = "INSERT INTO users (name, email, password, role, is_verified, created_at) 
            VALUES (?, ?, ?, 'admin', 1, NOW())";
    $result = $db->query($sql, 'sss', [$name, $email, $hashedPassword]);
    
    if ($result !== false) {
        echo "Admin user created successfully!\n";
    } else {
        echo "Failed to create admin user.\n";
        exit(1);
    }
}

echo "\n";
echo "===========================================\n";
echo "Admin Login Credentials:\n";
echo "===========================================\n";
echo "Email:    admin@gmail.com\n";
echo "Password: admin@123\n";
echo "===========================================\n";
echo "\nYou can now login at: /cyberhawk/login\n";
?>
