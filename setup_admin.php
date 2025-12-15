<?php
/**
 * Standalone Admin User Creation Script
 * Run directly: php setup_admin.php
 */

// Database connection
$host = "localhost";
$user = "root";
$password = "";
$db = "cyberhawk";

$mysqli = new MySQLi($host, $user, $password, $db);

if ($mysqli->connect_errno) {
    die("Database connection failed: " . $mysqli->connect_error . "\n");
}

// Admin credentials
$name = 'Administrator';
$email = 'admin@gmail.com';
$plainPassword = 'admin@123';
$hashedPassword = password_hash($plainPassword, PASSWORD_DEFAULT);

// Check if user exists
$stmt = $mysqli->prepare("SELECT id FROM users WHERE email = ?");
$stmt->bind_param('s', $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    // Update existing user
    $updateStmt = $mysqli->prepare("UPDATE users SET name = ?, password = ?, role = 'admin', is_verified = 1 WHERE email = ?");
    $updateStmt->bind_param('sss', $name, $hashedPassword, $email);
    
    if ($updateStmt->execute()) {
        echo "Admin user UPDATED successfully!\n";
    } else {
        echo "Failed to update admin user: " . $updateStmt->error . "\n";
    }
    $updateStmt->close();
} else {
    // Insert new user
    $insertStmt = $mysqli->prepare("INSERT INTO users (name, email, password, role, is_verified, created_at) VALUES (?, ?, ?, 'admin', 1, NOW())");
    $insertStmt->bind_param('sss', $name, $email, $hashedPassword);
    
    if ($insertStmt->execute()) {
        echo "Admin user CREATED successfully!\n";
    } else {
        echo "Failed to create admin user: " . $insertStmt->error . "\n";
    }
    $insertStmt->close();
}

$stmt->close();
$mysqli->close();

echo "\n===========================================\n";
echo "Admin Login Credentials:\n";
echo "===========================================\n";
echo "Email:    admin@gmail.com\n";
echo "Password: admin@123\n";
echo "===========================================\n";
?>
