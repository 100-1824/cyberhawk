<?php
/**
 * Test script to verify settings are being saved correctly
 */

require 'app/database/config.php';
require 'app/core/functions.php';

session_start();

// Set a test user ID (change this to your actual user ID)
$_SESSION['user_id'] = 1;

echo "<h1>CyberHawk Settings Test</h1>";
echo "<hr>";

// 1. Check if system_settings table exists
echo "<h2>1. Database Check</h2>";
$tableCheck = mysqli_query($oConnection->dbc, "SHOW TABLES LIKE 'system_settings'");
if (mysqli_num_rows($tableCheck) > 0) {
    echo "✅ system_settings table exists<br>";
} else {
    echo "❌ system_settings table does NOT exist<br>";
}

// 2. Check current database settings
echo "<h2>2. Current Database Settings</h2>";
$sql = "SELECT * FROM system_settings WHERE user_id = 1";
$result = mysqli_query($oConnection->dbc, $sql);
if ($result && mysqli_num_rows($result) > 0) {
    echo "<table border='1' cellpadding='5'>";
    echo "<tr><th>ID</th><th>Setting Key</th><th>Setting Value</th><th>Updated At</th></tr>";
    while ($row = mysqli_fetch_assoc($result)) {
        echo "<tr>";
        echo "<td>{$row['id']}</td>";
        echo "<td>{$row['setting_key']}</td>";
        echo "<td>{$row['setting_value']}</td>";
        echo "<td>{$row['updated_at']}</td>";
        echo "</tr>";
    }
    echo "</table>";
} else {
    echo "⚠️ No settings found for user_id = 1<br>";
}

// 3. Check config file
echo "<h2>3. Config File Check</h2>";
$configPath = DIR . 'assets/config/settings.json';
echo "Config path: $configPath<br>";

if (file_exists($configPath)) {
    echo "✅ Config file exists<br>";
    echo "File permissions: " . substr(sprintf('%o', fileperms($configPath)), -4) . "<br>";

    $content = file_get_contents($configPath);
    echo "<h3>Current Content:</h3>";
    echo "<pre>" . htmlspecialchars($content) . "</pre>";

    $json = json_decode($content, true);
    if ($json) {
        echo "✅ Valid JSON<br>";
        echo "<h3>Parsed Settings:</h3>";
        echo "<ul>";
        foreach ($json as $key => $value) {
            $valueStr = is_bool($value) ? ($value ? 'true' : 'false') : $value;
            echo "<li><strong>$key:</strong> $valueStr</li>";
        }
        echo "</ul>";
    } else {
        echo "❌ Invalid JSON in config file<br>";
    }
} else {
    echo "❌ Config file does NOT exist at: $configPath<br>";
}

// 4. Test write permissions
echo "<h2>4. Write Permission Test</h2>";
$testData = [
    'alert_threshold' => 0.75,
    'test_timestamp' => date('c'),
    'test_write' => true
];

$testJson = json_encode($testData, JSON_PRETTY_PRINT);
if (file_put_contents($configPath, $testJson) !== false) {
    echo "✅ Successfully wrote test data to config file<br>";

    // Read it back
    $readBack = file_get_contents($configPath);
    if ($readBack === $testJson) {
        echo "✅ Read-back verification successful<br>";
    } else {
        echo "⚠️ Read-back data doesn't match<br>";
    }
} else {
    echo "❌ FAILED to write to config file<br>";
    echo "Error: Check file permissions<br>";
}

echo "<hr>";
echo "<p><a href='test_settings.php'>Refresh</a> | <a href='settings'>Go to Settings</a></p>";
?>
