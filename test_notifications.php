<?php
/**
 * Test script to verify notification system
 * Access: http://localhost/cyberhawk/test_notifications.php
 */

// Start session
session_start();

// Include necessary files
define('DIR', __DIR__ . '/');
require_once DIR . 'app/database/config.php';
require_once DIR . 'app/helpers/notifications.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    echo "<h1>Please login first</h1>";
    echo "<a href='/cyberhawk/login'>Go to Login</a>";
    exit;
}

$userId = $_SESSION['user_id'];

// Add a test notification
if (isset($_GET['add'])) {
    add_notification(
        $userId,
        'success',
        'Test Notification',
        'This is a test notification to verify the system is working!',
        [
            'action' => 'test',
            'timestamp' => date('Y-m-d H:i:s')
        ]
    );
    echo "<p style='color: green;'>✅ Test notification added!</p>";
}

// Get notifications
$notifications = get_user_notifications($userId, 10);
$unreadCount = get_unread_notification_count($userId);

?>
<!DOCTYPE html>
<html>
<head>
    <title>Notification System Test</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        .notification { border: 1px solid #ddd; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .success { background: #d4edda; }
        .info { background: #d1ecf1; }
        .warning { background: #fff3cd; }
        .error { background: #f8d7da; }
    </style>
</head>
<body>
    <h1>Notification System Test</h1>
    <p>Logged in as User ID: <?= $userId ?></p>
    <p>Unread Count: <strong><?= $unreadCount ?></strong></p>

    <hr>

    <h2>Actions</h2>
    <p>
        <a href="?add=1">➕ Add Test Notification</a> |
        <a href="test_notifications.php">🔄 Refresh</a> |
        <a href="/cyberhawk/dashboard">🏠 Back to Dashboard</a>
    </p>

    <hr>

    <h2>Recent Notifications (<?= count($notifications) ?>)</h2>

    <?php if (empty($notifications)): ?>
        <p style="color: #999;">No notifications found.</p>
    <?php else: ?>
        <?php foreach ($notifications as $notif): ?>
            <div class="notification <?= $notif['type'] ?>">
                <strong><?= htmlspecialchars($notif['title']) ?></strong>
                <p><?= htmlspecialchars($notif['message']) ?></p>
                <small>
                    ID: <?= $notif['id'] ?> |
                    Created: <?= $notif['created_at'] ?> |
                    Read: <?= $notif['is_read'] ? 'Yes' : 'No' ?>
                </small>
            </div>
        <?php endforeach; ?>
    <?php endif; ?>

    <hr>

    <h2>Test API Endpoints</h2>
    <div id="apiTest">
        <button onclick="testGetNotifications()">Test GET /get-notifications</button>
        <pre id="apiResult" style="background: #f5f5f5; padding: 10px; border-radius: 5px;"></pre>
    </div>

    <script>
        const MDIR = '/cyberhawk/';

        function testGetNotifications() {
            document.getElementById('apiResult').textContent = 'Loading...';

            fetch(MDIR + 'get-notifications')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('apiResult').textContent = JSON.stringify(data, null, 2);
                })
                .catch(error => {
                    document.getElementById('apiResult').textContent = 'Error: ' + error;
                });
        }
    </script>
</body>
</html>
