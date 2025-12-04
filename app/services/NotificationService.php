<?php

/**
 * NotificationService Class
 *
 * Purpose: Manages user notifications
 * Replaces: All functions in app/helpers/notifications.php
 */
class NotificationService {

    private $notificationsFile;

    /**
     * Constructor
     */
    public function __construct() {
        $this->notificationsFile = DIR . 'assets/data/notifications.json';
        $this->initNotificationsFile();
    }

    /**
     * Initialize notifications file if it doesn't exist
     */
    private function initNotificationsFile() {
        $dir = dirname($this->notificationsFile);
        if (!file_exists($dir)) {
            mkdir($dir, 0755, true);
        }

        if (!file_exists($this->notificationsFile)) {
            file_put_contents($this->notificationsFile, json_encode([], JSON_PRETTY_PRINT));
        }
    }

    /**
     * Add a new notification
     *
     * @param int $userId User ID
     * @param string $type Notification type (success, info, warning, error)
     * @param string $title Notification title
     * @param string $message Notification message
     * @param array $details Additional details (optional)
     * @return bool Success status
     */
    public function add($userId, $type, $title, $message, $details = []) {
        // Load existing notifications
        $notifications = $this->getAll();

        // Create new notification
        $notification = [
            'id' => uniqid('notif_', true),
            'user_id' => $userId,
            'type' => $type,
            'title' => $title,
            'message' => $message,
            'details' => $details,
            'is_read' => false,
            'created_at' => date('Y-m-d H:i:s'),
            'timestamp' => time()
        ];

        // Add to beginning of array (newest first)
        array_unshift($notifications, $notification);

        // Keep only last 100 notifications per user
        $userNotifications = array_filter($notifications, function($n) use ($userId) {
            return $n['user_id'] == $userId;
        });

        if (count($userNotifications) > 100) {
            // Remove oldest notifications for this user
            $notifications = array_filter($notifications, function($n) use ($userId, $userNotifications) {
                if ($n['user_id'] != $userId) return true;
                return in_array($n, array_slice($userNotifications, 0, 100));
            });
        }

        // Save notifications
        return file_put_contents(
            $this->notificationsFile,
            json_encode(array_values($notifications), JSON_PRETTY_PRINT)
        ) !== false;
    }

    /**
     * Get all notifications from file
     *
     * @return array All notifications
     */
    public function getAll() {
        $content = file_get_contents($this->notificationsFile);
        $notifications = json_decode($content, true);
        return is_array($notifications) ? $notifications : [];
    }

    /**
     * Get notifications for a specific user
     *
     * @param int $userId User ID
     * @param int $limit Maximum number of notifications to return
     * @param bool $unreadOnly Return only unread notifications
     * @return array User notifications
     */
    public function getUserNotifications($userId, $limit = 50, $unreadOnly = false) {
        $notifications = $this->getAll();

        // Filter by user ID
        $userNotifications = array_filter($notifications, function($n) use ($userId, $unreadOnly) {
            $matchUser = $n['user_id'] == $userId;
            if ($unreadOnly) {
                return $matchUser && !$n['is_read'];
            }
            return $matchUser;
        });

        // Sort by timestamp (newest first)
        usort($userNotifications, function($a, $b) {
            return $b['timestamp'] - $a['timestamp'];
        });

        // Apply limit
        return array_slice($userNotifications, 0, $limit);
    }

    /**
     * Mark a notification as read
     *
     * @param string $notificationId Notification ID
     * @return bool Success status
     */
    public function markAsRead($notificationId) {
        $notifications = $this->getAll();

        $updated = false;
        foreach ($notifications as &$notification) {
            if ($notification['id'] === $notificationId) {
                $notification['is_read'] = true;
                $updated = true;
                break;
            }
        }

        if ($updated) {
            return file_put_contents(
                $this->notificationsFile,
                json_encode($notifications, JSON_PRETTY_PRINT)
            ) !== false;
        }

        return false;
    }

    /**
     * Mark all notifications as read for a user
     *
     * @param int $userId User ID
     * @return bool Success status
     */
    public function markAllAsRead($userId) {
        $notifications = $this->getAll();

        foreach ($notifications as &$notification) {
            if ($notification['user_id'] == $userId) {
                $notification['is_read'] = true;
            }
        }

        return file_put_contents(
            $this->notificationsFile,
            json_encode($notifications, JSON_PRETTY_PRINT)
        ) !== false;
    }

    /**
     * Delete a specific notification
     *
     * @param string $notificationId Notification ID
     * @return bool Success status
     */
    public function delete($notificationId) {
        $notifications = $this->getAll();

        $notifications = array_filter($notifications, function($n) use ($notificationId) {
            return $n['id'] !== $notificationId;
        });

        return file_put_contents(
            $this->notificationsFile,
            json_encode(array_values($notifications), JSON_PRETTY_PRINT)
        ) !== false;
    }

    /**
     * Clear all notifications for a user
     *
     * @param int $userId User ID
     * @return bool Success status
     */
    public function clearUserNotifications($userId) {
        $notifications = $this->getAll();

        $notifications = array_filter($notifications, function($n) use ($userId) {
            return $n['user_id'] != $userId;
        });

        return file_put_contents(
            $this->notificationsFile,
            json_encode(array_values($notifications), JSON_PRETTY_PRINT)
        ) !== false;
    }

    /**
     * Get unread notification count for a user
     *
     * @param int $userId User ID
     * @return int Unread count
     */
    public function getUnreadCount($userId) {
        $notifications = $this->getAll();

        $unread = array_filter($notifications, function($n) use ($userId) {
            return $n['user_id'] == $userId && !$n['is_read'];
        });

        return count($unread);
    }
}

?>
