<?php

/**
 * NotificationController Class
 *
 * Purpose: Handles notification management HTTP requests
 * Delegates business logic to NotificationService
 */
class NotificationController {

    private $notificationService;

    /**
     * Constructor
     */
    public function __construct() {
        $this->notificationService = new NotificationService();
    }

    /**
     * Get user notifications
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function getNotifications($vars = []) {
        header('Content-Type: application/json');

        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['error' => 1, 'message' => 'Unauthorized']);
            exit;
        }

        $userId = $_SESSION['user_id'];
        $notifications = $this->notificationService->getUserNotifications($userId);
        $unreadCount = $this->notificationService->getUnreadCount($userId);

        echo json_encode([
            'error' => 0,
            'notifications' => $notifications,
            'unread_count' => $unreadCount
        ]);
        exit;
    }

    /**
     * Mark notification as read
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function markAsRead($vars = []) {
        header('Content-Type: application/json');

        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['error' => 1, 'message' => 'Unauthorized']);
            exit;
        }

        $notificationId = $_POST['notification_id'] ?? '';

        if (!$notificationId) {
            echo json_encode(['error' => 1, 'message' => 'Notification ID required']);
            exit;
        }

        $success = $this->notificationService->markAsRead($notificationId);

        if ($success) {
            echo json_encode(['error' => 0, 'message' => 'Notification marked as read']);
        } else {
            echo json_encode(['error' => 1, 'message' => 'Failed to mark notification as read']);
        }
        exit;
    }

    /**
     * Mark all notifications as read
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function markAllAsRead($vars = []) {
        header('Content-Type: application/json');

        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['error' => 1, 'message' => 'Unauthorized']);
            exit;
        }

        $userId = $_SESSION['user_id'];
        $success = $this->notificationService->markAllAsRead($userId);

        if ($success) {
            echo json_encode(['error' => 0, 'message' => 'All notifications marked as read']);
        } else {
            echo json_encode(['error' => 1, 'message' => 'Failed to mark notifications as read']);
        }
        exit;
    }

    /**
     * Delete notification
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function deleteNotification($vars = []) {
        header('Content-Type: application/json');

        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['error' => 1, 'message' => 'Unauthorized']);
            exit;
        }

        $notificationId = $_POST['notification_id'] ?? '';

        if (!$notificationId) {
            echo json_encode(['error' => 1, 'message' => 'Notification ID required']);
            exit;
        }

        $success = $this->notificationService->delete($notificationId);

        if ($success) {
            echo json_encode(['error' => 0, 'message' => 'Notification deleted']);
        } else {
            echo json_encode(['error' => 1, 'message' => 'Failed to delete notification']);
        }
        exit;
    }

    /**
     * Clear all notifications
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function clearAll($vars = []) {
        header('Content-Type: application/json');

        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['error' => 1, 'message' => 'Unauthorized']);
            exit;
        }

        $userId = $_SESSION['user_id'];
        $success = $this->notificationService->clearUserNotifications($userId);

        if ($success) {
            echo json_encode(['error' => 0, 'message' => 'All notifications cleared']);
        } else {
            echo json_encode(['error' => 1, 'message' => 'Failed to clear notifications']);
        }
        exit;
    }
}

?>
