<?php

/**
 * AdminController Class
 * 
 * Purpose: Handle all admin-related HTTP requests and render admin views
 */
class AdminController {

    private $adminService;

    /**
     * Constructor
     */
    public function __construct() {
        $this->adminService = new AdminService();
    }

    /**
     * Show admin dashboard
     */
    public function showDashboard() {
        // Get dashboard data
        $stats = $this->adminService->getSystemStats();
        $users = $this->adminService->getAllUsers(10, 0);
        $recentActivity = $this->adminService->getRecentActivity(10);

        require 'app/views/pages/admin/admin_dashboard.php';
    }

    /**
     * Get all users (JSON response)
     */
    public function getUsers() {
        header('Content-Type: application/json');

        $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 100;
        $offset = isset($_GET['offset']) ? (int)$_GET['offset'] : 0;

        $users = $this->adminService->getAllUsers($limit, $offset);
        $total = $this->adminService->getTotalUsersCount();

        echo json_encode([
            'success' => true,
            'users' => $users,
            'total' => $total
        ]);
    }

    /**
     * Get single user (JSON response)
     */
    public function getUser() {
        header('Content-Type: application/json');

        $userId = isset($_GET['id']) ? (int)$_GET['id'] : 0;

        if (!$userId) {
            echo json_encode(['success' => false, 'message' => 'User ID required']);
            return;
        }

        $user = $this->adminService->getUserById($userId);

        if (!$user) {
            echo json_encode(['success' => false, 'message' => 'User not found']);
            return;
        }

        echo json_encode(['success' => true, 'user' => $user]);
    }

    /**
     * Update user information
     */
    public function updateUser() {
        header('Content-Type: application/json');

        $userId = isset($_POST['user_id']) ? (int)$_POST['user_id'] : 0;

        if (!$userId) {
            echo json_encode(['success' => false, 'message' => 'User ID required']);
            return;
        }

        $data = [
            'name' => $_POST['name'] ?? '',
            'email' => $_POST['email'] ?? '',
            'role' => $_POST['role'] ?? 'user',
            'phone' => $_POST['phone'] ?? '',
            'is_verified' => isset($_POST['is_verified']) ? (int)$_POST['is_verified'] : 0
        ];

        // Validate required fields
        if (empty($data['name']) || empty($data['email'])) {
            echo json_encode(['success' => false, 'message' => 'Name and email are required']);
            return;
        }

        // Validate email format
        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            echo json_encode(['success' => false, 'message' => 'Invalid email format']);
            return;
        }

        $result = $this->adminService->updateUser($userId, $data);

        if ($result) {
            echo json_encode(['success' => true, 'message' => 'User updated successfully']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to update user']);
        }
    }

    /**
     * Delete user
     */
    public function deleteUser() {
        header('Content-Type: application/json');

        $userId = isset($_POST['user_id']) ? (int)$_POST['user_id'] : 0;

        if (!$userId) {
            echo json_encode(['success' => false, 'message' => 'User ID required']);
            return;
        }

        // Prevent self-deletion
        if ($userId == $_SESSION['user_id']) {
            echo json_encode(['success' => false, 'message' => 'Cannot delete your own account']);
            return;
        }

        $result = $this->adminService->deleteUser($userId);

        if ($result) {
            echo json_encode(['success' => true, 'message' => 'User deleted successfully']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to delete user']);
        }
    }

    /**
     * Get system statistics (JSON response)
     */
    public function getStats() {
        header('Content-Type: application/json');

        $stats = $this->adminService->getSystemStats();

        echo json_encode([
            'success' => true,
            'stats' => $stats
        ]);
    }

    /**
     * Get system endpoints (JSON response)
     */
    public function getEndpoints() {
        header('Content-Type: application/json');

        $endpoints = $this->adminService->getEndpoints();

        echo json_encode([
            'success' => true,
            'endpoints' => $endpoints,
            'total' => count($endpoints)
        ]);
    }

    /**
     * Reset user password
     */
    public function resetPassword() {
        header('Content-Type: application/json');

        $userId = isset($_POST['user_id']) ? (int)$_POST['user_id'] : 0;
        $newPassword = $_POST['new_password'] ?? '';

        if (!$userId || !$newPassword) {
            echo json_encode(['success' => false, 'message' => 'User ID and new password required']);
            return;
        }

        if (strlen($newPassword) < 6) {
            echo json_encode(['success' => false, 'message' => 'Password must be at least 6 characters']);
            return;
        }

        $result = $this->adminService->resetUserPassword($userId, $newPassword);

        if ($result) {
            echo json_encode(['success' => true, 'message' => 'Password reset successfully']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to reset password']);
        }
    }
}

?>
