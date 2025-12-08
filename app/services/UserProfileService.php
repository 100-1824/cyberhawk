<?php

/**
 * UserProfileService Class
 *
 * Purpose: Handles user profile management operations
 * Replaces: update_profile(), upload_profile_picture(), delete_profile_picture(), change_password()
 */
class UserProfileService {

    private $db;
    private $notificationService;

    /**
     * Constructor
     */
    public function __construct() {
        $this->db = new DatabaseHelper();
        $this->notificationService = new NotificationService();
    }

    /**
     * Update user profile information
     *
     * @return void JSON response
     */
    public function updateProfile() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        header('Content-Type: application/json');

        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['success' => false, 'message' => 'Not authenticated']);
            return;
        }

        $userId = $_SESSION['user_id'];
        $name = trim($_POST['name'] ?? '');
        $phone = trim($_POST['phone'] ?? '');
        $bio = trim($_POST['bio'] ?? '');

        // Validation
        if (empty($name)) {
            echo json_encode(['success' => false, 'message' => 'Name is required']);
            return;
        }

        if (strlen($name) < 2 || strlen($name) > 100) {
            echo json_encode(['success' => false, 'message' => 'Name must be between 2 and 100 characters']);
            return;
        }

        if (!empty($phone) && !preg_match('/^[0-9+\-\s()]{7,20}$/', $phone)) {
            echo json_encode(['success' => false, 'message' => 'Invalid phone number format']);
            return;
        }

        if (strlen($bio) > 500) {
            echo json_encode(['success' => false, 'message' => 'Bio must be less than 500 characters']);
            return;
        }

        try {
            $sql = "UPDATE users SET name = ?, phone = ?, bio = ?, last_updated = NOW() WHERE id = ?";
            $result = $this->db->query($sql, 'sssi', [$name, $phone, $bio, $userId]);

            if ($result) {
                // Update session
                $_SESSION['user_name'] = $name;

                // Add notification
                $this->notificationService->add(
                    $userId,
                    'success',
                    'Profile Updated',
                    'Your profile information has been updated successfully.',
                    ['name' => $name]
                );

                echo json_encode([
                    'success' => true,
                    'message' => 'Profile updated successfully',
                    'user' => [
                        'name' => $name,
                        'phone' => $phone,
                        'bio' => $bio
                    ]
                ]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Failed to update profile']);
            }
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
        }
    }

    /**
     * Upload user profile picture
     *
     * @return void JSON response
     */
    public function uploadProfilePicture() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        header('Content-Type: application/json');

        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['success' => false, 'message' => 'Not authenticated']);
            return;
        }

        if (!isset($_FILES['profile_picture'])) {
            echo json_encode(['success' => false, 'message' => 'No file uploaded']);
            return;
        }

        $userId = $_SESSION['user_id'];
        $file = $_FILES['profile_picture'];

        // Validate file
        $allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif'];
        $maxSize = 5 * 1024 * 1024; // 5MB

        if ($file['error'] !== UPLOAD_ERR_OK) {
            echo json_encode(['success' => false, 'message' => 'File upload error']);
            return;
        }

        if (!in_array($file['type'], $allowedTypes)) {
            echo json_encode(['success' => false, 'message' => 'Invalid file type. Only JPG, PNG, and GIF allowed']);
            return;
        }

        if ($file['size'] > $maxSize) {
            echo json_encode(['success' => false, 'message' => 'File too large. Maximum size is 5MB']);
            return;
        }

        // Verify it's actually an image
        $imageInfo = getimagesize($file['tmp_name']);
        if ($imageInfo === false) {
            echo json_encode(['success' => false, 'message' => 'File is not a valid image']);
            return;
        }

        try {
            // Create upload directory if it doesn't exist
            $uploadDir = DIR . 'assets/uploads/profiles/';
            if (!is_dir($uploadDir)) {
                mkdir($uploadDir, 0755, true);
            }

            // Get current profile picture to delete old one
            $user = $this->getUserProfile($userId);

            // Generate unique filename
            $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
            $filename = 'profile_' . $userId . '_' . time() . '.' . $extension;
            $filepath = $uploadDir . $filename;

            // Move uploaded file
            if (move_uploaded_file($file['tmp_name'], $filepath)) {
                // Delete old profile picture if exists
                if ($user && !empty($user['profile_picture'])) {
                    $oldFile = $uploadDir . $user['profile_picture'];
                    if (file_exists($oldFile)) {
                        @unlink($oldFile);
                    }
                }

                // Update database
                $sql = "UPDATE users SET profile_picture = ?, last_updated = NOW() WHERE id = ?";
                $result = $this->db->query($sql, 'si', [$filename, $userId]);

                if ($result) {
                    // Add notification
                    $this->notificationService->add(
                        $userId,
                        'success',
                        'Profile Picture Updated',
                        'Your profile picture has been updated successfully.',
                        []
                    );

                    echo json_encode([
                        'success' => true,
                        'message' => 'Profile picture updated successfully',
                        'filename' => $filename,
                        'url' => MDIR . 'assets/uploads/profiles/' . $filename
                    ]);
                } else {
                    // Delete uploaded file if database update fails
                    @unlink($filepath);
                    echo json_encode(['success' => false, 'message' => 'Failed to update database']);
                }
            } else {
                echo json_encode(['success' => false, 'message' => 'Failed to save file']);
            }
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
        }
    }

    /**
     * Delete user profile picture
     *
     * @return void JSON response
     */
    public function deleteProfilePicture() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        header('Content-Type: application/json');

        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['success' => false, 'message' => 'Not authenticated']);
            return;
        }

        $userId = $_SESSION['user_id'];

        try {
            // Get current profile picture
            $user = $this->getUserProfile($userId);

            if ($user && !empty($user['profile_picture'])) {
                $uploadDir = DIR . 'assets/uploads/profiles/';
                $filepath = $uploadDir . $user['profile_picture'];

                // Delete file
                if (file_exists($filepath)) {
                    @unlink($filepath);
                }

                // Update database
                $sql = "UPDATE users SET profile_picture = NULL, last_updated = NOW() WHERE id = ?";
                $result = $this->db->query($sql, 'i', [$userId]);

                if ($result) {
                    // Add notification
                    $this->notificationService->add(
                        $userId,
                        'info',
                        'Profile Picture Removed',
                        'Your profile picture has been removed.',
                        []
                    );

                    echo json_encode([
                        'success' => true,
                        'message' => 'Profile picture removed successfully'
                    ]);
                } else {
                    echo json_encode(['success' => false, 'message' => 'Failed to update database']);
                }
            } else {
                echo json_encode(['success' => false, 'message' => 'No profile picture to delete']);
            }
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
        }
    }

    /**
     * Change user password
     *
     * @return void JSON response
     */
    public function changePassword() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        header('Content-Type: application/json');

        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['success' => false, 'message' => 'Not authenticated']);
            return;
        }

        $userId = $_SESSION['user_id'];
        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        // Validation
        if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
            echo json_encode(['success' => false, 'message' => 'All fields are required']);
            return;
        }

        if ($newPassword !== $confirmPassword) {
            echo json_encode(['success' => false, 'message' => 'New passwords do not match']);
            return;
        }

        if (strlen($newPassword) < 6) {
            echo json_encode(['success' => false, 'message' => 'New password must be at least 6 characters']);
            return;
        }

        if ($newPassword === $currentPassword) {
            echo json_encode(['success' => false, 'message' => 'New password must be different from current password']);
            return;
        }

        try {
            // Verify current password
            $sql = "SELECT password FROM users WHERE id = ?";
            $result = $this->db->query($sql, 'i', [$userId]);

            if (!$result || count($result) === 0) {
                echo json_encode(['success' => false, 'message' => 'User not found']);
                return;
            }

            $user = $result[0];

            if (!password_verify($currentPassword, $user['password'])) {
                echo json_encode(['success' => false, 'message' => 'Current password is incorrect']);
                return;
            }

            // Update password
            $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
            $sql = "UPDATE users SET password = ?, last_updated = NOW() WHERE id = ?";
            $result = $this->db->query($sql, 'si', [$hashedPassword, $userId]);

            if ($result) {
                // Add notification
                $this->notificationService->add(
                    $userId,
                    'warning',
                    'Password Changed',
                    'Your account password has been changed. If you did not do this, please contact support immediately.',
                    []
                );

                echo json_encode([
                    'success' => true,
                    'message' => 'Password changed successfully'
                ]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Failed to update password']);
            }
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
        }
    }

    /**
     * Get user profile data
     *
     * @param int $userId User ID
     * @return array|null User profile data or null
     */
    private function getUserProfile($userId) {
        $sql = "SELECT id, name, email, phone, bio, profile_picture FROM users WHERE id = ?";
        $result = $this->db->query($sql, 'i', [$userId]);

        if ($result && count($result) > 0) {
            return $result[0];
        }

        return null;
    }
}

?>
