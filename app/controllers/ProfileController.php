<?php

/**
 * ProfileController Class
 *
 * Purpose: Handles user profile management HTTP requests
 * Delegates business logic to UserProfileService
 */
class ProfileController {

    private $profileService;

    /**
     * Constructor
     */
    public function __construct() {
        $this->profileService = new UserProfileService();
    }

    /**
     * Show profile page
     *
     * @param array $vars Route variables
     * @return void
     */
    public function show($vars = []) {
        if (!isset($_SESSION['user_id'])) {
            header("Location: " . MDIR . "login");
            exit;
        }
        require 'app/views/pages/profile.php';
    }

    /**
     * Update profile
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function updateProfile($vars = []) {
        return $this->profileService->updateProfile();
    }

    /**
     * Upload profile picture
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function uploadPicture($vars = []) {
        return $this->profileService->uploadProfilePicture();
    }

    /**
     * Delete profile picture
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function deletePicture($vars = []) {
        return $this->profileService->deleteProfilePicture();
    }

    /**
     * Change password
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function changePassword($vars = []) {
        return $this->profileService->changePassword();
    }

    /**
     * Terminate all sessions
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function terminateSessions($vars = []) {
        $accountService = new AccountService();
        return $accountService->terminateSessions();
    }

    /**
     * Export user data
     *
     * @param array $vars Route variables
     * @return void File download
     */
    public function exportData($vars = []) {
        $accountService = new AccountService();
        return $accountService->exportUserData();
    }

    /**
     * Delete account
     *
     * @param array $vars Route variables
     * @return void JSON response
     */
    public function deleteAccount($vars = []) {
        $accountService = new AccountService();
        return $accountService->deleteAccount();
    }
}

?>
