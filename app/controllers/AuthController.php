<?php

/**
 * AuthController Class
 *
 * Purpose: Handles authentication-related HTTP requests
 * Delegates business logic to AuthService
 */
class AuthController {

    private $authService;

    /**
     * Constructor
     */
    public function __construct() {
        $this->authService = new AuthService();
    }

    /**
     * Handle login request
     *
     * @param array $vars Route variables
     * @return void
     */
    public function login($vars = []) {
        return $this->authService->login();
    }

    /**
     * Handle registration request
     *
     * @param array $vars Route variables
     * @return void
     */
    public function register($vars = []) {
        return $this->authService->register();
    }

    /**
     * Handle email verification request
     *
     * @param array $vars Route variables
     * @return void
     */
    public function verify($vars = []) {
        return $this->authService->verify();
    }

    /**
     * Handle logout request
     *
     * @param array $vars Route variables
     * @return void
     */
    public function logout($vars = []) {
        return $this->authService->logout();
    }

    /**
     * Handle password update request
     *
     * @param array $vars Route variables
     * @return void
     */
    public function updatePassword($vars = []) {
        return $this->authService->updatePassword();
    }
}

?>
