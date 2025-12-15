<?php

/**
 * AdminMiddleware Class
 * 
 * Purpose: Protect admin routes - only allow access for users with 'admin' role
 */
class AdminMiddleware {

    /**
     * Handle the middleware check
     * 
     * @param callable $handler The route handler to execute if authorized
     * @return callable Middleware function that wraps the handler
     */
    public function handle($handler) {
        // Return a closure that will be executed when the route is matched
        return function($vars = []) use ($handler) {
            // Check if session is started
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }

            // Check if user is logged in
            if (!isset($_SESSION['user_id'])) {
                header("Location: " . MDIR . "login");
                exit;
            }

            // Check if user has admin role
            if (!isset($_SESSION['user_role']) || $_SESSION['user_role'] !== 'admin') {
                header("Location: " . MDIR . "dashboard");
                exit;
            }

            // User is authorized, call the handler
            if (is_callable($handler)) {
                return call_user_func($handler, $vars);
            } elseif (is_array($handler) && count($handler) === 2) {
                return call_user_func($handler, $vars);
            } elseif (is_string($handler) && function_exists($handler)) {
                return call_user_func($handler, $vars);
            } else {
                header('HTTP/1.1 500 Internal Server Error');
                header('Location: ' . MDIR . '500');
                exit;
            }
        };
    }
}

?>
