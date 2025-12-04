<?php

/**
 * ApiAuthMiddleware Class
 *
 * Purpose: Handles API token authentication for API endpoints
 * Replaces: checkApi() function
 */
class ApiAuthMiddleware {

    /**
     * Handle middleware logic - check API token
     *
     * @param callable $handler The handler to call if token is valid
     * @return callable Middleware function
     */
    public function handle($handler) {
        return function($vars) use ($handler) {
            $token = $this->getAuthHeader();

            if ($this->checkApiToken($token) === false) {
                header('HTTP/1.1 401 Unauthorized');
                header('Content-Type: application/json');
                echo json_encode(['error' => 1, 'message' => 'Unauthorized Access']);
                exit;
            }

            // Pass the $token to the handler function
            if (is_callable($handler)) {
                return call_user_func($handler, $vars, $token);
            } elseif (is_array($handler) && count($handler) === 2) {
                // Handle [ControllerInstance, 'methodName'] format
                return call_user_func($handler, $vars, $token);
            } elseif (is_string($handler) && function_exists($handler)) {
                return call_user_func($handler, $vars, $token);
            } else {
                header('HTTP/1.1 500 Internal Server Error');
                header('Location: ' . MDIR . '500');
                exit;
            }
        };
    }

    /**
     * Get authorization header
     *
     * @return string|null Authorization token
     */
    private function getAuthHeader() {
        $headers = null;

        if (isset($_SERVER['Authorization'])) {
            $headers = trim($_SERVER["Authorization"]);
        } else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
        } elseif (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            $requestHeaders = array_combine(
                array_map('ucwords', array_keys($requestHeaders)),
                array_values($requestHeaders)
            );

            if (isset($requestHeaders['Authorization'])) {
                $headers = trim($requestHeaders['Authorization']);
            }
        }

        if (!empty($headers)) {
            if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
                return $matches[1];
            }
        }

        return null;
    }

    /**
     * Check if API token is valid
     *
     * @param string|null $token API token
     * @return bool True if valid, false otherwise
     */
    private function checkApiToken($token) {
        global $ApiEndPointToken;

        if (empty($token)) {
            return false;
        }

        // Check against global API token
        if (isset($ApiEndPointToken) && $token === $ApiEndPointToken) {
            return true;
        }

        // You can add database token validation here if needed
        // For now, just check against the global token

        return false;
    }
}

?>
