<?php
/**
 * Bootstrap file for loading environment variables
 * This file loads the .env file using vlucas/phpdotenv library
 */

use Dotenv\Dotenv;

// Determine the project root directory
$rootDir = dirname(__DIR__);

// Check if .env file exists
if (!file_exists($rootDir . '/.env')) {
    // Fallback to .env.example if .env doesn't exist (for development)
    if (!file_exists($rootDir . '/.env.example')) {
        trigger_error(
            'No .env or .env.example file found. Please create a .env file from .env.example',
            E_USER_ERROR
        );
    }
    // Use .env.example as fallback
    $dotenv = Dotenv::createImmutable($rootDir, '.env.example');
} else {
    // Load the actual .env file
    $dotenv = Dotenv::createImmutable($rootDir);
}

// Load environment variables
$dotenv->load();

// Helper function to get environment variables with default values
if (!function_exists('env')) {
    /**
     * Get an environment variable value
     *
     * @param string $key The environment variable key
     * @param mixed $default The default value if key doesn't exist
     * @return mixed
     */
    function env($key, $default = null)
    {
        $value = $_ENV[$key] ?? $_SERVER[$key] ?? getenv($key);

        if ($value === false) {
            return $default;
        }

        // Convert string boolean values
        switch (strtolower($value)) {
            case 'true':
            case '(true)':
                return true;
            case 'false':
            case '(false)':
                return false;
            case 'empty':
            case '(empty)':
                return '';
            case 'null':
            case '(null)':
                return null;
        }

        return $value;
    }
}

// Define constants from environment variables if they don't already exist
if (!defined('MDIR')) {
    define('MDIR', env('MDIR', '/cyberhawk/'));
}

if (!defined('DIR')) {
    define('DIR', env('APP_DIR', dirname(__DIR__) . '/'));
}
