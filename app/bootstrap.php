<?php
/**
 * Bootstrap file for loading environment variables
 * This file loads the .env file using vlucas/phpdotenv library
 *
 * NOTE: If Dotenv is not available (composer install not run),
 * environment variables can still be manually loaded from .env file
 */

// Determine the project root directory
$rootDir = dirname(__DIR__);

// Check if Dotenv class is available (composer install has been run)
if (class_exists('Dotenv\Dotenv')) {
    use Dotenv\Dotenv;

    // Check if .env file exists
    if (!file_exists($rootDir . '/.env')) {
        // Fallback to .env.example if .env doesn't exist (for development)
        if (!file_exists($rootDir . '/.env.example')) {
            trigger_error(
                'No .env or .env.example file found. Please create a .env file from .env.example',
                E_USER_WARNING
            );
        } else {
            // Use .env.example as fallback
            $dotenv = Dotenv::createImmutable($rootDir, '.env.example');
            $dotenv->load();
        }
    } else {
        // Load the actual .env file
        $dotenv = Dotenv::createImmutable($rootDir);
        $dotenv->load();
    }
} else {
    // Dotenv not available - manually parse .env file
    $envFile = $rootDir . '/.env';
    if (!file_exists($envFile)) {
        $envFile = $rootDir . '/.env.example';
    }

    if (file_exists($envFile)) {
        $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            // Skip comments and empty lines
            if (strpos(trim($line), '#') === 0 || trim($line) === '') {
                continue;
            }

            // Parse KEY=VALUE format
            if (strpos($line, '=') !== false) {
                list($key, $value) = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value);

                // Remove quotes if present
                if ((substr($value, 0, 1) === '"' && substr($value, -1) === '"') ||
                    (substr($value, 0, 1) === "'" && substr($value, -1) === "'")) {
                    $value = substr($value, 1, -1);
                }

                // Set environment variable
                if (!isset($_ENV[$key])) {
                    $_ENV[$key] = $value;
                    putenv("$key=$value");
                }
            }
        }
    }
}

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
