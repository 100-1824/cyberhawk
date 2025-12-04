<?php

/**
 * AlertService Class
 *
 * Purpose: Handles display of alert messages (success, error, info)
 * Replaces: display_error(), display_success(), display_errors() functions
 */
class AlertService {

    /**
     * Display a single error message
     *
     * @param string $message The error message to display
     * @return string HTML for error alert
     */
    public function error($message) {
        return '<div class="alert alert-danger alert-dismissible" role="alert">
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    <p class="mb-0">' . htmlspecialchars($message) . '</p>
                </div>';
    }

    /**
     * Display multiple error messages
     *
     * @param array $messages Array of error messages to display
     * @return string HTML for all error alerts
     */
    public function errors($messages) {
        $html = '';
        foreach ($messages as $message) {
            $html .= '<div class="alert alert-danger alert-dismissible" role="alert">
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                        <p class="mb-0">' . htmlspecialchars($message) . '</p>
                      </div>';
        }
        return $html;
    }

    /**
     * Display a success message
     *
     * @param string $message The success message to display
     * @return string HTML for success alert
     */
    public function success($message) {
        return '<div class="alert alert-success-outline alert-dismissible d-flex align-items-center" role="alert">
                    <i class="fa fa-check-square-o mr-10"></i> ' . htmlspecialchars($message) . '
                    <button class="btn-close" type="button" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>';
    }

    /**
     * Display an info message
     *
     * @param string $message The info message to display
     * @return string HTML for info alert
     */
    public function info($message) {
        return '<div class="alert alert-info alert-dismissible d-flex align-items-center" role="alert">
                    <i class="fa fa-info-circle mr-10"></i> ' . htmlspecialchars($message) . '
                    <button class="btn-close" type="button" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>';
    }

    /**
     * Display a warning message
     *
     * @param string $message The warning message to display
     * @return string HTML for warning alert
     */
    public function warning($message) {
        return '<div class="alert alert-warning alert-dismissible d-flex align-items-center" role="alert">
                    <i class="fa fa-exclamation-triangle mr-10"></i> ' . htmlspecialchars($message) . '
                    <button class="btn-close" type="button" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>';
    }

    /**
     * Echo error message directly (for backward compatibility)
     *
     * @param string $message The error message
     */
    public function displayError($message) {
        echo $this->error($message);
    }

    /**
     * Echo success message directly (for backward compatibility)
     *
     * @param string $message The success message
     */
    public function displaySuccess($message) {
        echo $this->success($message);
    }

    /**
     * Echo multiple error messages directly (for backward compatibility)
     *
     * @param array $messages Array of error messages
     */
    public function displayErrors($messages) {
        echo $this->errors($messages);
    }
}

?>
