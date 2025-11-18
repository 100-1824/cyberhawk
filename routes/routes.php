<?php
// START SESSION FIRST
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require 'app/database/config.php';
require 'vendor/autoload.php';
require 'app/core/functions.php';
require 'app/core/views.php';

//Starting FastRoute Library
use FastRoute\RouteCollector;

$dispatcher = FastRoute\simpleDispatcher(function (RouteCollector $r) {

    $r->addRoute('GET', MDIR.'500', 'get_500_error_view');
    
    // Public routes (no authentication)
    $r->addRoute('GET', MDIR.'login', 'get_login_view');
    $r->addRoute('POST', MDIR . 'auth/login', 'handle_login');
    $r->addRoute('GET', MDIR.'register', 'get_register_view');
    $r->addRoute('POST', MDIR.'register', 'handle_Register');
    $r->addRoute('GET', MDIR . 'logout', 'logout_user');
    $r->addRoute('GET', MDIR . 'clearlogs', 'clear_traffic_logs');

    $r->addRoute('POST', MDIR . 'start-logs', 'startLogsHandler');
    $r->addRoute('POST', MDIR . 'start-model', 'startModelHandler');
    $r->addRoute('POST', MDIR . 'stop-logs', 'stopLogsHandler');

    $r->addRoute('GET', MDIR . 'get-intrusion-chart-data', 'get_intrusion_chart_data');

    // Protected routes (require authentication)
    $r->addRoute('GET', MDIR . 'dashboard', checkSession('user_id', 'get_dashboard'));


// UPDATED ROUTES - Remove scan-path endpoint
    $r->addRoute('GET', MDIR . 'ransomware', checkSession('user_id', 'get_ransomware_page'));
    $r->addRoute('GET', MDIR . 'get-ransomware-activity', checkSession('user_id', 'get_ransomware_activity'));
    $r->addRoute('GET', MDIR . 'get-ransomware-stats', checkSession('user_id', 'get_ransomware_stats')); 
    $r->addRoute('GET', MDIR . 'check-ransomware-threats', checkSession('user_id', 'check_ransomware_threats'));
    $r->addRoute('GET', MDIR . 'get-quarantine-files', checkSession('user_id', 'get_quarantine_files'));
    $r->addRoute('GET', MDIR . 'get-scan-progress', checkSession('user_id', 'get_scan_progress'));
    $r->addRoute('GET', MDIR . 'get-monitor-status', checkSession('user_id', 'get_monitor_status'));

    $r->addRoute('POST', MDIR . 'start-full-scan', checkSession('user_id', 'start_full_scan'));
    $r->addRoute('POST', MDIR . 'start-quick-scan', checkSession('user_id', 'start_quick_scan'));
    $r->addRoute('POST', MDIR . 'start-ransomware-monitor', checkSession('user_id', 'start_ransomware_monitor'));
    $r->addRoute('POST', MDIR . 'stop-ransomware-monitor', checkSession('user_id', 'stop_ransomware_monitor'));
    $r->addRoute('POST', MDIR . 'isolate-threats', checkSession('user_id', 'isolate_threats'));
    $r->addRoute('POST', MDIR . 'restore-quarantine-file', checkSession('user_id', 'restore_quarantine_file'));
    $r->addRoute('POST', MDIR . 'delete-quarantine-file', checkSession('user_id', 'delete_quarantine_file'));
    $r->addRoute('POST', MDIR . 'update-signatures', checkSession('user_id', 'update_signatures'));
    $r->addRoute('POST', MDIR . 'restore-backup', checkSession('user_id', 'restore_backup'));



    // Malware Analysis Module
    $r->addRoute('GET', MDIR . 'malware', checkSession('user_id', 'get_malware_page'));
    $r->addRoute('GET', MDIR . 'get-malware-stats', checkSession('user_id', 'get_malware_stats'));
    $r->addRoute('GET', MDIR . 'get-all-malware-reports', checkSession('user_id', 'get_all_malware_reports'));
    $r->addRoute('GET', MDIR . 'get-malware-report', checkSession('user_id', 'get_malware_report'));
    $r->addRoute('GET', MDIR . 'get-scan-queue', checkSession('user_id', 'get_scan_queue'));
    $r->addRoute('GET', MDIR . 'get-malware-scan-progress', checkSession('user_id', 'get_malware_scan_progress'));

    $r->addRoute('POST', MDIR . 'upload-malware-sample', checkSession('user_id', 'upload_malware_sample'));
    $r->addRoute('POST', MDIR . 'start-malware-scan', checkSession('user_id', 'start_malware_scan'));
    $r->addRoute('POST', MDIR . 'delete-malware-sample', checkSession('user_id', 'delete_malware_sample'));
    $r->addRoute('POST', MDIR . 'export-malware-report', checkSession('user_id', 'export_malware_report'));
    // $r->addRoute('POST', MDIR . 'start-behavioral-analysis', checkSession('user_id', 'start_behavioral_analysis'));

// REMOVED: scan-path endpoint

    /**
     * GDPR Routes
     */
    $r->addRoute('GET', MDIR . 'gdpr/verify/{token}', 'get_gdpr_verify_page');

    /**
     * Azure SSO Login Routes
     * File Location : app/core/Azure/functions.php
     */
    $r->addRoute('GET', MDIR.'loginAzure', 'authenticate_azureuser');
    $r->addRoute('GET', MDIR.'AzureCallback', 'authenticate_azurecallback');
    $r->addRoute('GET', MDIR.'AzureError', 'authenticate_azure_error');

    /**
     * Contract Routes
     */
    $r->addRoute('GET', MDIR . 'test-contracts', 'test_get_contracts');

    //Testing purpose
    $r->addRoute('GET', MDIR.'test', 'testing');

    if(is_file('routes/test-routes.php'))
    {
        require 'routes/test-routes.php';
    }
});

// Fetch method and URI from the server variables
$httpMethod = $_SERVER['REQUEST_METHOD'];
$uri = $_SERVER['REQUEST_URI'];

// Strip query string (?foo=bar) and decode URI
if (false !== $pos = strpos($uri, '?')) {
    $uri = substr($uri, 0, $pos);
}
$uri = rawurldecode($uri);

// Dispatch the request
$routeInfo = $dispatcher->dispatch($httpMethod, $uri);

switch ($routeInfo[0]) {
    case FastRoute\Dispatcher::NOT_FOUND:
        // 404 Not Found
        header("HTTP/1.0 404 Not Found");
        require 'app/views/error/404.php';
        break;
        
    case FastRoute\Dispatcher::METHOD_NOT_ALLOWED:
        // 405 Method Not Allowed
        header("HTTP/1.0 405 Method Not Allowed");
        display_error("405 Method Not Allowed");
        break;
        
    case FastRoute\Dispatcher::FOUND:
        // Handle the request
        $handler = $routeInfo[1];
        $vars = $routeInfo[2];
        call_user_func($handler, $vars);
        break;
}
?>