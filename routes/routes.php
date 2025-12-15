<?php
// START SESSION FIRST
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Set timezone to Pakistan Standard Time
date_default_timezone_set('Asia/Karachi');

require 'app/database/config.php';
require 'vendor/autoload.php';

// ==================== LOAD ALL CLASS FILES ====================

// Infrastructure
require 'app/infrastructure/DatabaseHelper.php';
require 'app/infrastructure/AlertService.php';
require 'app/infrastructure/LogManager.php';

// Services
require 'app/services/AuthService.php';
require 'app/services/EmailService.php';
require 'app/services/NotificationService.php';
require 'app/services/UserProfileService.php';
require 'app/services/SettingsService.php';
require 'app/services/AccountService.php';
require 'app/services/ChatbotService.php';
require 'app/services/MalwareService.php';
require 'app/services/RansomwareService.php';
require 'app/services/ThreatIntelligenceService.php';
require 'app/services/NetworkAnalyticsService.php';
require 'app/services/ReportingService.php';
require 'app/services/AdminService.php';

// Middleware
require 'app/middleware/SessionMiddleware.php';
require 'app/middleware/ApiAuthMiddleware.php';
require 'app/middleware/AdminMiddleware.php';

// Controllers
require 'app/controllers/AuthController.php';
require 'app/controllers/DashboardController.php';
require 'app/controllers/MalwareController.php';
require 'app/controllers/RansomwareController.php';
require 'app/controllers/ReportingController.php';
require 'app/controllers/SettingsController.php';
require 'app/controllers/ProfileController.php';
require 'app/controllers/NotificationController.php';
require 'app/controllers/ThreatIntelligenceController.php';
require 'app/controllers/NetworkAnalyticsController.php';
require 'app/controllers/ViewController.php';
require 'app/controllers/AdminController.php';

// Legacy functions for backward compatibility (will be removed in future)
require 'app/core/functions.php';
require 'app/core/views.php';

// ==================== INSTANTIATE CONTROLLERS ====================

$authController = new AuthController();
$dashboardController = new DashboardController();
$malwareController = new MalwareController();
$ransomwareController = new RansomwareController();
$reportingController = new ReportingController();
$settingsController = new SettingsController();
$profileController = new ProfileController();
$notificationController = new NotificationController();
$threatController = new ThreatIntelligenceController();
$networkController = new NetworkAnalyticsController();
$viewController = new ViewController();
$adminController = new AdminController();

// ==================== INSTANTIATE MIDDLEWARE ====================

$sessionMiddleware = new SessionMiddleware();
$apiMiddleware = new ApiAuthMiddleware();
$adminMiddleware = new AdminMiddleware();

// ==================== HELPER FUNCTIONS ====================

/**
 * Session middleware wrapper for backward compatibility
 */
function checkSession($requiredSession, $handler) {
    global $sessionMiddleware;
    return $sessionMiddleware->handle($handler);
}

/**
 * API middleware wrapper for backward compatibility
 */
function checkApi($handler) {
    global $apiMiddleware;
    return $apiMiddleware->handle($handler);
}

/**
 * Admin middleware wrapper - checks if user is admin
 */
function checkAdmin($handler) {
    global $adminMiddleware;
    return $adminMiddleware->handle($handler);
}

//Starting FastRoute Library
use FastRoute\RouteCollector;

$dispatcher = FastRoute\simpleDispatcher(function (RouteCollector $r) use (
    $authController, $dashboardController, $malwareController, $ransomwareController,
    $reportingController, $settingsController, $profileController, $notificationController,
    $threatController, $networkController, $viewController, $adminController
) {

    // ==================== PUBLIC ROUTES (No Authentication) ====================

    // Landing Page
    $r->addRoute('GET', MDIR, [$viewController, 'showHome']);
    $r->addRoute('GET', MDIR.'home', [$viewController, 'showHome']);

    $r->addRoute('GET', MDIR.'500', [$viewController, 'show500Error']);
    $r->addRoute('GET', MDIR.'login', [$viewController, 'showLogin']);
    $r->addRoute('POST', MDIR . 'auth/login', [$authController, 'login']);
    $r->addRoute('GET', MDIR.'register', [$viewController, 'showRegister']);
    $r->addRoute('POST', MDIR.'register', [$authController, 'register']);
    $r->addRoute('GET', MDIR . 'logout', [$authController, 'logout']);
    $r->addRoute('POST', MDIR . 'verify-email', [$authController, 'verify']);
    $r->addRoute('GET', MDIR . 'verify', [$viewController, 'showVerify']);

    // Traffic log operations (public for testing)
    $r->addRoute('POST', MDIR . 'start-logs', [$viewController, 'startLogsHandler']);
    $r->addRoute('POST', MDIR . 'stop-logs', [$viewController, 'stopLogsHandler']);
    $r->addRoute('GET', MDIR . 'clearlogs', [$viewController, 'clearTrafficLogs']);

    // Legacy routes (still using functions - to be refactored)
    $r->addRoute('POST', MDIR . 'start-model', 'startModelHandler');
    $r->addRoute('GET', MDIR . 'get-intrusion-chart-data', 'get_intrusion_chart_data');
    $r->addRoute('GET', MDIR . 'get-validated-alerts', checkSession('user_id', 'get_validated_alerts'));
    $r->addRoute('GET', MDIR . 'test-ip-validation', checkSession('user_id', 'test_ip_validation'));

    // ==================== DASHBOARD ROUTES ====================

    $r->addRoute('GET', MDIR . 'dashboard', checkSession('user_id', [$dashboardController, 'show']));

    // ==================== ADMIN ROUTES ====================

    $r->addRoute('GET', MDIR . 'admin/dashboard', checkAdmin([$adminController, 'showDashboard']));
    $r->addRoute('GET', MDIR . 'admin/users', checkAdmin([$adminController, 'getUsers']));
    $r->addRoute('GET', MDIR . 'admin/get-user', checkAdmin([$adminController, 'getUser']));
    $r->addRoute('POST', MDIR . 'admin/update-user', checkAdmin([$adminController, 'updateUser']));
    $r->addRoute('POST', MDIR . 'admin/delete-user', checkAdmin([$adminController, 'deleteUser']));
    $r->addRoute('GET', MDIR . 'admin/stats', checkAdmin([$adminController, 'getStats']));
    $r->addRoute('GET', MDIR . 'admin/endpoints', checkAdmin([$adminController, 'getEndpoints']));
    $r->addRoute('POST', MDIR . 'admin/reset-password', checkAdmin([$adminController, 'resetPassword']));

    // ==================== RANSOMWARE ROUTES ====================

    $r->addRoute('GET', MDIR . 'ransomware', checkSession('user_id', [$ransomwareController, 'show']));
    $r->addRoute('GET', MDIR . 'get-ransomware-activity', checkSession('user_id', [$ransomwareController, 'getActivity']));
    $r->addRoute('GET', MDIR . 'get-ransomware-stats', checkSession('user_id', [$ransomwareController, 'getStats']));
    $r->addRoute('GET', MDIR . 'check-ransomware-threats', checkSession('user_id', [$ransomwareController, 'checkThreats']));
    $r->addRoute('GET', MDIR . 'get-quarantine-files', checkSession('user_id', [$ransomwareController, 'getQuarantineFiles']));
    $r->addRoute('GET', MDIR . 'get-scan-progress', checkSession('user_id', [$ransomwareController, 'getScanProgress']));
    $r->addRoute('GET', MDIR . 'get-monitor-status', checkSession('user_id', [$ransomwareController, 'getStatus']));

    $r->addRoute('POST', MDIR . 'start-full-scan', checkSession('user_id', [$ransomwareController, 'startFullScan']));
    $r->addRoute('POST', MDIR . 'start-quick-scan', checkSession('user_id', [$ransomwareController, 'startQuickScan']));
    $r->addRoute('POST', MDIR . 'start-ransomware-monitor', checkSession('user_id', [$ransomwareController, 'startMonitor']));
    $r->addRoute('POST', MDIR . 'stop-ransomware-monitor', checkSession('user_id', [$ransomwareController, 'stopMonitor']));
    $r->addRoute('POST', MDIR . 'isolate-threats', checkSession('user_id', [$ransomwareController, 'isolateThreats']));
    $r->addRoute('POST', MDIR . 'restore-quarantine-file', checkSession('user_id', [$ransomwareController, 'restoreFile']));
    $r->addRoute('POST', MDIR . 'delete-quarantine-file', checkSession('user_id', [$ransomwareController, 'deleteFile']));
    $r->addRoute('POST', MDIR . 'update-signatures', checkSession('user_id', [$ransomwareController, 'updateSignatures']));
    $r->addRoute('POST', MDIR . 'restore-backup', checkSession('user_id', [$ransomwareController, 'restoreBackup']));

    // ==================== MALWARE ROUTES ====================

    $r->addRoute('GET', MDIR . 'malware', checkSession('user_id', [$malwareController, 'show']));
    $r->addRoute('GET', MDIR . 'get-malware-stats', checkSession('user_id', [$malwareController, 'getStats']));
    $r->addRoute('GET', MDIR . 'get-all-malware-reports', checkSession('user_id', [$malwareController, 'getAllReports']));
    $r->addRoute('GET', MDIR . 'get-malware-report', checkSession('user_id', [$malwareController, 'getReport']));
    $r->addRoute('GET', MDIR . 'get-scan-queue', checkSession('user_id', [$malwareController, 'getScanQueue']));
    $r->addRoute('GET', MDIR . 'get-malware-scan-progress', checkSession('user_id', [$malwareController, 'getScanProgress']));

    $r->addRoute('POST', MDIR . 'upload-malware-sample', checkSession('user_id', [$malwareController, 'uploadSample']));
    $r->addRoute('POST', MDIR . 'start-malware-scan', checkSession('user_id', [$malwareController, 'startScan']));
    $r->addRoute('POST', MDIR . 'delete-malware-sample', checkSession('user_id', [$malwareController, 'deleteSample']));
    $r->addRoute('POST', MDIR . 'export-malware-report', checkSession('user_id', [$malwareController, 'exportReport']));

    // ==================== REPORTING ROUTES ====================

    $r->addRoute('GET', MDIR . 'reporting', checkSession('user_id', [$reportingController, 'show']));
    $r->addRoute('GET', MDIR . 'get-reporting-data', checkSession('user_id', [$reportingController, 'getData']));
    $r->addRoute('GET', MDIR . 'generate-executive-summary', checkSession('user_id', [$reportingController, 'getExecutiveSummary']));
    $r->addRoute('GET', MDIR . 'get-network-statistics', checkSession('user_id', [$reportingController, 'getNetworkStats']));
    $r->addRoute('GET', MDIR . 'get-threat-timeline', checkSession('user_id', [$reportingController, 'getThreatTimeline']));
    $r->addRoute('POST', MDIR . 'export-report-pdf', checkSession('user_id', [$reportingController, 'exportPDF']));
    $r->addRoute('POST', MDIR . 'download-report', checkSession('user_id', [$reportingController, 'downloadReport']));
    $r->addRoute('POST', MDIR . 'email-report', checkSession('user_id', [$reportingController, 'emailReport']));

    // ==================== PROFILE ROUTES ====================

    $r->addRoute('GET', MDIR . 'profile', checkSession('user_id', [$profileController, 'show']));
    $r->addRoute('POST', MDIR . 'update-profile', checkSession('user_id', [$profileController, 'updateProfile']));
    $r->addRoute('POST', MDIR . 'upload-profile-picture', checkSession('user_id', [$profileController, 'uploadPicture']));
    $r->addRoute('POST', MDIR . 'delete-profile-picture', checkSession('user_id', [$profileController, 'deletePicture']));
    $r->addRoute('POST', MDIR . 'change-password', checkSession('user_id', [$profileController, 'changePassword']));

    // ==================== SETTINGS ROUTES ====================

    $r->addRoute('GET', MDIR . 'settings', checkSession('user_id', [$settingsController, 'show']));
    $r->addRoute('POST', MDIR . 'update-password', checkSession('user_id', [$authController, 'updatePassword']));
    $r->addRoute('POST', MDIR . 'save-settings', checkSession('user_id', [$settingsController, 'saveSettings']));
    $r->addRoute('POST', MDIR . 'save-api-keys', checkSession('user_id', [$settingsController, 'saveApiKeys']));
    $r->addRoute('POST', MDIR . 'clear-all-logs', checkSession('user_id', [$viewController, 'clearAllLogs']));
    $r->addRoute('POST', MDIR . 'export-user-data', checkSession('user_id', [$profileController, 'exportData']));
    $r->addRoute('POST', MDIR . 'terminate-sessions', checkSession('user_id', [$profileController, 'terminateSessions']));
    $r->addRoute('POST', MDIR . 'delete-account', checkSession('user_id', [$profileController, 'deleteAccount']));
    $r->addRoute('GET', MDIR . 'get-user-stats', checkSession('user_id', [$settingsController, 'getUserStats']));

    // ==================== NOTIFICATION ROUTES ====================

    $r->addRoute('GET', MDIR . 'get-notifications', checkSession('user_id', [$notificationController, 'getNotifications']));
    $r->addRoute('POST', MDIR . 'mark-notification-read', checkSession('user_id', [$notificationController, 'markAsRead']));
    $r->addRoute('POST', MDIR . 'mark-all-notifications-read', checkSession('user_id', [$notificationController, 'markAllAsRead']));
    $r->addRoute('POST', MDIR . 'delete-notification', checkSession('user_id', [$notificationController, 'deleteNotification']));
    $r->addRoute('POST', MDIR . 'clear-all-notifications', checkSession('user_id', [$notificationController, 'clearAll']));

    // ==================== THREAT INTELLIGENCE ROUTES ====================

    $r->addRoute('GET', MDIR . 'threat-intelligence', checkSession('user_id', [$threatController, 'show']));
    $r->addRoute('GET', MDIR . 'get-threat-feeds', checkSession('user_id', [$threatController, 'getThreatFeeds']));
    $r->addRoute('GET', MDIR . 'get-threat-actors', checkSession('user_id', [$threatController, 'getThreatActors']));
    $r->addRoute('GET', MDIR . 'get-iocs', checkSession('user_id', [$threatController, 'getIOCs']));
    $r->addRoute('GET', MDIR . 'get-vulnerabilities', checkSession('user_id', [$threatController, 'getVulnerabilities']));
    $r->addRoute('POST', MDIR . 'block-ioc', checkSession('user_id', [$threatController, 'blockIOC']));
    $r->addRoute('POST', MDIR . 'whitelist-ioc', checkSession('user_id', [$threatController, 'whitelistIOC']));

    // ==================== NETWORK ANALYTICS ROUTES ====================

    $r->addRoute('GET', MDIR . 'network-analytics', checkSession('user_id', [$networkController, 'show']));
    $r->addRoute('GET', MDIR . 'get-network-metrics', checkSession('user_id', [$networkController, 'getMetrics']));
    $r->addRoute('GET', MDIR . 'get-bandwidth-data', checkSession('user_id', [$networkController, 'getBandwidthData']));
    $r->addRoute('GET', MDIR . 'get-protocol-stats', checkSession('user_id', [$networkController, 'getProtocolStats']));
    $r->addRoute('GET', MDIR . 'get-top-talkers', checkSession('user_id', [$networkController, 'getTopTalkers']));
    $r->addRoute('GET', MDIR . 'get-active-connections', checkSession('user_id', [$networkController, 'getActiveConnections']));
    $r->addRoute('GET', MDIR . 'get-packet-activity', checkSession('user_id', [$networkController, 'getPacketActivity']));

    // ==================== GDPR ROUTES ====================

    $r->addRoute('GET', MDIR . 'gdpr/verify/{token}', 'get_gdpr_verify_page');

    // ==================== LEGACY/TEST ROUTES ====================

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
        $alertService = new AlertService();
        $alertService->displayError("405 Method Not Allowed");
        break;

    case FastRoute\Dispatcher::FOUND:
        // Handle the request
        $handler = $routeInfo[1];
        $vars = $routeInfo[2];
        call_user_func($handler, $vars);
        break;
}
?>
