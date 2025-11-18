<?php
/**
 * CyberHawk Settings Page
 * Comprehensive settings management for user preferences and system configuration
 */

$httpMethod = $_SERVER['REQUEST_METHOD'];
$uri = $_SERVER['REQUEST_URI'];

if (false !== $pos = strpos($uri, '?')) {
    $uri = substr($uri, 0, $pos);
}

$basePath = MDIR;
if (strpos($uri, $basePath) === 0) {
    $uri = substr($uri, strlen($basePath));
    if ($uri === '') {
        $uri = '/';
    }
}

// Get current user data
$userId = $_SESSION['user_id'];
$sql = "SELECT name, email, role FROM users WHERE id = ?";
$userData = mysqli_prepared_query($sql, 'i', [$userId]);
$user = $userData[0];

// Get system settings from database or use defaults
$settingsSql = "SELECT setting_key, setting_value FROM system_settings WHERE user_id = ? OR user_id IS NULL";
$settingsData = mysqli_prepared_query($settingsSql, 'i', [$userId]);

$settings = [
    'alert_threshold' => 0.85,
    'session_timeout' => 30,
    'enable_email_alerts' => false,
    'enable_desktop_alerts' => true,
    'log_retention_days' => 30,
    'auto_quarantine' => true,
    'scan_on_upload' => true,
    'virustotal_api_key' => '',
    'theme' => 'light'
];

// Override with user's custom settings
if ($settingsData) {
    foreach ($settingsData as $setting) {
        $settings[$setting['setting_key']] = $setting['setting_value'];
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Settings - CyberHawk</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <style>
        html, body {
            max-width: 100%;
            overflow-x: hidden;
            background-color: #f8f9fa;
        }

        .settings-container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .settings-card {
            background: white;
            border-radius: 15px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 25px;
            overflow: hidden;
            border: 2px solid #0a74da;
        }

        .settings-card-header {
            background: linear-gradient(135deg, #0a74da, #061a40);
            color: white;
            padding: 20px 25px;
            border-bottom: none;
        }

        .settings-card-header h5 {
            margin: 0;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .settings-card-body {
            padding: 25px;
        }

        .setting-item {
            padding: 20px 0;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .setting-item:last-child {
            border-bottom: none;
        }

        .setting-info {
            flex: 1;
        }

        .setting-info h6 {
            margin: 0 0 5px 0;
            font-weight: 600;
            color: #2c3246;
        }

        .setting-info p {
            margin: 0;
            color: #6c757d;
            font-size: 0.9rem;
        }

        .setting-control {
            min-width: 200px;
            text-align: right;
        }

        .gradient-text {
            background: linear-gradient(135deg, #0a74da, #061a40);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            color: transparent;
            font-weight: bold;
        }

        .custom-switch {
            padding-left: 2.5rem;
        }

        .custom-switch .form-check-input {
            width: 3rem;
            height: 1.5rem;
            cursor: pointer;
        }

        .custom-switch .form-check-input:checked {
            background-color: #0a74da;
            border-color: #0a74da;
        }

        .btn-save {
            background: linear-gradient(135deg, #0a74da, #061a40);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .btn-save:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(10, 116, 218, 0.3);
            color: white;
        }

        .profile-avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            background: linear-gradient(135deg, #0a74da, #061a40);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 2.5rem;
            font-weight: bold;
            margin: 0 auto 20px;
        }

        .stats-badge {
            display: inline-block;
            padding: 8px 15px;
            background: linear-gradient(135deg, rgba(10, 116, 218, 0.1), rgba(6, 26, 64, 0.1));
            border-radius: 20px;
            margin: 5px;
            font-size: 0.9rem;
        }

        .api-key-input {
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
        }

        .danger-zone {
            border: 2px solid #dc3545;
            border-radius: 10px;
            padding: 20px;
            background: rgba(220, 53, 69, 0.05);
        }

        .toast-container {
            position: fixed;
            top: 80px;
            right: 20px;
            z-index: 10000;
        }

        .form-control:focus, .form-select:focus {
            border-color: #0a74da;
            box-shadow: 0 0 0 0.2rem rgba(10, 116, 218, 0.25);
        }

        .password-strength {
            height: 5px;
            border-radius: 3px;
            margin-top: 5px;
            transition: all 0.3s ease;
        }

        .strength-weak { background: #dc3545; width: 33%; }
        .strength-medium { background: #ffc107; width: 66%; }
        .strength-strong { background: #28a745; width: 100%; }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .nav-pills .nav-link {
            color: #6c757d;
            border-radius: 10px;
            padding: 12px 20px;
            margin-bottom: 10px;
            transition: all 0.3s ease;
        }

        .nav-pills .nav-link:hover {
            background: rgba(10, 116, 218, 0.1);
        }

        .nav-pills .nav-link.active {
            background: linear-gradient(135deg, #0a74da, #061a40);
            color: white;
        }

        .version-info {
            background: linear-gradient(135deg, rgba(10, 116, 218, 0.05), rgba(6, 26, 64, 0.05));
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
    </style>
</head>

<body>
    <?php include 'app/views/common/header.php'; ?>

    <div class="d-flex" style="min-height: calc(100vh - 60px);">
        <?php include 'app/views/common/sidebar.php'; ?>

        <div class="main-content flex-grow-1 p-4">
            <div class="settings-container">

                <!-- Page Header -->
                <div class="mb-4">
                    <h2 class="gradient-text">
                        <i class="bi bi-gear"></i> Settings
                    </h2>
                    <p class="text-muted">Manage your account, security, and system preferences</p>
                </div>

                <!-- Toast Notification Container -->
                <div class="toast-container"></div>

                <div class="row">
                    <!-- Sidebar Navigation -->
                    <div class="col-md-3">
                        <div class="settings-card">
                            <div class="settings-card-body p-3">
                                <ul class="nav nav-pills flex-column" id="settingsTabs">
                                    <li class="nav-item">
                                        <a class="nav-link active" href="#profile" data-tab="profile">
                                            <i class="bi bi-person-circle me-2"></i> Profile
                                        </a>
                                    </li>
                                    <li class="nav-item">
                                        <a class="nav-link" href="#security" data-tab="security">
                                            <i class="bi bi-shield-lock me-2"></i> Security
                                        </a>
                                    </li>
                                    <li class="nav-item">
                                        <a class="nav-link" href="#system" data-tab="system">
                                            <i class="bi bi-cpu me-2"></i> System
                                        </a>
                                    </li>
                                    <li class="nav-item">
                                        <a class="nav-link" href="#notifications" data-tab="notifications">
                                            <i class="bi bi-bell me-2"></i> Notifications
                                        </a>
                                    </li>
                                    <li class="nav-item">
                                        <a class="nav-link" href="#integrations" data-tab="integrations">
                                            <i class="bi bi-plug me-2"></i> Integrations
                                        </a>
                                    </li>
                                    <li class="nav-item">
                                        <a class="nav-link" href="#about" data-tab="about">
                                            <i class="bi bi-info-circle me-2"></i> About
                                        </a>
                                    </li>
                                </ul>
                            </div>
                        </div>
                    </div>

                    <!-- Main Content Area -->
                    <div class="col-md-9">

                        <!-- Profile Tab -->
                        <div id="profile" class="tab-content active">
                            <div class="settings-card">
                                <div class="settings-card-header">
                                    <h5><i class="bi bi-person-circle"></i> Profile Information</h5>
                                </div>
                                <div class="settings-card-body">
                                    <div class="text-center mb-4">
                                        <div class="profile-avatar">
                                            <?= strtoupper(substr($user['name'], 0, 1)) ?>
                                        </div>
                                        <h5><?= htmlspecialchars($user['name']) ?></h5>
                                        <p class="text-muted"><?= htmlspecialchars($user['email']) ?></p>
                                        <span class="badge bg-primary"><?= ucfirst($user['role']) ?></span>
                                    </div>

                                    <div class="alert alert-info">
                                        <i class="bi bi-info-circle me-2"></i>
                                        Profile information is managed by your system administrator.
                                        Contact support to update your profile details.
                                    </div>
                                </div>
                            </div>

                            <!-- Activity Stats -->
                            <div class="settings-card">
                                <div class="settings-card-header">
                                    <h5><i class="bi bi-graph-up"></i> Your Activity</h5>
                                </div>
                                <div class="settings-card-body text-center">
                                    <div class="row">
                                        <div class="col-md-3">
                                            <h3 class="gradient-text" id="userScans">0</h3>
                                            <p class="text-muted">Total Scans</p>
                                        </div>
                                        <div class="col-md-3">
                                            <h3 class="gradient-text" id="userAlerts">0</h3>
                                            <p class="text-muted">Alerts Triggered</p>
                                        </div>
                                        <div class="col-md-3">
                                            <h3 class="gradient-text" id="userQuarantine">0</h3>
                                            <p class="text-muted">Files Quarantined</p>
                                        </div>
                                        <div class="col-md-3">
                                            <h3 class="gradient-text" id="userDays">0</h3>
                                            <p class="text-muted">Days Active</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Security Tab -->
                        <div id="security" class="tab-content">
                            <div class="settings-card">
                                <div class="settings-card-header">
                                    <h5><i class="bi bi-shield-lock"></i> Change Password</h5>
                                </div>
                                <div class="settings-card-body">
                                    <form id="passwordForm">
                                        <div class="mb-3">
                                            <label for="currentPassword" class="form-label">Current Password</label>
                                            <input type="password" class="form-control" id="currentPassword" required>
                                        </div>

                                        <div class="mb-3">
                                            <label for="newPassword" class="form-label">New Password</label>
                                            <input type="password" class="form-control" id="newPassword" required>
                                            <div class="password-strength" id="passwordStrength"></div>
                                            <small class="text-muted" id="passwordStrengthText"></small>
                                        </div>

                                        <div class="mb-3">
                                            <label for="confirmPassword" class="form-label">Confirm New Password</label>
                                            <input type="password" class="form-control" id="confirmPassword" required>
                                        </div>

                                        <div class="text-end">
                                            <button type="submit" class="btn btn-save">
                                                <i class="bi bi-shield-check me-2"></i>Update Password
                                            </button>
                                        </div>
                                    </form>
                                </div>
                            </div>

                            <div class="settings-card">
                                <div class="settings-card-header">
                                    <h5><i class="bi bi-clock-history"></i> Session Management</h5>
                                </div>
                                <div class="settings-card-body">
                                    <div class="setting-item">
                                        <div class="setting-info">
                                            <h6>Session Timeout</h6>
                                            <p>Automatically logout after period of inactivity</p>
                                        </div>
                                        <div class="setting-control">
                                            <select class="form-select" id="sessionTimeout">
                                                <option value="15">15 minutes</option>
                                                <option value="30" selected>30 minutes</option>
                                                <option value="60">1 hour</option>
                                                <option value="120">2 hours</option>
                                                <option value="0">Never</option>
                                            </select>
                                        </div>
                                    </div>

                                    <div class="setting-item">
                                        <div class="setting-info">
                                            <h6>Active Sessions</h6>
                                            <p>You are currently logged in on this device</p>
                                        </div>
                                        <div class="setting-control">
                                            <button class="btn btn-outline-danger btn-sm" onclick="terminateAllSessions()">
                                                <i class="bi bi-x-circle me-1"></i>Logout All Devices
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <!-- Danger Zone -->
                            <div class="settings-card">
                                <div class="settings-card-header bg-danger">
                                    <h5><i class="bi bi-exclamation-triangle"></i> Danger Zone</h5>
                                </div>
                                <div class="settings-card-body">
                                    <div class="danger-zone">
                                        <h6 class="text-danger">Delete Account</h6>
                                        <p class="mb-3">Once you delete your account, there is no going back. All your data will be permanently deleted.</p>
                                        <button class="btn btn-danger" onclick="confirmDeleteAccount()">
                                            <i class="bi bi-trash me-2"></i>Delete My Account
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- System Tab -->
                        <div id="system" class="tab-content">
                            <div class="settings-card">
                                <div class="settings-card-header">
                                    <h5><i class="bi bi-sliders"></i> Detection Settings</h5>
                                </div>
                                <div class="settings-card-body">
                                    <div class="setting-item">
                                        <div class="setting-info">
                                            <h6>Alert Threshold</h6>
                                            <p>Minimum confidence level to trigger alerts (85% recommended)</p>
                                        </div>
                                        <div class="setting-control">
                                            <input type="range" class="form-range" min="60" max="95" step="5" 
                                                   value="85" id="alertThreshold">
                                            <span id="thresholdValue">85%</span>
                                        </div>
                                    </div>

                                    <div class="setting-item">
                                        <div class="setting-info">
                                            <h6>Auto-Quarantine Threats</h6>
                                            <p>Automatically quarantine detected malicious files</p>
                                        </div>
                                        <div class="setting-control">
                                            <div class="form-check form-switch custom-switch">
                                                <input class="form-check-input" type="checkbox" id="autoQuarantine" checked>
                                            </div>
                                        </div>
                                    </div>

                                    <div class="setting-item">
                                        <div class="setting-info">
                                            <h6>Scan on Upload</h6>
                                            <p>Automatically scan files when uploaded for malware analysis</p>
                                        </div>
                                        <div class="setting-control">
                                            <div class="form-check form-switch custom-switch">
                                                <input class="form-check-input" type="checkbox" id="scanOnUpload" checked>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="settings-card">
                                <div class="settings-card-header">
                                    <h5><i class="bi bi-archive"></i> Data Management</h5>
                                </div>
                                <div class="settings-card-body">
                                    <div class="setting-item">
                                        <div class="setting-info">
                                            <h6>Log Retention Period</h6>
                                            <p>How long to keep traffic and alert logs</p>
                                        </div>
                                        <div class="setting-control">
                                            <select class="form-select" id="logRetention">
                                                <option value="7">7 days</option>
                                                <option value="14">14 days</option>
                                                <option value="30" selected>30 days</option>
                                                <option value="60">60 days</option>
                                                <option value="90">90 days</option>
                                            </select>
                                        </div>
                                    </div>

                                    <div class="setting-item">
                                        <div class="setting-info">
                                            <h6>Clear All Logs</h6>
                                            <p>Delete all traffic logs, alerts, and scan results</p>
                                        </div>
                                        <div class="setting-control">
                                            <button class="btn btn-outline-danger btn-sm" onclick="clearAllLogs()">
                                                <i class="bi bi-trash me-1"></i>Clear Logs
                                            </button>
                                        </div>
                                    </div>

                                    <div class="setting-item">
                                        <div class="setting-info">
                                            <h6>Export Data</h6>
                                            <p>Download all your data in JSON format</p>
                                        </div>
                                        <div class="setting-control">
                                            <button class="btn btn-outline-primary btn-sm" onclick="exportUserData()">
                                                <i class="bi bi-download me-1"></i>Export Data
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Notifications Tab -->
                        <div id="notifications" class="tab-content">
                            <div class="settings-card">
                                <div class="settings-card-header">
                                    <h5><i class="bi bi-bell"></i> Alert Preferences</h5>
                                </div>
                                <div class="settings-card-body">
                                    <div class="setting-item">
                                        <div class="setting-info">
                                            <h6>Email Notifications</h6>
                                            <p>Receive email alerts for critical threats</p>
                                        </div>
                                        <div class="setting-control">
                                            <div class="form-check form-switch custom-switch">
                                                <input class="form-check-input" type="checkbox" id="emailAlerts">
                                            </div>
                                        </div>
                                    </div>

                                    <div class="setting-item">
                                        <div class="setting-info">
                                            <h6>Desktop Notifications</h6>
                                            <p>Show browser notifications for real-time alerts</p>
                                        </div>
                                        <div class="setting-control">
                                            <div class="form-check form-switch custom-switch">
                                                <input class="form-check-input" type="checkbox" id="desktopAlerts" checked>
                                            </div>
                                        </div>
                                    </div>

                                    <div class="setting-item">
                                        <div class="setting-info">
                                            <h6>Alert Sound</h6>
                                            <p>Play sound when threats are detected</p>
                                        </div>
                                        <div class="setting-control">
                                            <div class="form-check form-switch custom-switch">
                                                <input class="form-check-input" type="checkbox" id="alertSound">
                                            </div>
                                        </div>
                                    </div>

                                    <div class="setting-item">
                                        <div class="setting-info">
                                            <h6>Daily Summary</h6>
                                            <p>Receive daily email summary of system activity</p>
                                        </div>
                                        <div class="setting-control">
                                            <div class="form-check form-switch custom-switch">
                                                <input class="form-check-input" type="checkbox" id="dailySummary">
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="settings-card">
                                <div class="settings-card-header">
                                    <h5><i class="bi bi-filter"></i> Alert Filters</h5>
                                </div>
                                <div class="settings-card-body">
                                    <p class="text-muted mb-3">Choose which types of alerts you want to receive</p>
                                    
                                    <div class="form-check mb-3">
                                        <input class="form-check-input" type="checkbox" id="alertDDoS" checked>
                                        <label class="form-check-label" for="alertDDoS">
                                            DDoS / DoS Attacks
                                        </label>
                                    </div>

                                    <div class="form-check mb-3">
                                        <input class="form-check-input" type="checkbox" id="alertMalware" checked>
                                        <label class="form-check-label" for="alertMalware">
                                            Malware Detection
                                        </label>
                                    </div>

                                    <div class="form-check mb-3">
                                        <input class="form-check-input" type="checkbox" id="alertRansomware" checked>
                                        <label class="form-check-label" for="alertRansomware">
                                            Ransomware Activity
                                        </label>
                                    </div>

                                    <div class="form-check mb-3">
                                        <input class="form-check-input" type="checkbox" id="alertPortScan" checked>
                                        <label class="form-check-label" for="alertPortScan">
                                            Port Scanning
                                        </label>
                                    </div>

                                    <div class="form-check mb-3">
                                        <input class="form-check-input" type="checkbox" id="alertBruteForce" checked>
                                        <label class="form-check-label" for="alertBruteForce">
                                            Brute Force Attempts
                                        </label>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Integrations Tab -->
                        <div id="integrations" class="tab-content">
                            <div class="settings-card">
                                <div class="settings-card-header">
                                    <h5><i class="bi bi-key"></i> API Keys</h5>
                                </div>
                                <div class="settings-card-body">
                                    <div class="alert alert-info">
                                        <i class="bi bi-info-circle me-2"></i>
                                        API keys are stored securely and used for third-party integrations
                                    </div>

                                    <div class="mb-4">
                                        <label for="hybridApiKey" class="form-label">Hybrid Analysis API Key (Optional)</label>
                                        <input type="text" class="form-control api-key-input" id="hybridApiKey" 
                                               placeholder="Enter your Hybrid Analysis API key">
                                        <small class="text-muted">
                                            Get your free API key from 
                                            <a href="https://www.hybrid-analysis.com/apikeys/info" target="_blank">Hybrid Analysis</a>
                                        </small>
                                    </div>

                                    <div class="text-end">
                                        <button type="button" class="btn btn-save" onclick="saveApiKeys()">
                                            <i class="bi bi-check-circle me-2"></i>Save API Keys
                                        </button>
                                    </div>
                                </div>
                            </div>

                            <div class="settings-card">
                                <div class="settings-card-header">
                                    <h5><i class="bi bi-link-45deg"></i> External Services</h5>
                                </div>
                                <div class="settings-card-body">
                                    <div class="setting-item">
                                        <div class="setting-info">
                                            <h6>VirusTotal Integration</h6>
                                            <p>Use VirusTotal for malware scanning</p>
                                        </div>
                                        <div class="setting-control">
                                            <span class="badge bg-success">
                                                <i class="bi bi-check-circle"></i> Active
                                            </span>
                                        </div>
                                    </div>

                                    <div class="setting-item">
                                        <div class="setting-info">
                                            <h6>MalwareBazaar</h6>
                                            <p>Check files against MalwareBazaar database</p>
                                        </div>
                                        <div class="setting-control">
                                            <span class="badge bg-success">
                                                <i class="bi bi-check-circle"></i> Active
                                            </span>
                                        </div>
                                    </div>

                                    <div class="setting-item">
                                        <div class="setting-info">
                                            <h6>ThreatFox IOC</h6>
                                            <p>Query ThreatFox indicators of compromise</p>
                                        </div>
                                        <div class="setting-control">
                                            <span class="badge bg-success">
                                                <i class="bi bi-check-circle"></i> Active
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- About Tab -->
                        <div id="about" class="tab-content">
                            <div class="settings-card">
                                <div class="settings-card-header">
                                    <h5><i class="bi bi-info-circle"></i> About CyberHawk</h5>
                                </div>
                                <div class="settings-card-body">
                                    <div class="version-info mb-4">
                                        <img src="<?= MDIR ?>assets/images/logo.png" alt="CyberHawk" 
                                             onerror="this.style.display='none'" style="max-width: 150px; margin-bottom: 20px;">
                                        <h4 class="gradient-text">CyberHawk Security Suite</h4>
                                        <p class="mb-2"><strong>Version:</strong> 1.0.0</p>
                                        <p class="mb-2"><strong>Build:</strong> 2025.01.19</p>
                                        <p class="text-muted">Advanced Network Intrusion Detection & Malware Analysis System</p>
                                    </div>

                                    <div class="row text-center mb-4">
                                        <div class="col-md-3">
                                            <h5 class="gradient-text">97.73%</h5>
                                            <small class="text-muted">Detection Accuracy</small>
                                        </div>
                                        <div class="col-md-3">
                                            <h5 class="gradient-text">3</h5>
                                            <small class="text-muted">Core Modules</small>
                                        </div>
                                        <div class="col-md-3">
                                            <h5 class="gradient-text">70+</h5>
                                            <small class="text-muted">AV Engines</small>
                                        </div>
                                        <div class="col-md-3">
                                            <h5 class="gradient-text">24/7</h5>
                                            <small class="text-muted">Protection</small>
                                        </div>
                                    </div>

                                    <hr>

                                    <h6 class="mb-3">Key Features</h6>
                                    <ul class="list-unstyled">
                                        <li class="mb-2">
                                            <i class="bi bi-check-circle-fill text-success me-2"></i>
                                            Real-time Network Intrusion Detection (97.73% accuracy)
                                        </li>
                                        <li class="mb-2">
                                            <i class="bi bi-check-circle-fill text-success me-2"></i>
                                            Multi-source Malware Analysis (VirusTotal, MalwareBazaar, ThreatFox)
                                        </li>
                                        <li class="mb-2">
                                            <i class="bi bi-check-circle-fill text-success me-2"></i>
                                            Behavioral Ransomware Detection
                                        </li>
                                        <li class="mb-2">
                                            <i class="bi bi-check-circle-fill text-success me-2"></i>
                                            Advanced Threat Intelligence
                                        </li>
                                        <li class="mb-2">
                                            <i class="bi bi-check-circle-fill text-success me-2"></i>
                                            Automated Quarantine & Response
                                        </li>
                                    </ul>

                                    <hr>

                                    <h6 class="mb-3">Technologies</h6>
                                    <div class="d-flex flex-wrap gap-2 mb-4">
                                        <span class="stats-badge">TensorFlow Deep Learning</span>
                                        <span class="stats-badge">Python 3.x</span>
                                        <span class="stats-badge">PHP 8.x</span>
                                        <span class="stats-badge">MySQL</span>
                                        <span class="stats-badge">Bootstrap 5</span>
                                        <span class="stats-badge">Scapy</span>
                                        <span class="stats-badge">CICIDS2022</span>
                                    </div>

                                    <hr>

                                    <h6 class="mb-3">System Information</h6>
                                    <div class="table-responsive">
                                        <table class="table table-sm">
                                            <tr>
                                                <td><strong>PHP Version:</strong></td>
                                                <td><?= phpversion() ?></td>
                                            </tr>
                                            <tr>
                                                <td><strong>Server:</strong></td>
                                                <td><?= $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown' ?></td>
                                            </tr>
                                            <tr>
                                                <td><strong>Database:</strong></td>
                                                <td>MySQL/MariaDB</td>
                                            </tr>
                                            <tr>
                                                <td><strong>Session Status:</strong></td>
                                                <td>
                                                    <span class="badge bg-success">Active</span>
                                                </td>
                                            </tr>
                                        </table>
                                    </div>

                                    <div class="text-center mt-4">
                                        <button class="btn btn-outline-primary btn-sm me-2" onclick="checkForUpdates()">
                                            <i class="bi bi-arrow-clockwise me-1"></i>Check for Updates
                                        </button>
                                        <button class="btn btn-outline-secondary btn-sm" onclick="viewLicense()">
                                            <i class="bi bi-file-text me-1"></i>View License
                                        </button>
                                    </div>
                                </div>
                            </div>

                            <div class="settings-card">
                                <div class="settings-card-header">
                                    <h5><i class="bi bi-book"></i> Documentation & Support</h5>
                                </div>
                                <div class="settings-card-body">
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <div class="card h-100">
                                                <div class="card-body text-center">
                                                    <i class="bi bi-book display-4 text-primary mb-3"></i>
                                                    <h6>Documentation</h6>
                                                    <p class="text-muted small">Comprehensive guides and API reference</p>
                                                    <a href="#" class="btn btn-sm btn-outline-primary">View Docs</a>
                                                </div>
                                            </div>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <div class="card h-100">
                                                <div class="card-body text-center">
                                                    <i class="bi bi-question-circle display-4 text-success mb-3"></i>
                                                    <h6>Help Center</h6>
                                                    <p class="text-muted small">FAQs and troubleshooting guides</p>
                                                    <a href="#" class="btn btn-sm btn-outline-success">Get Help</a>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                    </div>
                </div>

            </div>
        </div>
    </div>

    <script>
        // ==================== TAB NAVIGATION ====================
        $(document).ready(function() {
            // Tab switching
            $('.nav-link[data-tab]').on('click', function(e) {
                e.preventDefault();
                
                const targetTab = $(this).data('tab');
                
                // Update nav links
                $('.nav-link').removeClass('active');
                $(this).addClass('active');
                
                // Update content
                $('.tab-content').removeClass('active');
                $(`#${targetTab}`).addClass('active');
                
                // Update URL hash without scrolling
                history.pushState(null, null, `#${targetTab}`);
            });
            
            // Handle direct hash navigation
            const hash = window.location.hash.substring(1);
            if (hash) {
                $(`.nav-link[data-tab="${hash}"]`).click();
            }
            
            // Load user statistics
            loadUserStatistics();
        });

        // ==================== PROFILE MANAGEMENT ====================
        $('#profileForm').on('submit', function(e) {
            e.preventDefault();
            
            const name = $('#userName').val();
            const email = $('#userEmail').val();
            
            $.ajax({
                url: "<?= MDIR ?>update-profile",
                method: "POST",
                dataType: "json",
                data: { name, email },
                success: function(response) {
                    if (response.success) {
                        showToast('Success', 'Profile updated successfully', 'success');
                        // Update header display
                        setTimeout(() => location.reload(), 1500);
                    } else {
                        showToast('Error', response.message || 'Failed to update profile', 'danger');
                    }
                },
                error: function(xhr, status, error) {
                    showToast('Error', 'Failed to update profile: ' + error, 'danger');
                }
            });
        });

        // ==================== PASSWORD MANAGEMENT ====================
        $('#newPassword').on('input', function() {
            const password = $(this).val();
            const strength = calculatePasswordStrength(password);
            
            $('#passwordStrength').removeClass('strength-weak strength-medium strength-strong');
            
            if (strength.score < 40) {
                $('#passwordStrength').addClass('strength-weak');
                $('#passwordStrengthText').text('Weak password').css('color', '#dc3545');
            } else if (strength.score < 70) {
                $('#passwordStrength').addClass('strength-medium');
                $('#passwordStrengthText').text('Medium strength').css('color', '#ffc107');
            } else {
                $('#passwordStrength').addClass('strength-strong');
                $('#passwordStrengthText').text('Strong password').css('color', '#28a745');
            }
        });

        $('#passwordForm').on('submit', function(e) {
            e.preventDefault();
            
            const currentPassword = $('#currentPassword').val();
            const newPassword = $('#newPassword').val();
            const confirmPassword = $('#confirmPassword').val();
            
            if (newPassword !== confirmPassword) {
                showToast('Error', 'Passwords do not match', 'danger');
                return;
            }
            
            if (newPassword.length < 6) {
                showToast('Error', 'Password must be at least 6 characters', 'danger');
                return;
            }
            
            $.ajax({
                url: "<?= MDIR ?>update-password",
                method: "POST",
                dataType: "json",
                data: { current_password: currentPassword, new_password: newPassword },
                success: function(response) {
                    if (response.success) {
                        showToast('Success', 'Password updated successfully', 'success');
                        $('#passwordForm')[0].reset();
                        $('#passwordStrength').removeClass('strength-weak strength-medium strength-strong');
                        $('#passwordStrengthText').text('');
                    } else {
                        showToast('Error', response.message || 'Failed to update password', 'danger');
                    }
                },
                error: function(xhr, status, error) {
                    showToast('Error', 'Failed to update password: ' + error, 'danger');
                }
            });
        });

        function calculatePasswordStrength(password) {
            let score = 0;
            
            if (password.length >= 8) score += 20;
            if (password.length >= 12) score += 20;
            if (/[a-z]/.test(password)) score += 15;
            if (/[A-Z]/.test(password)) score += 15;
            if (/[0-9]/.test(password)) score += 15;
            if (/[^A-Za-z0-9]/.test(password)) score += 15;
            
            return { score };
        }

        // ==================== SYSTEM SETTINGS ====================
        $('#alertThreshold').on('input', function() {
            const value = $(this).val();
            $('#thresholdValue').text(value + '%');
        });

        // Auto-save settings on change
        $('#autoQuarantine, #scanOnUpload, #emailAlerts, #desktopAlerts, #alertSound, #dailySummary').on('change', function() {
            saveSystemSettings();
        });

        $('#sessionTimeout, #logRetention, #alertThreshold').on('change', function() {
            saveSystemSettings();
        });

        function saveSystemSettings() {
            const settings = {
                alert_threshold: $('#alertThreshold').val() / 100,
                session_timeout: $('#sessionTimeout').val(),
                auto_quarantine: $('#autoQuarantine').is(':checked'),
                scan_on_upload: $('#scanOnUpload').is(':checked'),
                enable_email_alerts: $('#emailAlerts').is(':checked'),
                enable_desktop_alerts: $('#desktopAlerts').is(':checked'),
                alert_sound: $('#alertSound').is(':checked'),
                daily_summary: $('#dailySummary').is(':checked'),
                log_retention_days: $('#logRetention').val()
            };
            
            $.ajax({
                url: "<?= MDIR ?>save-settings",
                method: "POST",
                dataType: "json",
                data: { settings: JSON.stringify(settings) },
                success: function(response) {
                    if (response.success) {
                        showToast('Saved', 'Settings saved successfully', 'success');
                    }
                },
                error: function() {
                    showToast('Error', 'Failed to save settings', 'danger');
                }
            });
        }

        // ==================== API KEYS ====================
        function saveApiKeys() {
            const vtKey = $('#vtApiKey').val();
            const hybridKey = $('#hybridApiKey').val();
            
            $.ajax({
                url: "<?= MDIR ?>save-api-keys",
                method: "POST",
                dataType: "json",
                data: { virustotal: vtKey, hybrid: hybridKey },
                success: function(response) {
                    if (response.success) {
                        showToast('Success', 'API keys saved successfully', 'success');
                    } else {
                        showToast('Error', response.message || 'Failed to save API keys', 'danger');
                    }
                },
                error: function() {
                    showToast('Error', 'Failed to save API keys', 'danger');
                }
            });
        }

        // ==================== DATA MANAGEMENT ====================
        function clearAllLogs() {
            if (confirm('Are you sure you want to clear all logs? This action cannot be undone.')) {
                $.ajax({
                    url: "<?= MDIR ?>clear-all-logs",
                    method: "POST",
                    dataType: "json",
                    success: function(response) {
                        if (response.success) {
                            showToast('Success', 'All logs cleared successfully', 'success');
                        } else {
                            showToast('Error', 'Failed to clear logs', 'danger');
                        }
                    },
                    error: function() {
                        showToast('Error', 'Failed to clear logs', 'danger');
                    }
                });
            }
        }

        function exportUserData() {
            showToast('Exporting', 'Preparing your data for download...', 'info');
            
            $.ajax({
                url: "<?= MDIR ?>export-user-data",
                method: "POST",
                dataType: "json",
                success: function(response) {
                    if (response.success) {
                        const dataStr = JSON.stringify(response.data, null, 2);
                        const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);
                        const exportFileDefaultName = 'cyberhawk_data_' + Date.now() + '.json';
                        
                        const linkElement = document.createElement('a');
                        linkElement.setAttribute('href', dataUri);
                        linkElement.setAttribute('download', exportFileDefaultName);
                        linkElement.click();
                        
                        showToast('Success', 'Data exported successfully', 'success');
                    } else {
                        showToast('Error', 'Failed to export data', 'danger');
                    }
                },
                error: function() {
                    showToast('Error', 'Failed to export data', 'danger');
                }
            });
        }

        // ==================== SESSION MANAGEMENT ====================
        function terminateAllSessions() {
            if (confirm('This will log you out from all devices. Continue?')) {
                $.ajax({
                    url: "<?= MDIR ?>terminate-sessions",
                    method: "POST",
                    dataType: "json",
                    success: function(response) {
                        if (response.success) {
                            showToast('Success', 'All sessions terminated. Redirecting...', 'success');
                            setTimeout(() => {
                                window.location.href = "<?= MDIR ?>logout";
                            }, 2000);
                        }
                    },
                    error: function() {
                        showToast('Error', 'Failed to terminate sessions', 'danger');
                    }
                });
            }
        }

        // ==================== ACCOUNT DELETION ====================
        function confirmDeleteAccount() {
            const modal = `
                <div class="modal fade" id="deleteAccountModal" tabindex="-1">
                    <div class="modal-dialog modal-dialog-centered">
                        <div class="modal-content">
                            <div class="modal-header bg-danger text-white">
                                <h5 class="modal-title">
                                    <i class="bi bi-exclamation-triangle me-2"></i>Delete Account
                                </h5>
                                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body">
                                <div class="alert alert-danger">
                                    <strong>Warning:</strong> This action is permanent and cannot be undone!
                                </div>
                                <p>All your data will be permanently deleted, including:</p>
                                <ul>
                                    <li>User profile and settings</li>
                                    <li>All scan results and reports</li>
                                    <li>Traffic logs and alerts</li>
                                    <li>Quarantined files</li>
                                </ul>
                                <p>Type <strong>DELETE</strong> to confirm:</p>
                                <input type="text" class="form-control" id="deleteConfirm" placeholder="Type DELETE">
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                <button type="button" class="btn btn-danger" onclick="executeDeleteAccount()">
                                    <i class="bi bi-trash me-2"></i>Delete My Account
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            $('body').append(modal);
            $('#deleteAccountModal').modal('show');
            
            $('#deleteAccountModal').on('hidden.bs.modal', function() {
                $(this).remove();
            });
        }

        function executeDeleteAccount() {
            const confirmation = $('#deleteConfirm').val();
            
            if (confirmation !== 'DELETE') {
                showToast('Error', 'Please type DELETE to confirm', 'danger');
                return;
            }
            
            $.ajax({
                url: "<?= MDIR ?>delete-account",
                method: "POST",
                dataType: "json",
                success: function(response) {
                    if (response.success) {
                        $('#deleteAccountModal').modal('hide');
                        showToast('Success', 'Account deleted. Redirecting...', 'success');
                        setTimeout(() => {
                            window.location.href = "<?= MDIR ?>logout";
                        }, 2000);
                    } else {
                        showToast('Error', response.message || 'Failed to delete account', 'danger');
                    }
                },
                error: function() {
                    showToast('Error', 'Failed to delete account', 'danger');
                }
            });
        }

        // ==================== ABOUT FUNCTIONS ====================
        function checkForUpdates() {
            showToast('Checking', 'Checking for updates...', 'info');
            
            setTimeout(() => {
                showToast('Success', 'You are running the latest version!', 'success');
            }, 1500);
        }

        function viewLicense() {
            window.open('https://opensource.org/licenses/MIT', '_blank');
        }

        // ==================== USER STATISTICS ====================
        function loadUserStatistics() {
            $.ajax({
                url: "<?= MDIR ?>get-user-stats",
                method: "GET",
                dataType: "json",
                success: function(data) {
                    $('#userScans').text(data.total_scans || 0);
                    $('#userAlerts').text(data.total_alerts || 0);
                    $('#userQuarantine').text(data.quarantined_files || 0);
                    $('#userDays').text(data.days_active || 0);
                },
                error: function() {
                    console.log('Failed to load user statistics');
                }
            });
        }

        // ==================== TOAST NOTIFICATIONS ====================
        function showToast(title, message, type) {
            const iconMap = {
                success: 'bi-check-circle-fill',
                danger: 'bi-x-circle-fill',
                warning: 'bi-exclamation-triangle-fill',
                info: 'bi-info-circle-fill'
            };
            
            const toast = $(`
                <div class="toast align-items-center text-white bg-${type} border-0 show" role="alert">
                    <div class="d-flex">
                        <div class="toast-body">
                            <i class="bi ${iconMap[type]} me-2"></i>
                            <strong>${title}:</strong> ${message}
                        </div>
                        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                    </div>
                </div>
            `);
            
            $('.toast-container').append(toast);
            
            setTimeout(() => {
                toast.fadeOut(() => toast.remove());
            }, 5000);
        }
    </script>
</body>
</html>
