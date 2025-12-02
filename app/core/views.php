<?php


function get_500_error_view()
{
	header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error', true, 500);
	require 'app/views/error/500.php';
}

function get_login_view()
{
	require 'app/views/pages/login.php';
}


function get_dashboard()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }

    require 'app/views/pages/dashboard.php';
}

function get_register_view()
{
	require 'app/views/pages/register.php';
}

function startLogsHandler() {
    $projectDir = DIR;  
    $pythonPath = $projectDir . '/fyp/Scripts/python.exe';
    $snifferScript = $projectDir . '/python/traffic_capture/traffic_sniffer.py';
    $predictScript = $projectDir . '/python/training/predict_realtime.py';

    $input = json_decode(file_get_contents("php://input"), true);
    $models = isset($input['models']) && is_array($input['models']) ? implode(",", $input['models']) : "rf,lr,cyberhawk";

    try {
        $cmdSniffer = "powershell -Command \"Start-Process -FilePath '$pythonPath' -ArgumentList '$snifferScript' -PassThru | Select-Object -ExpandProperty Id\"";
        $snifferPid = trim(shell_exec($cmdSniffer));

        $cmdPredict = "powershell -Command \"Start-Process -FilePath '$pythonPath' -ArgumentList '$predictScript --models $models' -PassThru | Select-Object -ExpandProperty Id\"";
        $predictPid = trim(shell_exec($cmdPredict));

        if (is_numeric($snifferPid) && is_numeric($predictPid)) {
            file_put_contents($projectDir . '/assets/data/pid.json', json_encode([
                'sniffer_pid' => $snifferPid,
                'predict_pid' => $predictPid,
                'models' => $models
            ]));

            echo json_encode([
                'success' => true,
                'pid' => "$snifferPid, $predictPid",
                'models' => $models,
                'message' => 'Sniffer + Model(s) started successfully',
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Failed to retrieve one or both PIDs'
            ]);
        }

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => $e->getMessage()
        ]);
    }
}


function stopLogsHandler() {
    $projectDir = DIR;
    $pidFile = $projectDir . '/assets/data/pid.json';

    if (!file_exists($pidFile)) {
        echo json_encode([
            'success' => false,
            'message' => 'PID file not found'
        ]);
        return;
    }

    $pids = json_decode(file_get_contents($pidFile), true);
    $snifferPid = $pids['sniffer_pid'] ?? null;
    $predictPid = $pids['predict_pid'] ?? null;

    if (!$snifferPid || !$predictPid) {
        echo json_encode([
            'success' => false,
            'message' => 'One or both PIDs missing'
        ]);
        return;
    }

    try {
        exec("powershell -Command \"Stop-Process -Id $snifferPid -Force\"");
        exec("powershell -Command \"Stop-Process -Id $predictPid -Force\"");

        unlink($pidFile);

        echo json_encode([
            'success' => true,
            'message' => 'Both processes stopped'
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => $e->getMessage()
        ]);
    }
}

function clear_traffic_logs() {
    $logFile = DIR. '/assets/data/traffic_log.json';
    file_put_contents($logFile, json_encode([]));
    
    header('Content-Type: application/json');
    echo json_encode(['success' => true]);
}

/**
 * CyberHawk Ransomware Detection Module - PHP Functions
 * FIXED VERSION - Removed custom scan, fixed progress tracking
 */

// ==================== PAGE LOADER ====================

function get_ransomware_page()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }
    require 'app/views/pages/ransomware.php';
}




function get_malware_page()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }
    require 'app/views/pages/malware.php';
}

function get_reporting_page()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }
    require 'app/views/pages/reporting.php';
}



function get_profile_page()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }
    require 'app/views/pages/profile.php';
}

function get_user_profile($user_id)
{
    $sql = "SELECT id, name, email, role, profile_picture, phone, bio, created_at, last_updated 
            FROM users WHERE id = ?";
    $result = mysqli_prepared_query($sql, 'i', [$user_id]);
    
    if ($result && count($result) > 0) {
        return $result[0];
    }
    return null;
}



function get_settings_page()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }
    require 'app/views/pages/settings.php';
}


function get_verify_page()
{
    require 'app/views/pages/verify.php';
}

function get_threat_intelligence_page()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }
    require 'app/views/pages/threat_intelligence.php';
}

/**
 * Network Analytics Page Loader
 */
function get_network_analytics_page()
{
    if (!isset($_SESSION['user_id'])) {
        header("Location: " . MDIR . "login");
        exit;
    }
    require 'app/views/pages/network_analytics.php';
}
?>