@echo off
:: CyberHawk Admin Launcher
:: This script starts the traffic sniffer with admin privileges

:: Check if running as admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Set paths
set VENV_PYTHON=E:\xampp\htdocs\cyberhawk\fyp\Scripts\python.exe
set SNIFFER_SCRIPT=E:\xampp\htdocs\cyberhawk\python\traffic_capture\traffic_sniffer.py
set PREDICT_SCRIPT=E:\xampp\htdocs\cyberhawk\python\detection\realtime_predict.py
set LOG_FILE=E:\xampp\htdocs\cyberhawk\assets\data\sniffer_console.log

echo ========================================
echo CyberHawk Traffic Sniffer - Admin Mode
echo ========================================
echo.
echo Starting traffic sniffer...
echo Output logged to: %LOG_FILE%
echo.

:: Start sniffer in new window
start "CyberHawk Sniffer" /MIN cmd /c "%VENV_PYTHON%" "%SNIFFER_SCRIPT%" 2>&1 ^| tee "%LOG_FILE%"

:: Wait a moment then start prediction model
timeout /t 2 /nobreak >nul
echo Starting prediction model...
start "CyberHawk Predictor" /MIN "%VENV_PYTHON%" "%PREDICT_SCRIPT%"

echo.
echo ========================================
echo Both processes started!
echo.
echo To stop: Close the minimized command windows
echo or use Task Manager to end python.exe
echo ========================================
pause
