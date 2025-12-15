#!/bin/bash
# CyberHawk Python Services Startup Script

echo "=========================================="
echo "🦅 CyberHawk Python Services Starting..."
echo "=========================================="

# Wait for data directory to be available
echo "[*] Waiting for data directory..."
while [ ! -d "$PYTHON_DATA_DIR" ]; do
    sleep 2
    echo "[*] Waiting for $PYTHON_DATA_DIR..."
done

echo "[✓] Data directory available: $PYTHON_DATA_DIR"

# Create necessary subdirectories
mkdir -p "$PYTHON_DATA_DIR/malware_uploads"
mkdir -p "$PYTHON_DATA_DIR/quarantine"
mkdir -p "$PYTHON_DATA_DIR/reports"

# Initialize empty JSON files if they don't exist
if [ ! -f "$PYTHON_DATA_DIR/traffic_log.json" ]; then
    echo "[]" > "$PYTHON_DATA_DIR/traffic_log.json"
fi

if [ ! -f "$PYTHON_DATA_DIR/malware_reports.json" ]; then
    echo "[]" > "$PYTHON_DATA_DIR/malware_reports.json"
fi

if [ ! -f "$PYTHON_DATA_DIR/malware_stats.json" ]; then
    echo '{"total_scans":0,"malware_detected":0,"clean_files":0}' > "$PYTHON_DATA_DIR/malware_stats.json"
fi

echo "[✓] Data files initialized"

# Start traffic sniffer in background
echo "[*] Starting Traffic Sniffer..."
python3 /app/python/traffic_capture/traffic_sniffer.py &
SNIFFER_PID=$!
echo "[✓] Traffic Sniffer started (PID: $SNIFFER_PID)"

echo ""
echo "=========================================="
echo "🦅 CyberHawk Python Services Running"
echo "=========================================="
echo "Services:"
echo "  - Traffic Sniffer (PID: $SNIFFER_PID)"
echo "  - Malware Analyzer (on-demand)"
echo "=========================================="

# Keep container running and wait for child processes
wait $SNIFFER_PID
