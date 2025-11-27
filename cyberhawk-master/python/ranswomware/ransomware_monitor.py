#!/usr/bin/env python3
"""
CyberHawk Ransomware Detection System
Real-time behavioral analysis and file monitoring
FIXED FOR WINDOWS
"""

import os
import sys
import json
import time
import hashlib
import math
import threading
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configuration
CONFIG = {
    'MONITORED_PATHS': [
        os.path.join(os.path.expanduser('~'), 'Documents'),
        os.path.join(os.path.expanduser('~'), 'Downloads'),
        os.path.join(os.path.expanduser('~'), 'Desktop'),
    ],
    'DATA_DIR': 'assets/data',
    'SUSPICIOUS_EXTENSIONS': [
        '.encrypted', '.locked', '.crypto', '.crypt', '.crypted',
        '.enc', '.locky', '.zepto', '.cerber', '.wannacry',
    ],
    'SUSPICIOUS_FILENAMES': [
        'HOW_TO_DECRYPT', 'README', 'DECRYPT_INSTRUCTIONS',
        'HELP_DECRYPT', 'RECOVERY', 'RESTORE_FILES'
    ],
    'MAX_FILES_PER_MINUTE': 50,
    'ENTROPY_THRESHOLD': 7.5,
}

class RansomwareDetector:
    def __init__(self):
        self.file_operations = defaultdict(list)
        self.threats_detected = []
        self.files_scanned = 0
        self.quarantined_files = []
        self.stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'quarantined': 0,
            'scan_rate': 0,
            'scan_progress': 0,
            'current_file': 'Idle'
        }
        
        # File write lock
        self.write_lock = threading.Lock()
        
        # Ensure data directory exists
        os.makedirs(CONFIG['DATA_DIR'], exist_ok=True)
        
        # Initialize data files
        self.init_data_files()
        
    def init_data_files(self):
        """Initialize JSON data files with empty arrays"""
        files = [
            'ransomware_activity.json',
            'ransomware_stats.json',
            'ransomware_threats.json',
            'quarantine.json'
        ]
        
        for file in files:
            filepath = os.path.join(CONFIG['DATA_DIR'], file)
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    json.dump([], f)
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy - FIXED"""
        if not data or len(data) == 0:
            return 0
        
        try:
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            entropy = 0
            data_len = len(data)
            for count in byte_counts:
                if count > 0:
                    p_x = count / data_len
                    entropy += -p_x * math.log2(p_x)
            
            return entropy
        except:
            return 0
    
    def is_suspicious_extension(self, filename):
        """Check if file has suspicious extension"""
        try:
            ext = Path(filename).suffix.lower()
            return ext in CONFIG['SUSPICIOUS_EXTENSIONS']
        except:
            return False
    
    def is_ransom_note(self, filename):
        """Check if file is likely a ransom note"""
        try:
            name = Path(filename).stem.upper()
            return any(keyword in name for keyword in CONFIG['SUSPICIOUS_FILENAMES'])
        except:
            return False
    
    def check_file_encryption(self, filepath):
        """Check if file appears to be encrypted"""
        try:
            if not os.access(filepath, os.R_OK):
                return False
            
            file_size = os.path.getsize(filepath)
            if file_size > 5 * 1024 * 1024:  # Skip files > 5MB
                return False
            
            if file_size < 10:  # Skip tiny files
                return False
            
            with open(filepath, 'rb') as f:
                data = f.read(min(1024, file_size))
                if data and len(data) > 10:
                    entropy = self.calculate_entropy(data)
                    return entropy > CONFIG['ENTROPY_THRESHOLD']
        except:
            return False
        
        return False
    
    def analyze_file(self, filepath):
        """Comprehensive file analysis"""
        threat_indicators = []
        threat_level = 'safe'
        
        try:
            filename = os.path.basename(filepath)
            
            # Check 1: Suspicious extension
            if self.is_suspicious_extension(filename):
                threat_indicators.append('suspicious_extension')
                threat_level = 'critical'
            
            # Check 2: Ransom note detection
            if self.is_ransom_note(filename):
                threat_indicators.append('ransom_note')
                threat_level = 'critical'
            
            # Check 3: High entropy (only if safe to check)
            if os.path.exists(filepath) and os.path.isfile(filepath):
                if self.check_file_encryption(filepath):
                    threat_indicators.append('high_entropy')
                    if threat_level != 'critical':
                        threat_level = 'warning'
            
            return {
                'file_name': filename,
                'file_path': filepath,
                'threat_level': threat_level,
                'indicators': threat_indicators,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except:
            return {
                'file_name': os.path.basename(filepath),
                'file_path': filepath,
                'threat_level': 'safe',
                'indicators': [],
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
    
    def log_activity(self, activity_data):
        """Log file activity - WINDOWS SAFE VERSION"""
        activity_file = os.path.join(CONFIG['DATA_DIR'], 'ransomware_activity.json')
        
        with self.write_lock:
            try:
                # Read existing data
                data = []
                if os.path.exists(activity_file):
                    try:
                        with open(activity_file, 'r') as f:
                            data = json.load(f)
                            if not isinstance(data, list):
                                data = []
                    except:
                        data = []
                
                # Add new activity
                data.insert(0, activity_data)
                data = data[:100]  # Keep last 100
                
                # Write directly (no temp file on Windows)
                with open(activity_file, 'w') as f:
                    json.dump(data, f, indent=2)
                    
            except Exception as e:
                # Silently fail - don't spam console
                pass
    
    def log_threat(self, threat_data):
        """Log detected threat - WINDOWS SAFE"""
        threats_file = os.path.join(CONFIG['DATA_DIR'], 'ransomware_threats.json')
        
        with self.write_lock:
            try:
                threats = []
                if os.path.exists(threats_file):
                    try:
                        with open(threats_file, 'r') as f:
                            threats = json.load(f)
                            if not isinstance(threats, list):
                                threats = []
                    except:
                        threats = []
                
                threats.insert(0, threat_data)
                threats = threats[:50]
                
                with open(threats_file, 'w') as f:
                    json.dump(threats, f, indent=2)
                    
            except:
                pass
    
    def quarantine_file(self, filepath):
        """Move suspicious file to quarantine"""
        try:
            quarantine_dir = os.path.join(CONFIG['DATA_DIR'], 'quarantine_files')
            os.makedirs(quarantine_dir, exist_ok=True)
            
            filename = os.path.basename(filepath)
            timestamp = int(time.time())
            quarantine_path = os.path.join(quarantine_dir, f"{timestamp}_{filename}")
            
            if os.path.exists(filepath) and os.access(filepath, os.W_OK):
                os.rename(filepath, quarantine_path)
                
                quarantine_info = {
                    'id': hashlib.md5(filepath.encode()).hexdigest(),
                    'name': filename,
                    'original_path': filepath,
                    'quarantine_path': quarantine_path,
                    'quarantine_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                quarantine_file = os.path.join(CONFIG['DATA_DIR'], 'quarantine.json')
                
                with self.write_lock:
                    quarantine_list = []
                    if os.path.exists(quarantine_file):
                        try:
                            with open(quarantine_file, 'r') as f:
                                quarantine_list = json.load(f)
                        except:
                            pass
                    
                    quarantine_list.append(quarantine_info)
                    
                    with open(quarantine_file, 'w') as f:
                        json.dump(quarantine_list, f, indent=2)
                
                return True
        except:
            pass
        
        return False
    
    def update_stats(self):
        """Update statistics file"""
        stats_file = os.path.join(CONFIG['DATA_DIR'], 'ransomware_stats.json')
        
        with self.write_lock:
            try:
                with open(stats_file, 'w') as f:
                    json.dump(self.stats, f, indent=2)
            except:
                pass

class RansomwareFileHandler(FileSystemEventHandler):
    def __init__(self, detector):
        self.detector = detector
        self.last_event_time = defaultdict(float)
    
    def on_created(self, event):
        if not event.is_directory:
            self.process_file(event.src_path, 'created')
    
    def on_modified(self, event):
        if not event.is_directory:
            current_time = time.time()
            if current_time - self.last_event_time[event.src_path] > 1:
                self.process_file(event.src_path, 'modified')
                self.last_event_time[event.src_path] = current_time
    
    def process_file(self, filepath, operation):
        """Process file event"""
        try:
            self.detector.files_scanned += 1
            self.detector.stats['files_scanned'] = self.detector.files_scanned
            self.detector.stats['current_file'] = os.path.basename(filepath)
            
            analysis = self.detector.analyze_file(filepath)
            
            behavior_type = 'normal'
            if 'suspicious_extension' in analysis['indicators']:
                behavior_type = 'extension'
            elif 'high_entropy' in analysis['indicators']:
                behavior_type = 'encryption'
            elif 'ransom_note' in analysis['indicators']:
                behavior_type = 'ransom_note'
            
            analysis['behavior_type'] = behavior_type
            
            self.detector.log_activity(analysis)
            
            if analysis['threat_level'] in ['critical', 'warning']:
                self.detector.stats['threats_detected'] += 1
                
                threat = {
                    'timestamp': analysis['timestamp'],
                    'file_path': filepath,
                    'type': behavior_type.upper(),
                    'severity': analysis['threat_level'].upper(),
                    'action': 'quarantined' if analysis['threat_level'] == 'critical' else 'flagged',
                    'status': 'active',
                    'description': f"Suspicious {behavior_type} detected"
                }
                
                self.detector.log_threat(threat)
                
                if analysis['threat_level'] == 'critical':
                    if self.detector.quarantine_file(filepath):
                        self.detector.stats['quarantined'] += 1
                        print(f"[THREAT] {filepath} - QUARANTINED")
            
            self.detector.update_stats()
            
            process_name = 'system'
            self.detector.file_operations[process_name].append(time.time())
            
        except Exception as e:
            # Silently handle errors
            pass

def monitor_filesystem(detector):
    """Start filesystem monitoring"""
    event_handler = RansomwareFileHandler(detector)
    observer = Observer()
    
    for path in CONFIG['MONITORED_PATHS']:
        if os.path.exists(path):
            print(f"[MONITOR] Watching: {path}")
            observer.schedule(event_handler, path, recursive=True)
    
    observer.start()
    
    try:
        while True:
            time.sleep(10)
            
            # Update scan rate
            detector.stats['scan_rate'] = detector.files_scanned / max(1, time.time() - start_time) * 60
            detector.update_stats()
            
    except KeyboardInterrupt:
        observer.stop()
        print("\n[STOP] Monitoring stopped")
    
    observer.join()

if __name__ == '__main__':
    print("="*60)
    print("CyberHawk Ransomware Detection System")
    print("="*60)
    print("[INIT] Starting ransomware monitor...")
    
    detector = RansomwareDetector()
    start_time = time.time()
    
    print("[READY] Monitoring for ransomware activity")
    print("Press Ctrl+C to stop")
    print("="*60)
    
    monitor_filesystem(detector)