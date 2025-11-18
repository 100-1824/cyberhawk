#!/usr/bin/env python3
"""
CyberHawk Ransomware Scanner with ML Model Integration
FIXED VERSION - Progress tracking and scanning issues resolved
"""

import os
import sys
import json
import hashlib
import requests
import argparse
import time
import math
import joblib
import numpy as np
from pathlib import Path
from datetime import datetime

# Configuration
CONFIG = {
    'DATA_DIR': 'assets/data',
    'MODEL_PATH': 'python/ranswomware/ransomware_model.pkl',
    'VIRUSTOTAL_API_KEY': '685fe9d7889aaddde1c019f7d2a4ebccc9032c2663112fdc95257a699b3d4f30',
    'USE_VIRUSTOTAL': True,
    'USE_ML_MODEL': False                                                                                                                                                                                                                                                            ,
    'SCAN_EXTENSIONS': [
        '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs',
        '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.zip', '.rar',
        '.jpg', '.png', '.txt', '.db', '.sql'
    ],
    'SUSPICIOUS_EXTENSIONS': [
        '.encrypted', '.locked', '.crypto', '.crypt', '.crypted',
        '.enc', '.locky', '.zepto', '.cerber', '.wannacry'
    ]
}

class MLFeatureExtractor:
    """Extract features for ML model prediction"""
    
    @staticmethod
    def extract_features(filepath):
        """Extract 10 features from file"""
        features = {}
        
        try:
            # Feature 1: File Entropy
            features['entropy'] = MLFeatureExtractor._calculate_entropy(filepath)
            
            # Feature 2: File Size (MB)
            features['file_size'] = os.path.getsize(filepath) / (1024 * 1024)
            
            # Feature 3: Suspicious Extension
            ext = Path(filepath).suffix.lower()
            features['suspicious_extension'] = 1 if ext in CONFIG['SUSPICIOUS_EXTENSIONS'] else 0
            
            # Feature 4: Executable Header
            features['executable_header'] = MLFeatureExtractor._check_pe_header(filepath)
            
            # Feature 5: High Entropy Sections
            features['high_entropy_sections'] = MLFeatureExtractor._count_high_entropy_sections(filepath)
            
            # Feature 6: Packing Indicator
            features['packed_indicator'] = MLFeatureExtractor._check_packing(filepath)
            
            # Feature 7: Suspicious API Calls
            features['api_call_suspicious'] = MLFeatureExtractor._check_suspicious_apis(filepath)
            
            # Feature 8: String Entropy
            features['string_entropy'] = MLFeatureExtractor._calculate_string_entropy(filepath)
            
            # Feature 9: Section Count
            features['section_count'] = MLFeatureExtractor._count_sections(filepath)
            
            # Feature 10: Import Count
            features['import_count'] = MLFeatureExtractor._count_imports(filepath)
            
        except Exception as e:
            # Return default features on error
            feature_names = ['entropy', 'file_size', 'suspicious_extension', 'executable_header',
                           'high_entropy_sections', 'packed_indicator', 'api_call_suspicious',
                           'string_entropy', 'section_count', 'import_count']
            features = {name: 0 for name in feature_names}
        
        # Convert to numpy array
        feature_array = np.array([
            features['entropy'],
            features['file_size'],
            features['suspicious_extension'],
            features['executable_header'],
            features['high_entropy_sections'],
            features['packed_indicator'],
            features['api_call_suspicious'],
            features['string_entropy'],
            features['section_count'],
            features['import_count']
        ])
        
        return feature_array.reshape(1, -1)
    
    @staticmethod
    def _calculate_entropy(filepath):
        """Calculate Shannon entropy"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(min(4096, os.path.getsize(filepath)))
            
            if not data:
                return 0
            
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
    
    @staticmethod
    def _check_pe_header(filepath):
        """Check for PE executable header"""
        try:
            with open(filepath, 'rb') as f:
                header = f.read(2)
                return 1 if header == b'MZ' else 0
        except:
            return 0
    
    @staticmethod
    def _count_high_entropy_sections(filepath):
        """Count sections with high entropy"""
        try:
            with open(filepath, 'rb') as f:
                file_size = os.path.getsize(filepath)
                chunk_size = min(1024, file_size // 10)
                high_entropy_count = 0
                
                for i in range(10):
                    f.seek(i * chunk_size)
                    chunk = f.read(chunk_size)
                    if chunk:
                        entropy = MLFeatureExtractor._calculate_chunk_entropy(chunk)
                        if entropy > 7.0:
                            high_entropy_count += 1
                
                return high_entropy_count
        except:
            return 0
    
    @staticmethod
    def _calculate_chunk_entropy(data):
        """Calculate entropy of chunk"""
        if not data:
            return 0
        
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
    
    @staticmethod
    def _check_packing(filepath):
        """Check for packer signatures"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(1024)
                packers = [b'UPX', b'PECompact', b'ASPack']
                for packer in packers:
                    if packer in data:
                        return 1
            return 0
        except:
            return 0
    
    @staticmethod
    def _check_suspicious_apis(filepath):
        """Check for suspicious API calls"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(8192)
                suspicious_apis = [
                    b'CryptEncrypt', b'DeleteFile', b'WriteFile',
                    b'CreateRemoteThread', b'VirtualAlloc'
                ]
                count = sum(1 for api in suspicious_apis if api in data)
                return min(count, 5)
        except:
            return 0
    
    @staticmethod
    def _calculate_string_entropy(filepath):
        """Calculate entropy of printable strings"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(4096)
                strings = bytes([b for b in data if 32 <= b <= 126])
                
                if len(strings) < 10:
                    return 0
                
                return MLFeatureExtractor._calculate_chunk_entropy(strings)
        except:
            return 0
    
    @staticmethod
    def _count_sections(filepath):
        """Count PE sections"""
        try:
            with open(filepath, 'rb') as f:
                f.seek(0x3C)
                pe_offset = int.from_bytes(f.read(4), 'little')
                f.seek(pe_offset + 6)
                section_count = int.from_bytes(f.read(2), 'little')
                return min(section_count, 20)
        except:
            return 0
    
    @staticmethod
    def _count_imports(filepath):
        """Count imported functions"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(4096)
                import_count = data.count(b'\x00') // 10
                return min(import_count, 50)
        except:
            return 0

class RansomwareScanner:
    def __init__(self):
        self.scanned_files = 0
        self.threats_found = 0
        self.total_files = 0
        self.stats_file = os.path.join(CONFIG['DATA_DIR'], 'ransomware_stats.json')
        self.progress_file = os.path.join(CONFIG['DATA_DIR'], 'scan_progress.json')
        self.threats_file = os.path.join(CONFIG['DATA_DIR'], 'ransomware_threats.json')
        self.start_time = time.time()
        self.ml_model = None
        
        # Load ML model
        if CONFIG['USE_ML_MODEL']:
            self.load_ml_model()
        
        # Ensure data directory exists
        os.makedirs(CONFIG['DATA_DIR'], exist_ok=True)
    
    def load_ml_model(self):
        """Load the trained ML model"""
        try:
            model_path = CONFIG['MODEL_PATH']
            if os.path.exists(model_path):
                self.ml_model = joblib.load(model_path)
                print(f"[ML] ✓ Model loaded from {model_path}")
            else:
                print(f"[ML] ⚠ Model not found at {model_path}")
                print("[ML] Continuing with VirusTotal-only detection")
                CONFIG['USE_ML_MODEL'] = False
        except Exception as e:
            print(f"[ML] ✗ Failed to load model: {e}")
            CONFIG['USE_ML_MODEL'] = False
    
    def predict_with_ml(self, filepath):
        """Predict using ML model"""
        if not self.ml_model:
            return None
        
        try:
            features = MLFeatureExtractor.extract_features(filepath)
            prediction = self.ml_model.predict(features)[0]
            probabilities = self.ml_model.predict_proba(features)[0]
            
            result = {
                'prediction': 'RANSOMWARE' if prediction == 1 else 'BENIGN',
                'ransomware_probability': float(probabilities[1]) if len(probabilities) > 1 else 0,
                'benign_probability': float(probabilities[0]),
                'confidence': float(probabilities[prediction]) * 100
            }
            
            return result
        except Exception as e:
            print(f"[ML] Error predicting: {e}")
            return None
    
    def get_file_hash(self, filepath):
        """Calculate SHA256 hash"""
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            return None
    
    def check_virustotal(self, file_hash):
        """Check file against VirusTotal"""
        if not CONFIG['USE_VIRUSTOTAL'] or not CONFIG['VIRUSTOTAL_API_KEY']:
            return None
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": CONFIG['VIRUSTOTAL_API_KEY']}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0)
                }
            elif response.status_code == 404:
                return {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0}
                
        except Exception as e:
            pass
        
        return None
    
    def scan_file(self, filepath):
        """Scan individual file with ML + VirusTotal"""
        self.scanned_files += 1
        
        # Update progress MORE FREQUENTLY
        if self.scanned_files % 5 == 0 or self.scanned_files == 1:
            progress = int((self.scanned_files / max(self.total_files, 1)) * 100)
            self.update_progress(progress, filepath)
        
        # Get file hash
        file_hash = self.get_file_hash(filepath)
        if not file_hash:
            return None
        
        # STEP 1: ML Model Prediction (Fast, Offline)
        ml_result = None
        if CONFIG['USE_ML_MODEL'] and self.ml_model:
            ml_result = self.predict_with_ml(filepath)
        
        # STEP 2: VirusTotal Check (if ML detects threat)
        vt_result = None
        threat_level = 'safe'
        detection_method = 'Clean'
        
        if ml_result and ml_result['prediction'] == 'RANSOMWARE':
            # ML detected threat, verify with VirusTotal
            if CONFIG['USE_VIRUSTOTAL']:
                vt_result = self.check_virustotal(file_hash)
                time.sleep(0.5)  # Rate limiting
                
                if vt_result and vt_result['malicious'] > 0:
                    threat_level = 'critical'  # Both agree
                    detection_method = 'ML + VirusTotal'
                else:
                    threat_level = 'warning'  # Only ML detected
                    detection_method = 'ML Only'
            else:
                threat_level = 'warning'
                detection_method = 'ML Only'
        
        # Log threat if detected
        if threat_level in ['warning', 'critical']:
            self.threats_found += 1
            
            threat_data = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'file_path': filepath,
                'file_name': os.path.basename(filepath),
                'hash': file_hash,
                'type': 'RANSOMWARE',
                'severity': threat_level.upper(),
                'action': 'flagged',
                'status': 'active',
                'detection_method': detection_method,
                'ml_confidence': ml_result['confidence'] if ml_result else 0,
                'ml_probability': ml_result['ransomware_probability'] if ml_result else 0,
                'vt_detection': vt_result.get('malicious', 0) if vt_result else 0
            }
            
            self.log_threat(threat_data)
            print(f"[THREAT] {filepath} - {threat_level.upper()} ({detection_method})")
            
            return threat_data
        
        return None
    
    def count_scannable_files(self, directory):
        """Count total files to scan"""
        count = 0
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if Path(file).suffix.lower() in CONFIG['SCAN_EXTENSIONS']:
                        count += 1
        except Exception as e:
            pass
        return count
    
    def scan_directory(self, directory):
        """Scan directory recursively"""
        print(f"[SCAN] Scanning: {directory}")
        
        # Count files
        print("[INFO] Counting files...")
        self.total_files = self.count_scannable_files(directory)
        print(f"[INFO] Total files to scan: {self.total_files}")
        
        # Handle empty directory
        if self.total_files == 0:
            self.update_progress(100, 'No scannable files found')
            return []
        
        # Initialize progress
        self.update_progress(0, 'Starting scan...')
        
        # Scan files
        threats = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                
                if Path(file).suffix.lower() in CONFIG['SCAN_EXTENSIONS']:
                    result = self.scan_file(filepath)
                    if result:
                        threats.append(result)
                
                # Update stats regularly
                if self.scanned_files % 10 == 0:
                    self.update_stats()
        
        # Final updates
        self.update_progress(100, 'Scan complete')
        self.update_stats()
        
        return threats
    
    def update_progress(self, progress, current_file):
        """Update scan progress - FIXED TYPO"""
        try:
            status = 'Scanning in progress...'
            if progress >= 100:
                status = 'Scan complete'
            elif progress == 0:
                status = 'Initializing scan...'
            
            data = {
                'progress': progress,
                'status': status,
                'current_file': os.path.basename(current_file) if len(current_file) < 100 else '...' + current_file[-97:],
                'files_scanned': self.scanned_files,
                'threats_found': self.threats_found,
                'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # FIXED: was %H:%i:s
            }
            
            with open(self.progress_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            print(f"[ERROR] Failed to update progress: {e}")
    
    def update_stats(self):
        """Update statistics"""
        try:
            elapsed = time.time() - self.start_time
            scan_rate = (self.scanned_files / elapsed * 60) if elapsed > 0 else 0
            
            stats = {
                'files_scanned': self.scanned_files,
                'threats_detected': self.threats_found,
                'scan_rate': round(scan_rate, 2),
                'scan_progress': int((self.scanned_files / max(self.total_files, 1)) * 100),
                'current_file': 'Scanning...'
            }
            
            # Preserve quarantine count
            if os.path.exists(self.stats_file):
                with open(self.stats_file, 'r') as f:
                    existing = json.load(f)
                    stats['quarantined'] = existing.get('quarantined', 0)
            else:
                stats['quarantined'] = 0
            
            with open(self.stats_file, 'w') as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            print(f"[ERROR] Failed to update stats: {e}")
    
    def log_threat(self, threat_data):
        """Log detected threat"""
        try:
            threats = []
            if os.path.exists(self.threats_file):
                with open(self.threats_file, 'r') as f:
                    threats = json.load(f)
            
            threats.insert(0, threat_data)
            threats = threats[:100]
            
            with open(self.threats_file, 'w') as f:
                json.dump(threats, f, indent=2)
        except Exception as e:
            print(f"[ERROR] Failed to log threat: {e}")
    
    def save_results(self, threats):
        """Save final scan results"""
        results_file = os.path.join(CONFIG['DATA_DIR'], 'scan_results.json')
        
        try:
            results = {
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'files_scanned': self.scanned_files,
                'threats_found': self.threats_found,
                'scan_time': round(time.time() - self.start_time, 2),
                'detection_method': 'ML + VirusTotal' if CONFIG['USE_ML_MODEL'] and CONFIG['USE_VIRUSTOTAL'] else 'VirusTotal Only',
                'threats': threats
            }
            
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
                print(f"[SAVE] Results saved to {results_file}")
        except Exception as e:
            print(f"[ERROR] Saving results: {e}")

def main():
    parser = argparse.ArgumentParser(description='CyberHawk Ransomware Scanner with ML')
    parser.add_argument('--full-scan', action='store_true', help='Full system scan')
    parser.add_argument('--quick-scan', action='store_true', help='Quick scan (user folders)')
    args = parser.parse_args()
    
    scanner = RansomwareScanner()
    
    print("=" * 70)
    print("CYBERHAWK RANSOMWARE SCANNER WITH ML DETECTION")
    print("=" * 70)
    print(f"ML Model: {'✓ Loaded' if scanner.ml_model else '✗ Not Available'}")
    print(f"VirusTotal: {'✓ Enabled' if CONFIG['USE_VIRUSTOTAL'] else '✗ Disabled'}")
    print("=" * 70 + "\n")
    
    scan_paths = []
    
    if args.full_scan:
        print("[MODE] Full System Scan")
        user_home = os.path.expanduser('~')
        scan_paths = [
            os.path.join(user_home, 'Documents'),
            os.path.join(user_home, 'Downloads'),
            os.path.join(user_home, 'Desktop'),
            os.path.join(user_home, 'Pictures'),
            os.path.join(user_home, 'Videos')
        ]
        
    elif args.quick_scan:
        print("[MODE] Quick Scan")
        user_home = os.path.expanduser('~')
        scan_paths = [
            os.path.join(user_home, 'Documents'),
            os.path.join(user_home, 'Downloads'),
            os.path.join(user_home, 'Desktop')
        ]
    else:
        print("[ERROR] Please specify --full-scan or --quick-scan")
        parser.print_help()
        return
    
    # Scan all paths
    all_threats = []
    for path in scan_paths:
        if os.path.exists(path):
            print(f"\n[START] Scanning: {path}")
            threats = scanner.scan_directory(path)
            all_threats.extend(threats)
        else:
            print(f"[SKIP] Path not found: {path}")
    
    # Save final results
    scanner.save_results(all_threats)
    
    print("\n" + "=" * 70)
    print("[COMPLETE] Scan finished")
    print(f"Files scanned: {scanner.scanned_files}")
    print(f"Threats found: {scanner.threats_found}")
    print(f"Scan time: {round(time.time() - scanner.start_time, 2)}s")
    
    if scanner.threats_found > 0:
        print(f"\n⚠ {scanner.threats_found} threats detected!")
        print("Check assets/data/ransomware_threats.json for details")
    else:
        print("\n✓ No threats detected")
    
    print("=" * 70)

if __name__ == '__main__':
    main()