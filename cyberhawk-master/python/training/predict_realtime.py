"""
CyberHawk Intrusion Detection System - Real-Time Prediction Script
Final Year Project
Author: Muhammad Ahmed

This script monitors traffic_log.json in real-time and performs intrusion detection
using the trained TensorFlow model. Detected attacks are logged to alerts.json.
"""

import os
import sys
import time
import json
import numpy as np
import pandas as pd
from datetime import datetime
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

# Import required libraries
try:
    import tensorflow as tf
    from tensorflow import keras
    import joblib
except ImportError as e:
    print(f"❌ ERROR: Missing required library - {e}")
    print("Please install: pip install tensorflow scikit-learn")
    sys.exit(1)

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Configuration parameters"""

    
    # Paths
    BASE_DIR = Path(__file__).parent.parent.parent  # Go up to cyberhawk root
    MODEL_DIR = BASE_DIR / "assets" / "model"  # ✅ Correct path
    DATA_DIR = BASE_DIR / "assets" / "data"  # ✅ Correct path
    
    # Files
    TRAFFIC_LOG = DATA_DIR / "traffic_log.json"
    ALERTS_LOG = DATA_DIR / "alerts.json"
    
    # Model files (will be detected automatically)
    MODEL_FILE = None
    SCALER_FILE = MODEL_DIR / "scaler.pkl"
    LABEL_ENCODER_FILE = MODEL_DIR / "label_encoder.pkl"
    FEATURE_NAMES_FILE = MODEL_DIR / "feature_names.json"
    
    # Prediction settings
    CHECK_INTERVAL = 2.0  # Check for new logs every 2 seconds
    BATCH_SIZE = 32  # Process logs in batches for efficiency
    CONFIDENCE_THRESHOLD = 0.90  # Minimum confidence for attack detection (raised to reduce false positives)
    
    # Alert settings
    MAX_ALERTS = 1000  # Maximum alerts to keep in alerts.json
    ALERT_COOLDOWN = 5  # Seconds to wait before alerting same flow again
    
    # Features expected by the model (must match training)
    EXPECTED_FEATURES = [
        'Flow Duration',
        'Total Fwd Packets',
        'Total Backward Packets',
        'Total Length of Fwd Packets',
        'Total Length of Bwd Packets',
        'Fwd Packet Length Max',
        'Fwd Packet Length Min',
        'Fwd Packet Length Mean',
        'Fwd Packet Length Std',
        'Bwd Packet Length Max',
        'Bwd Packet Length Min',
        'Bwd Packet Length Mean',
        'Bwd Packet Length Std',
        'Flow Bytes/s',
        'Flow Packets/s',
        'Flow IAT Mean',
        'Flow IAT Std',
        'Flow IAT Max',
        'Flow IAT Min',
        'Fwd IAT Mean',
        'Fwd IAT Std',
        'Fwd IAT Max',
        'Fwd IAT Min',
        'Bwd IAT Mean',
        'Bwd IAT Std',
        'Bwd IAT Max',
        'Bwd IAT Min',
        'FIN Flag Count',
        'SYN Flag Count',
        'RST Flag Count',
        'PSH Flag Count',
        'ACK Flag Count',
        'URG Flag Count',
        'ECE Flag Count',
        'CWR Flag Count',
        'Fwd PSH Flags',
        'Bwd PSH Flags',
        'Fwd URG Flags',
        'Bwd URG Flags',
        'Fwd Header Length',
        'Bwd Header Length',
        'Min Packet Length',
        'Max Packet Length',
        'Packet Length Mean',
        'Packet Length Std',
        'Packet Length Variance',
        'Down/Up Ratio',
        'Average Packet Size',
        'Avg Fwd Segment Size',
        'Avg Bwd Segment Size'
    ]

# ============================================================================
# MODEL LOADER
# ============================================================================

class ModelLoader:
    """Load and manage the trained model"""
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self.class_names = None
        
    def find_latest_model(self):
        """Find the most recent model file"""
        if not Config.MODEL_DIR.exists():
            raise FileNotFoundError(f"Model directory not found: {Config.MODEL_DIR}")
        
        # Look for .keras or .h5 model files
        model_files = list(Config.MODEL_DIR.glob("*.keras")) + list(Config.MODEL_DIR.glob("*.h5"))
        
        if not model_files:
            raise FileNotFoundError(f"No model files found in {Config.MODEL_DIR}")
        
        # Prefer files with "best" or "final" in the name
        best_models = [f for f in model_files if "best" in f.name.lower()]
        if best_models:
            model_files = best_models
        else:
            final_models = [f for f in model_files if "final" in f.name.lower()]
            if final_models:
                model_files = final_models
        
        # Get the most recent file
        latest_model = max(model_files, key=lambda x: x.stat().st_mtime)
        return latest_model
    
    def load(self):
        """Load all model components"""
        print("\n" + "=" * 80)
        print("LOADING MODEL COMPONENTS")
        print("=" * 80)
        
        try:
            # Find and load model
            model_path = self.find_latest_model()
            print(f"\n📦 Loading model: {model_path.name}")
            self.model = keras.models.load_model(str(model_path))
            print("✅ Model loaded successfully")
            
            # Load scaler
            if Config.SCALER_FILE.exists():
                print(f"\n📦 Loading scaler: {Config.SCALER_FILE.name}")
                self.scaler = joblib.load(Config.SCALER_FILE)
                print("✅ Scaler loaded successfully")
            else:
                raise FileNotFoundError(f"Scaler not found: {Config.SCALER_FILE}")
            
            # Load label encoder
            if Config.LABEL_ENCODER_FILE.exists():
                print(f"\n📦 Loading label encoder: {Config.LABEL_ENCODER_FILE.name}")
                self.label_encoder = joblib.load(Config.LABEL_ENCODER_FILE)
                self.class_names = self.label_encoder.classes_.tolist()
                print(f"✅ Label encoder loaded successfully")
                print(f"   Classes: {self.class_names}")
            else:
                raise FileNotFoundError(f"Label encoder not found: {Config.LABEL_ENCODER_FILE}")
            
            # Load feature names
            if Config.FEATURE_NAMES_FILE.exists():
                print(f"\n📦 Loading feature names: {Config.FEATURE_NAMES_FILE.name}")
                with open(Config.FEATURE_NAMES_FILE, 'r') as f:
                    self.feature_names = json.load(f)
                print(f"✅ Feature names loaded ({len(self.feature_names)} features)")
            else:
                print(f"⚠️  Warning: Feature names file not found, using default features")
                self.feature_names = Config.EXPECTED_FEATURES
            
            # Validate model input shape
            expected_features = self.model.input_shape[1]
            print(f"\n🔍 Model expects {expected_features} features")
            
            if len(self.feature_names) != expected_features:
                print(f"⚠️  WARNING: Feature count mismatch!")
                print(f"   Model expects: {expected_features}")
                print(f"   Feature file has: {len(self.feature_names)}")
            
            print("\n" + "=" * 80)
            print("✅ ALL COMPONENTS LOADED SUCCESSFULLY")
            print("=" * 80)
            
            return True
            
        except Exception as e:
            print(f"\n❌ ERROR loading model components: {e}")
            import traceback
            traceback.print_exc()
            return False

# ============================================================================
# TRAFFIC MONITOR
# ============================================================================

class TrafficMonitor:
    """Monitor traffic_log.json and detect intrusions"""
    
    def __init__(self, model_loader):
        self.model_loader = model_loader
        self.processed_flows = set()  # Track processed flow IDs
        self.last_alert_time = {}  # Track last alert time per flow
        self.stats = {
            'total_processed': 0,
            'attacks_detected': 0,
            'benign_flows': 0,
            'filtered_false_positives': 0,
            'errors': 0
        }
        
        # Ensure directories exist
        Config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        
        # Initialize alerts file if it doesn't exist
        if not Config.ALERTS_LOG.exists():
            self._save_alerts([])
    
    def _load_traffic_log(self):
        """Load traffic log file"""
        if not Config.TRAFFIC_LOG.exists():
            return []
        
        try:
            with open(Config.TRAFFIC_LOG, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                return []
        except json.JSONDecodeError:
            return []
        except Exception as e:
            print(f"⚠️  Error loading traffic log: {e}")
            return []
    
    def _load_alerts(self):
        """Load existing alerts"""
        if not Config.ALERTS_LOG.exists():
            return []
        
        try:
            with open(Config.ALERTS_LOG, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                return []
        except:
            return []
    
    def _save_alerts(self, alerts):
        """Save alerts to file"""
        try:
            # Keep only the most recent alerts
            if len(alerts) > Config.MAX_ALERTS:
                alerts = alerts[-Config.MAX_ALERTS:]
            
            with open(Config.ALERTS_LOG, 'w') as f:
                json.dump(alerts, f, indent=2)
        except Exception as e:
            print(f"⚠️  Error saving alerts: {e}")
    
    def _prepare_features(self, flows):
        """Prepare features for prediction"""
        if not flows:
            return None, []
        
        # Convert to DataFrame
        df = pd.DataFrame(flows)
        
        # Extract flow IDs for tracking
        flow_ids = df.get('Flow ID', ['unknown'] * len(df)).tolist()
        
        # Keep only feature columns that exist
        available_features = [f for f in self.model_loader.feature_names if f in df.columns]
        
        if len(available_features) != len(self.model_loader.feature_names):
            missing = set(self.model_loader.feature_names) - set(available_features)
            print(f"⚠️  Warning: Missing features: {missing}")
            
            # Add missing features with default value 0
            for feat in self.model_loader.feature_names:
                if feat not in df.columns:
                    df[feat] = 0
        
        # Select features in the correct order
        X = df[self.model_loader.feature_names]
        
        # Handle missing values and infinite values
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(0)
        
        # Convert to numpy array
        X = X.values
        
        # Scale features
        X_scaled = self.model_loader.scaler.transform(X)
        
        return X_scaled, flow_ids
    
    def _should_alert(self, flow_id, flow, class_name):
        """Check if we should alert for this flow (with false positive filtering)"""
        
        # Extract flow details
        src_ip = flow.get('Src IP', '')
        dst_ip = flow.get('Dst IP', '')
        src_port = flow.get('Src Port', 0)
        dst_port = flow.get('Dst Port', 0)
        total_packets = flow.get('Total Fwd Packets', 0) + flow.get('Total Backward Packets', 0)
        
        # ============================================================================
        # FALSE POSITIVE FILTERING - Skip alerts for common legitimate traffic
        # ============================================================================
        
        # 1. DNS traffic (port 53) - Normal name resolution
        if src_port == 53 or dst_port == 53:
            self.stats['filtered_false_positives'] += 1
            return False
        
        # 2. Low-volume HTTPS traffic (port 443) - Normal web browsing
        if (src_port == 443 or dst_port == 443) and total_packets < 100:
            self.stats['filtered_false_positives'] += 1
            return False
        
        # 3. Multicast/Broadcast traffic (mDNS, SSDP, etc.)
        if dst_ip.startswith('224.') or dst_ip.startswith('239.'):
            self.stats['filtered_false_positives'] += 1
            return False
        
        # 4. mDNS service discovery (port 5353)
        if src_port == 5353 or dst_port == 5353:
            self.stats['filtered_false_positives'] += 1
            return False
        
        # 5. SSDP/UPnP discovery (port 1900)
        if src_port == 1900 or dst_port == 1900:
            self.stats['filtered_false_positives'] += 1
            return False
        
        # 6. Local router traffic with low packet count
        if (src_ip.startswith('192.168.') and total_packets < 50):
            # Allow only high-severity attacks from local network
            high_severity = ['DDoS', 'DoS Hulk', 'Infiltration', 'SSH-Patator', 'FTP-Patator']
            if class_name not in high_severity:
                self.stats['filtered_false_positives'] += 1
                return False
        
        # ============================================================================
        # COOLDOWN LOGIC - Prevent alert spam
        # ============================================================================
        
        current_time = time.time()
        
        if flow_id in self.last_alert_time:
            time_since_last = current_time - self.last_alert_time[flow_id]
            if time_since_last < Config.ALERT_COOLDOWN:
                return False
        
        self.last_alert_time[flow_id] = current_time
        return True
    
    def _create_alert(self, flow, predicted_class, confidence):
        """Create an alert entry"""
        alert = {
            'Timestamp': datetime.now().isoformat(),
            'Flow ID': flow.get('Flow ID', 'unknown'),
            'Src IP': flow.get('Src IP', 'unknown'),
            'Src Port': flow.get('Src Port', 0),
            'Dst IP': flow.get('Dst IP', 'unknown'),
            'Dst Port': flow.get('Dst Port', 0),
            'Protocol': flow.get('Protocol', 0),
            'Flow Duration': flow.get('Flow Duration', 0),
            'Total Fwd Packets': flow.get('Total Fwd Packets', 0),
            'Total Backward Packets': flow.get('Total Backward Packets', 0),
            'Flow Bytes/s': flow.get('Flow Bytes/s', 0),
            'Attack Type': predicted_class,
            'Confidence': float(confidence),
            'Severity': self._get_severity(predicted_class, confidence)
        }
        return alert
    
    def _get_severity(self, attack_type, confidence):
        """Determine alert severity"""
        # High severity attacks
        high_severity = ['DDoS', 'DoS', 'Infiltration', 'Bot']
        
        # Medium severity attacks
        medium_severity = ['PortScan', 'Port Scan', 'Web Attack', 'Brute Force']
        
        if attack_type in high_severity:
            if confidence > 0.9:
                return 'CRITICAL'
            return 'HIGH'
        elif attack_type in medium_severity:
            if confidence > 0.9:
                return 'HIGH'
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def predict_and_alert(self, flows):
        """Predict on flows and generate alerts for attacks"""
        if not flows:
            return
        
        try:
            # Prepare features
            X_scaled, flow_ids = self._prepare_features(flows)
            
            if X_scaled is None or len(X_scaled) == 0:
                return
            
            # Make predictions
            predictions = self.model_loader.model.predict(X_scaled, verbose=0)
            predicted_classes = np.argmax(predictions, axis=1)
            confidences = np.max(predictions, axis=1)
            
            # Load existing alerts
            alerts = self._load_alerts()
            
            # Process each prediction
            for i, (flow, flow_id, pred_class, confidence) in enumerate(
                zip(flows, flow_ids, predicted_classes, confidences)
            ):
                # Update stats
                self.stats['total_processed'] += 1
                
                # Get class name
                class_name = self.model_loader.class_names[pred_class]
                
                # Check if it's an attack (not BENIGN)
                is_attack = class_name.upper() != 'BENIGN' and confidence >= Config.CONFIDENCE_THRESHOLD
                
                if is_attack:
                    self.stats['attacks_detected'] += 1
                    
                    # Check cooldown and false positive filtering
                    if self._should_alert(flow_id, flow, class_name):
                        # Create alert
                        alert = self._create_alert(flow, class_name, confidence)
                        alerts.append(alert)
                        
                        # Print to console
                        print(f"\n🚨 ATTACK DETECTED!")
                        print(f"   Type: {class_name}")
                        print(f"   Confidence: {confidence:.2%}")
                        print(f"   Source: {flow.get('Src IP')}:{flow.get('Src Port')}")
                        print(f"   Destination: {flow.get('Dst IP')}:{flow.get('Dst Port')}")
                        print(f"   Severity: {alert['Severity']}")
                else:
                    self.stats['benign_flows'] += 1
            
            # Save alerts
            if alerts:
                self._save_alerts(alerts)
            
        except Exception as e:
            self.stats['errors'] += 1
            print(f"⚠️  Error during prediction: {e}")
            import traceback
            traceback.print_exc()
    
    def run(self):
        """Main monitoring loop"""
        print("\n" + "=" * 80)
        print("🔍 STARTING REAL-TIME MONITORING")
        print("=" * 80)
        print(f"\n📁 Monitoring: {Config.TRAFFIC_LOG}")
        print(f"📁 Alerts will be saved to: {Config.ALERTS_LOG}")
        print(f"⏱️  Check interval: {Config.CHECK_INTERVAL} seconds")
        print(f"🎯 Confidence threshold: {Config.CONFIDENCE_THRESHOLD:.2%}")
        print(f"🛡️  False positive filtering: ENABLED")
        print("\nPress Ctrl+C to stop monitoring...")
        print("=" * 80 + "\n")
        
        last_check_time = time.time()
        
        try:
            while True:
                # Load traffic log
                flows = self._load_traffic_log()
                
                # Filter out already processed flows
                new_flows = []
                for flow in flows:
                    flow_id = flow.get('Flow ID', 'unknown')
                    if flow_id not in self.processed_flows:
                        new_flows.append(flow)
                        self.processed_flows.add(flow_id)
                
                # Process new flows
                if new_flows:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Processing {len(new_flows)} new flow(s)...")
                    self.predict_and_alert(new_flows)
                
                # Print stats periodically (every 30 seconds)
                current_time = time.time()
                if current_time - last_check_time >= 30:
                    print(f"\n📊 Statistics:")
                    print(f"   Total processed: {self.stats['total_processed']}")
                    print(f"   Attacks detected: {self.stats['attacks_detected']}")
                    print(f"   Benign flows: {self.stats['benign_flows']}")
                    print(f"   Filtered false positives: {self.stats['filtered_false_positives']}")
                    print(f"   Errors: {self.stats['errors']}")
                    last_check_time = current_time
                
                # Wait before next check
                time.sleep(Config.CHECK_INTERVAL)
                
        except KeyboardInterrupt:
            print("\n\n" + "=" * 80)
            print("🛑 MONITORING STOPPED BY USER")
            print("=" * 80)
            print(f"\n📊 Final Statistics:")
            print(f"   Total processed: {self.stats['total_processed']}")
            print(f"   Attacks detected: {self.stats['attacks_detected']}")
            print(f"   Benign flows: {self.stats['benign_flows']}")
            print(f"   Filtered false positives: {self.stats['filtered_false_positives']}")
            print(f"   Errors: {self.stats['errors']}")
            print("\nThank you for using CyberHawk IDS!")
            print("=" * 80 + "\n")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution function"""
    
    print("\n" + "=" * 80)
    print("CyberHawk IDS - Real-Time Prediction System")
    print("Final Year Project")
    print("=" * 80)
    print(f"\n⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Wait for traffic sniffer to collect initial data
    STARTUP_DELAY = 10  # seconds
    print(f"\n⏳ Waiting {STARTUP_DELAY} seconds for traffic sniffer to collect initial data...")
    for remaining in range(STARTUP_DELAY, 0, -1):
        print(f"   Starting in {remaining} seconds...", end='\r')
        time.sleep(1)
    print("\n✅ Startup delay complete. Beginning monitoring...")
    
    try:
        # Load model components
        model_loader = ModelLoader()
        if not model_loader.load(): 
            print("\n❌ Failed to load model components. Exiting...")
            sys.exit(1)
        
        # Start monitoring
        monitor = TrafficMonitor(model_loader)
        monitor.run()
        
    except Exception as e:
        print(f"\n❌ CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()