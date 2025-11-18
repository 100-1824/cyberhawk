# ===== CELL 1: Install Dependencies =====
#!pip install scikit-learn numpy pandas joblib -q
print("✓ Dependencies installed")

# ===== CELL 2: Training Code =====
import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib
import warnings
warnings.filterwarnings('ignore')

class RansomwareMLTrainer:
    def __init__(self):
        self.model = None
        self.feature_names = [
            'entropy',
            'file_size',
            'suspicious_extension',
            'executable_header',
            'high_entropy_sections',
            'packed_indicator',
            'api_call_suspicious',
            'string_entropy',
            'section_count',
            'import_count'
        ]
    
    def create_synthetic_training_data(self):
        """Create synthetic training data with realistic noise"""
        print("[DATA] Creating synthetic training dataset...")
        
        np.random.seed(42)
        n_samples = 1000
        
        # Benign files
        benign_samples = []
        for _ in range(n_samples // 2):
            features = [
                np.random.uniform(3.0, 6.0),
                np.random.uniform(0.1, 5.0),
                0,
                np.random.choice([0, 1], p=[0.8, 0.2]),
                np.random.randint(0, 3),
                0,
                np.random.randint(0, 2),
                np.random.uniform(3.0, 5.5),
                np.random.randint(3, 8),
                np.random.randint(5, 30)
            ]
            benign_samples.append(features)
        
        # Ransomware files
        ransomware_samples = []
        for _ in range(n_samples // 2):
            features = [
                np.random.uniform(7.0, 8.0),
                np.random.uniform(0.5, 10.0),
                np.random.choice([0, 1], p=[0.3, 0.7]),
                np.random.choice([0, 1], p=[0.2, 0.8]),
                np.random.randint(5, 10),
                np.random.choice([0, 1], p=[0.5, 0.5]),
                np.random.randint(2, 5),
                np.random.uniform(6.5, 8.0),
                np.random.randint(5, 15),
                np.random.randint(20, 50)
            ]
            ransomware_samples.append(features)
        
        X = np.array(benign_samples + ransomware_samples)
        y = np.array([0] * len(benign_samples) + [1] * len(ransomware_samples))
        
        # ADD: Introduce realistic noise to reduce overfitting
        print("[DATA] Adding realistic noise to prevent overfitting...")
        noise = np.random.normal(0, 0.1, X.shape)  # 10% noise
        X = X + noise
        X = np.clip(X, 0, None)  # Keep values positive
        
        # Add 5% label noise (mislabeled samples)
        noise_indices = np.random.choice(len(y), size=int(len(y) * 0.05), replace=False)
        y[noise_indices] = 1 - y[noise_indices]  # Flip labels
        print(f"[DATA] Added noise to {len(noise_indices)} samples")
        
        # Shuffle data
        indices = np.random.permutation(len(X))
        X = X[indices]
        y = y[indices]
        
        print(f"[DATA] Created {len(X)} samples:")
        print(f"       - {len(benign_samples)} benign files")
        print(f"       - {len(ransomware_samples)} ransomware files")
        
        return X, y
    
    def train_model(self, X_train, y_train):
        """Train Random Forest with regularization"""
        print("\n[TRAIN] Training Random Forest Classifier...")
        print("[TRAIN] Hyperparameters (with regularization):")
        print("        - Trees: 100")
        print("        - Max Depth: 15 (reduced from 20)")
        print("        - Min Samples Split: 10 (increased from 5)")
        print("        - Min Samples Leaf: 4 (increased from 2)")
        
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,  # Reduced to prevent overfitting
            min_samples_split=10,  # Increased to prevent overfitting
            min_samples_leaf=4,  # Increased to prevent overfitting
            max_features='sqrt',  # Use sqrt of features
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        print("[TRAIN] ✓ Model training completed")
    
    def evaluate_model(self, X_test, y_test):
        """Evaluate model"""
        print("\n[EVAL] Evaluating model on test set...")
        
        y_pred = self.model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)
        
        print("\n" + "="*60)
        print("MODEL EVALUATION RESULTS")
        print("="*60)
        print(f"Accuracy:  {accuracy*100:.2f}%")
        print(f"Precision: {precision*100:.2f}%")
        print(f"Recall:    {recall*100:.2f}%")
        print(f"F1-Score:  {f1*100:.2f}%")
        print("\nConfusion Matrix:")
        print(f"                Predicted")
        print(f"              Benign  Ransomware")
        print(f"Actual Benign    {cm[0][0]:3d}      {cm[0][1]:3d}")
        print(f"       Ransomware {cm[1][0]:3d}      {cm[1][1]:3d}")
        print("="*60)
        
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        print("\nTop 5 Important Features:")
        for i in range(min(5, len(indices))):
            print(f"  {i+1}. {self.feature_names[indices[i]]}: {importances[indices[i]]:.4f}")
        
        return {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'confusion_matrix': cm.tolist(),
            'feature_importance': {
                self.feature_names[i]: float(importances[i]) 
                for i in range(len(self.feature_names))
            }
        }
    
    def save_model(self, path):
        """Save model"""
        joblib.dump(self.model, path)
        print(f"\n[SAVE] ✓ Model saved to: {path}")
    
    def save_metrics(self, metrics, path):
        """Save metrics"""
        with open(path, 'w') as f:
            json.dump(metrics, f, indent=2)
        print(f"[SAVE] ✓ Metrics saved to: {path}")

# ===== CELL 3: Train Model =====
print("\n" + "="*60)
print("CYBERHAWK RANSOMWARE DETECTION - MODEL TRAINING")
print("="*60 + "\n")

trainer = RansomwareMLTrainer()

# Create data
X, y = trainer.create_synthetic_training_data()

# Split
print("\n[SPLIT] Splitting into train/test sets (80/20)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"[SPLIT] Training samples: {len(X_train)}")
print(f"[SPLIT] Testing samples:  {len(X_test)}")

# Train
trainer.train_model(X_train, y_train)

# Evaluate
metrics = trainer.evaluate_model(X_test, y_test)

# Save
trainer.save_model('ransomware_model.pkl')
trainer.save_metrics(metrics, 'model_metrics.json')

print("\n" + "="*60)
print("✓ TRAINING COMPLETE!")
print("="*60)

# ===== CELL 4: Download Files =====
from google.colab import files

print("\n[DOWNLOAD] Downloading model file...")
files.download('ransomware_model.pkl')

print("[DOWNLOAD] Downloading metrics file...")
files.download('model_metrics.json')

print("\n✓ Files downloaded!")
print("\nNext steps:")
print("1. Place ransomware_model.pkl in: cyberhawk/python/ranswomware/")
print("2. Place model_metrics.json in: cyberhawk/assets/data/")