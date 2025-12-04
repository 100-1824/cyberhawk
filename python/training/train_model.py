"""
IDSModelTrainer Class

Purpose: Trains machine learning models for intrusion detection system.

This class handles the complete training pipeline including data loading,
preprocessing, model creation, training, and evaluation.

Author: Muhammad Ahmed
Final Year Project - CyberHawk IDS
"""

import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_recall_fscore_support
)
from datetime import datetime
import json
import warnings
warnings.filterwarnings('ignore')

# Set random seeds for reproducibility
np.random.seed(42)


class IDSModelTrainer:
    """
    Machine Learning Model Trainer for CyberHawk Intrusion Detection System.

    Handles complete training pipeline:
    - Data loading and preprocessing
    - Feature engineering
    - Model creation and training
    - Evaluation and reporting
    """

    def __init__(self, base_dir="/content/drive/MyDrive/cyberhawk"):
        """
        Initialize the IDSModelTrainer

        Args:
            base_dir: Base directory containing datasets and models
        """
        self.base_dir = base_dir
        self.dataset_dir = os.path.join(base_dir, "datasets")
        self.model_dir = os.path.join(base_dir, "models")

        # Create directories
        os.makedirs(self.dataset_dir, exist_ok=True)
        os.makedirs(self.model_dir, exist_ok=True)

        # Configuration
        self.config = {
            'EPOCHS': 200,
            'BATCH_SIZE': 256,
            'VALIDATION_SPLIT': 0.2,
            'TEST_SIZE': 0.15,
            'RANDOM_STATE': 42,
            'LEARNING_RATE': 0.001,
            'DROPOUT_RATE': 0.3,
            'MIN_SAMPLES_THRESHOLD': 500
        }

        # Dataset files
        self.dataset_files = [
            "monday.csv",
            "tuesday.csv",
            "wednesday.csv",
            "thursday.csv",
            "friday.csv"
        ]

        # Features that match captured JSON structure
        self.captured_features = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Fwd Packet Length Max', 'Fwd Packet Length Min',
            'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Max', 'Bwd Packet Length Min',
            'Bwd Packet Length Mean', 'Bwd Packet Length Std',
            'Flow Bytes/s', 'Flow Packets/s',
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
            'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
            'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
            'ECE Flag Count', 'CWR Flag Count',
            'Fwd PSH Flags', 'Bwd PSH Flags',
            'Fwd URG Flags', 'Bwd URG Flags',
            'Fwd Header Length', 'Bwd Header Length',
            'Min Packet Length', 'Max Packet Length',
            'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
            'Down/Up Ratio', 'Average Packet Size',
            'Avg Fwd Segment Size', 'Avg Bwd Segment Size'
        ]

        # Column mapping for inconsistent names
        self.column_mapping = self._build_column_mapping()

        # Model components
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self.training_history = None

        print("="*80)
        print("CyberHawk IDS - Model Trainer Initialized")
        print("="*80)
        print(f"Dataset Directory: {self.dataset_dir}")
        print(f"Model Directory: {self.model_dir}")
        print(f"Max Epochs: {self.config['EPOCHS']}")
        print("="*80)

    def _build_column_mapping(self):
        """Build column name mapping dictionary"""
        mapping = {}
        for feat in self.captured_features:
            mapping[' ' + feat] = feat
            mapping[feat] = feat
        mapping[' Label'] = 'Label'
        mapping['Label'] = 'Label'
        return mapping

    def loadAndPreprocessData(self):
        """
        Load and preprocess all CICIDS2017 dataset files

        Returns:
            pd.DataFrame: Combined and preprocessed dataset
        """
        print("\n" + "="*80)
        print("LOADING AND PREPROCESSING DATA")
        print("="*80)

        all_data = []

        for filename in self.dataset_files:
            filepath = os.path.join(self.dataset_dir, filename)

            if not os.path.exists(filepath):
                print(f"⚠️  WARNING: {filename} not found! Skipping...")
                continue

            print(f"\n📁 Loading {filename}...")

            try:
                df = pd.read_csv(filepath, encoding='utf-8', low_memory=False)
                print(f"   Raw shape: {df.shape}")

                # Standardize column names
                df.columns = df.columns.str.strip()
                df = df.rename(columns=self.column_mapping)

                if 'Label' not in df.columns:
                    print(f"   ⚠️  WARNING: No 'Label' column found")
                    continue

                # Remove duplicates
                before = len(df)
                df = df.drop_duplicates()
                print(f"   Removed {before - len(df)} duplicates")

                # Handle missing/infinite values
                df = df.replace([np.inf, -np.inf], np.nan)
                numeric_cols = df.select_dtypes(include=[np.number]).columns
                for col in numeric_cols:
                    if df[col].isnull().any():
                        df[col].fillna(df[col].median(), inplace=True)

                print(f"   Processed shape: {df.shape}")
                all_data.append(df)

            except Exception as e:
                print(f"   ❌ ERROR: {str(e)}")
                continue

        if not all_data:
            raise ValueError("No data could be loaded!")

        combined_df = pd.concat(all_data, ignore_index=True)
        print(f"\n✅ Combined shape: {combined_df.shape}")

        return combined_df

    def prepareFeaturesAndLabels(self, df):
        """
        Prepare features and labels for training

        Args:
            df: Input dataframe

        Returns:
            tuple: (X, y_encoded, label_encoder, feature_names)
        """
        print("\n" + "="*80)
        print("FEATURE ENGINEERING")
        print("="*80)

        df = df[df['Label'].notna()]
        print(f"✅ Samples after cleaning: {len(df):,}")

        X = df.drop(['Label'], axis=1, errors='ignore')
        y = df['Label']

        # Remove non-numeric columns
        non_numeric = X.select_dtypes(exclude=[np.number]).columns
        if len(non_numeric) > 0:
            X = X.drop(columns=non_numeric)

        # Keep only available features
        available_features = [f for f in self.captured_features if f in X.columns]
        X = X[available_features]

        print(f"✅ Using {len(available_features)} features")

        # Handle NaN/Inf
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

        # Encode labels
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)

        print(f"✅ Number of classes: {len(self.label_encoder.classes_)}")

        return X, y_encoded, self.label_encoder, available_features

    def balanceDataset(self, X, y):
        """
        Balance dataset using improved sampling strategy

        Args:
            X: Features
            y: Labels

        Returns:
            tuple: (X_balanced, y_balanced)
        """
        print("\n" + "="*80)
        print("BALANCING DATASET")
        print("="*80)

        unique_classes, class_counts = np.unique(y, return_counts=True)

        min_threshold = self.config['MIN_SAMPLES_THRESHOLD']
        valid_classes = unique_classes[class_counts >= min_threshold]
        valid_counts = class_counts[class_counts >= min_threshold]

        if len(valid_classes) == 0:
            raise ValueError(f"No classes have at least {min_threshold} samples!")

        # Use median for better sampling
        median_samples = int(np.median(valid_counts))
        target_samples = min(median_samples, 100000)
        target_samples = max(target_samples, min_threshold)

        print(f"🎯 Target samples per class: {target_samples:,}")

        balanced_indices = []
        for cls in valid_classes:
            cls_indices = np.where(y == cls)[0]
            if len(cls_indices) >= target_samples:
                selected = np.random.choice(cls_indices, target_samples, replace=False)
            else:
                selected = cls_indices
            balanced_indices.extend(selected)

        balanced_indices = np.array(balanced_indices)
        np.random.shuffle(balanced_indices)

        X_balanced = X.iloc[balanced_indices].reset_index(drop=True)
        y_balanced_old = y[balanced_indices]

        # Re-encode labels
        old_to_new = {old_cls: new_cls for new_cls, old_cls in enumerate(valid_classes)}
        y_balanced = np.array([old_to_new[old_cls] for old_cls in y_balanced_old])

        # Update label encoder
        new_label_encoder = LabelEncoder()
        new_label_encoder.classes_ = self.label_encoder.classes_[valid_classes]
        self.label_encoder = new_label_encoder

        print(f"✅ Balanced samples: {len(X_balanced):,}")
        print(f"✅ Classes: {len(valid_classes)}")

        return X_balanced, y_balanced

    def createModel(self, input_dim, num_classes):
        """
        Create deep learning model architecture

        Args:
            input_dim: Number of input features
            num_classes: Number of output classes

        Returns:
            keras.Model: Compiled model
        """
        print("\n" + "="*80)
        print("BUILDING MODEL ARCHITECTURE")
        print("="*80)

        import tensorflow as tf
        from tensorflow import keras
        from tensorflow.keras import layers

        tf.random.set_seed(42)

        model = keras.Sequential([
            layers.Input(shape=(input_dim,)),

            layers.Dense(256, activation='relu',
                        kernel_regularizer=keras.regularizers.l2(0.001)),
            layers.BatchNormalization(),
            layers.Dropout(self.config['DROPOUT_RATE']),

            layers.Dense(128, activation='relu',
                        kernel_regularizer=keras.regularizers.l2(0.001)),
            layers.BatchNormalization(),
            layers.Dropout(self.config['DROPOUT_RATE']),

            layers.Dense(64, activation='relu',
                        kernel_regularizer=keras.regularizers.l2(0.001)),
            layers.BatchNormalization(),
            layers.Dropout(self.config['DROPOUT_RATE']),

            layers.Dense(32, activation='relu',
                        kernel_regularizer=keras.regularizers.l2(0.001)),
            layers.BatchNormalization(),
            layers.Dropout(self.config['DROPOUT_RATE'] / 2),

            layers.Dense(num_classes, activation='softmax')
        ])

        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.config['LEARNING_RATE']),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )

        print("\n📋 Model Summary:")
        model.summary()

        self.model = model
        return model

    def trainModel(self, X_train, y_train, X_val, y_val):
        """
        Train the model with callbacks

        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features
            y_val: Validation labels

        Returns:
            tuple: (history, model_name)
        """
        print("\n" + "="*80)
        print("TRAINING MODEL")
        print("="*80)

        from tensorflow.keras.callbacks import ModelCheckpoint, EarlyStopping, ReduceLROnPlateau

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_name = f"cyberhawk_ids_model_{timestamp}"
        checkpoint_path = os.path.join(self.model_dir, f"{model_name}_best.keras")

        callbacks = [
            ModelCheckpoint(checkpoint_path, monitor='val_accuracy',
                          save_best_only=True, mode='max', verbose=1),
            EarlyStopping(monitor='val_loss', patience=15,
                         restore_best_weights=True, verbose=1),
            ReduceLROnPlateau(monitor='val_loss', factor=0.5,
                            patience=5, min_lr=1e-7, verbose=1)
        ]

        print(f"🚀 Training for up to {self.config['EPOCHS']} epochs...")

        history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=self.config['EPOCHS'],
            batch_size=self.config['BATCH_SIZE'],
            callbacks=callbacks,
            verbose=1
        )

        self.training_history = history
        print(f"\n✅ Training completed! Epochs: {len(history.history['loss'])}")

        return history, model_name

    def evaluateModel(self, X_test, y_test, model_name):
        """
        Evaluate model and generate reports

        Args:
            X_test: Test features
            y_test: Test labels
            model_name: Name for saving reports

        Returns:
            dict: Evaluation metrics
        """
        print("\n" + "="*80)
        print("MODEL EVALUATION")
        print("="*80)

        y_pred_probs = self.model.predict(X_test, batch_size=self.config['BATCH_SIZE'], verbose=1)
        y_pred = np.argmax(y_pred_probs, axis=1)

        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average='weighted'
        )

        print(f"\n📊 Overall Metrics:")
        print(f"   Accuracy:  {accuracy:.4f}")
        print(f"   Precision: {precision:.4f}")
        print(f"   Recall:    {recall:.4f}")
        print(f"   F1-Score:  {f1:.4f}")

        # Save reports
        self._saveClassificationReport(y_test, y_pred, model_name, accuracy, precision, recall, f1)
        self._saveConfusionMatrix(y_test, y_pred, model_name)

        return {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1)
        }

    def _saveClassificationReport(self, y_test, y_pred, model_name, accuracy, precision, recall, f1):
        """Save classification report to file"""
        report_path = os.path.join(self.model_dir, f"{model_name}_classification_report.txt")
        report = classification_report(y_test, y_pred,
                                      target_names=self.label_encoder.classes_,
                                      digits=4)

        with open(report_path, 'w') as f:
            f.write("CyberHawk IDS - Classification Report\n")
            f.write("="*80 + "\n\n")
            f.write(f"Accuracy:  {accuracy:.4f}\n")
            f.write(f"Precision: {precision:.4f}\n")
            f.write(f"Recall:    {recall:.4f}\n")
            f.write(f"F1-Score:  {f1:.4f}\n\n")
            f.write(report)

        print(f"💾 Report saved: {report_path}")

    def _saveConfusionMatrix(self, y_test, y_pred, model_name):
        """Save confusion matrix plot"""
        cm = confusion_matrix(y_test, y_pred)

        plt.figure(figsize=(12, 10))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=self.label_encoder.classes_,
                   yticklabels=self.label_encoder.classes_)
        plt.title('Confusion Matrix - CyberHawk IDS')
        plt.xlabel('Predicted')
        plt.ylabel('True')
        plt.tight_layout()

        cm_path = os.path.join(self.model_dir, f"{model_name}_confusion_matrix.png")
        plt.savefig(cm_path, dpi=300)
        plt.close()

        print(f"💾 Confusion matrix saved: {cm_path}")

    def saveModelAndComponents(self, model_name):
        """
        Save model and all components

        Args:
            model_name: Name for saved files
        """
        import joblib

        # Save model
        final_path = os.path.join(self.model_dir, f"{model_name}_final.keras")
        self.model.save(final_path)
        print(f"💾 Model saved: {final_path}")

        # Save scaler
        scaler_path = os.path.join(self.model_dir, "scaler.pkl")
        joblib.dump(self.scaler, scaler_path)
        print(f"💾 Scaler saved: {scaler_path}")

        # Save label encoder
        encoder_path = os.path.join(self.model_dir, "label_encoder.pkl")
        joblib.dump(self.label_encoder, encoder_path)
        print(f"💾 Label encoder saved: {encoder_path}")

        # Save feature names
        feature_path = os.path.join(self.model_dir, "feature_names.json")
        with open(feature_path, 'w') as f:
            json.dump(self.feature_names, f, indent=2)
        print(f"💾 Feature names saved: {feature_path}")

    def train(self):
        """
        Execute complete training pipeline

        Returns:
            dict: Training results and metrics
        """
        start_time = datetime.now()
        print(f"\n⏰ Training started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

        try:
            # Load data
            df = self.loadAndPreprocessData()

            # Prepare features
            X, y, _, feature_names = self.prepareFeaturesAndLabels(df)
            self.feature_names = feature_names

            # Balance dataset
            X_balanced, y_balanced = self.balanceDataset(X, y)

            # Split data
            X_temp, X_test, y_temp, y_test = train_test_split(
                X_balanced, y_balanced,
                test_size=self.config['TEST_SIZE'],
                random_state=self.config['RANDOM_STATE'],
                stratify=y_balanced
            )

            X_train, X_val, y_train, y_val = train_test_split(
                X_temp, y_temp,
                test_size=self.config['VALIDATION_SPLIT'],
                random_state=self.config['RANDOM_STATE'],
                stratify=y_temp
            )

            print(f"\n✅ Train: {len(X_train):,} | Val: {len(X_val):,} | Test: {len(X_test):,}")

            # Standardize
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_val_scaled = self.scaler.transform(X_val)
            X_test_scaled = self.scaler.transform(X_test)

            # Create model
            num_features = X_train_scaled.shape[1]
            num_classes = len(np.unique(y_train))
            self.createModel(num_features, num_classes)

            # Train
            history, model_name = self.trainModel(X_train_scaled, y_train,
                                                 X_val_scaled, y_val)

            # Evaluate
            metrics = self.evaluateModel(X_test_scaled, y_test, model_name)

            # Save everything
            self.saveModelAndComponents(model_name)

            duration = datetime.now() - start_time

            print("\n" + "="*80)
            print("✅ TRAINING COMPLETED SUCCESSFULLY!")
            print("="*80)
            print(f"⏰ Duration: {duration}")
            print(f"🎯 Accuracy: {metrics['accuracy']:.4f}")
            print(f"📊 F1-Score: {metrics['f1_score']:.4f}")
            print("="*80)

            return {
                'success': True,
                'metrics': metrics,
                'model_name': model_name,
                'duration': str(duration)
            }

        except Exception as e:
            print(f"\n❌ ERROR: {str(e)}")
            import traceback
            traceback.print_exc()
            return {'success': False, 'error': str(e)}


def main():
    """Main execution function"""
    print("="*80)
    print("CyberHawk IDS - Training Script (Class-Based)")
    print("="*80)

    # Create trainer
    trainer = IDSModelTrainer()

    # Run training
    result = trainer.train()

    if result['success']:
        print("\n✨ Training pipeline completed successfully!")
    else:
        print(f"\n❌ Training failed: {result['error']}")


if __name__ == "__main__":
    main()
