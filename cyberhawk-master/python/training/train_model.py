"""
CyberHawk Intrusion Detection System - IMPROVED Training Script
Final Year Project
Author: Muhammad Ahmed

IMPROVEMENTS:
1. More epochs (200 instead of 50) with smart early stopping
2. Better sampling strategy - uses MORE samples per class
3. Longer patience for early stopping
4. Better monitoring to prevent overfitting

IMPORTANT: If you get JAX import errors, run this first:
    !pip uninstall jax jaxlib -y -q
    Then: Runtime → Restart runtime
    Then run this script
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

print("=" * 80)
print("CyberHawk IDS - IMPROVED Training Script")
print("=" * 80)

# Import TensorFlow
print("Importing TensorFlow...")
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from tensorflow.keras.callbacks import ModelCheckpoint, EarlyStopping, ReduceLROnPlateau

tf.random.set_seed(42)

print(f"TensorFlow Version: {tf.__version__}")
print(f"GPU Available: {tf.config.list_physical_devices('GPU')}")
print("=" * 80)

# ============================================================================
# CONFIGURATION
# ============================================================================

# Paths
BASE_DIR = "/content/drive/MyDrive/cyberhawk"
DATASET_DIR = os.path.join(BASE_DIR, "datasets")
MODEL_DIR = os.path.join(BASE_DIR, "models")

# Create directories if they don't exist
os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

# Dataset files
DATASET_FILES = [
    "monday.csv",
    "tuesday.csv",
    "wednesday.csv",
    "thursday.csv",
    "friday.csv"
]

# Training configuration - IMPROVED
EPOCHS = 200  # Increased from 50 - will stop early if overfitting
BATCH_SIZE = 256
VALIDATION_SPLIT = 0.2
TEST_SIZE = 0.15
RANDOM_STATE = 42

# Model configuration
LEARNING_RATE = 0.001
DROPOUT_RATE = 0.3

print(f"\n✨ IMPROVEMENTS IN THIS VERSION:")
print(f"   - Training for up to {EPOCHS} epochs (increased from 50)")
print(f"   - Better sampling strategy for more data per class")
print(f"   - Smarter early stopping (patience=15 instead of 10)")
print(f"   - Will automatically stop when overfitting starts")
print(f"\nDataset Directory: {DATASET_DIR}")
print(f"Model Directory: {MODEL_DIR}")
print("=" * 80)

# ============================================================================
# COLUMN MAPPING - Handle inconsistent column names across different days
# ============================================================================

COLUMN_MAPPING = {
    # Common variations in CICIDS2017 dataset
    ' Destination Port': 'Destination Port',
    ' Flow Duration': 'Flow Duration',
    ' Total Fwd Packets': 'Total Fwd Packets',
    ' Total Backward Packets': 'Total Backward Packets',
    ' Total Length of Fwd Packets': 'Total Length of Fwd Packets',
    ' Total Length of Bwd Packets': 'Total Length of Bwd Packets',
    ' Fwd Packet Length Max': 'Fwd Packet Length Max',
    ' Fwd Packet Length Min': 'Fwd Packet Length Min',
    ' Fwd Packet Length Mean': 'Fwd Packet Length Mean',
    ' Fwd Packet Length Std': 'Fwd Packet Length Std',
    ' Bwd Packet Length Max': 'Bwd Packet Length Max',
    ' Bwd Packet Length Min': 'Bwd Packet Length Min',
    ' Bwd Packet Length Mean': 'Bwd Packet Length Mean',
    ' Bwd Packet Length Std': 'Bwd Packet Length Std',
    ' Flow Bytes/s': 'Flow Bytes/s',
    ' Flow Packets/s': 'Flow Packets/s',
    ' Flow IAT Mean': 'Flow IAT Mean',
    ' Flow IAT Std': 'Flow IAT Std',
    ' Flow IAT Max': 'Flow IAT Max',
    ' Flow IAT Min': 'Flow IAT Min',
    ' Fwd IAT Total': 'Fwd IAT Total',
    ' Fwd IAT Mean': 'Fwd IAT Mean',
    ' Fwd IAT Std': 'Fwd IAT Std',
    ' Fwd IAT Max': 'Fwd IAT Max',
    ' Fwd IAT Min': 'Fwd IAT Min',
    ' Bwd IAT Total': 'Bwd IAT Total',
    ' Bwd IAT Mean': 'Bwd IAT Mean',
    ' Bwd IAT Std': 'Bwd IAT Std',
    ' Bwd IAT Max': 'Bwd IAT Max',
    ' Bwd IAT Min': 'Bwd IAT Min',
    ' Fwd PSH Flags': 'Fwd PSH Flags',
    ' Bwd PSH Flags': 'Bwd PSH Flags',
    ' Fwd URG Flags': 'Fwd URG Flags',
    ' Bwd URG Flags': 'Bwd URG Flags',
    ' Fwd Header Length': 'Fwd Header Length',
    ' Bwd Header Length': 'Bwd Header Length',
    ' Fwd Packets/s': 'Fwd Packets/s',
    ' Bwd Packets/s': 'Bwd Packets/s',
    ' Min Packet Length': 'Min Packet Length',
    ' Max Packet Length': 'Max Packet Length',
    ' Packet Length Mean': 'Packet Length Mean',
    ' Packet Length Std': 'Packet Length Std',
    ' Packet Length Variance': 'Packet Length Variance',
    ' FIN Flag Count': 'FIN Flag Count',
    ' SYN Flag Count': 'SYN Flag Count',
    ' RST Flag Count': 'RST Flag Count',
    ' PSH Flag Count': 'PSH Flag Count',
    ' ACK Flag Count': 'ACK Flag Count',
    ' URG Flag Count': 'URG Flag Count',
    ' CWE Flag Count': 'CWE Flag Count',
    ' ECE Flag Count': 'ECE Flag Count',
    ' Down/Up Ratio': 'Down/Up Ratio',
    ' Average Packet Size': 'Average Packet Size',
    ' Avg Fwd Segment Size': 'Avg Fwd Segment Size',
    ' Avg Bwd Segment Size': 'Avg Bwd Segment Size',
    ' Fwd Header Length.1': 'Fwd Header Length',
    ' Fwd Avg Bytes/Bulk': 'Fwd Avg Bytes/Bulk',
    ' Fwd Avg Packets/Bulk': 'Fwd Avg Packets/Bulk',
    ' Fwd Avg Bulk Rate': 'Fwd Avg Bulk Rate',
    ' Bwd Avg Bytes/Bulk': 'Bwd Avg Bytes/Bulk',
    ' Bwd Avg Packets/Bulk': 'Bwd Avg Packets/Bulk',
    ' Bwd Avg Bulk Rate': 'Bwd Avg Bulk Rate',
    ' Subflow Fwd Packets': 'Subflow Fwd Packets',
    ' Subflow Fwd Bytes': 'Subflow Fwd Bytes',
    ' Subflow Bwd Packets': 'Subflow Bwd Packets',
    ' Subflow Bwd Bytes': 'Subflow Bwd Bytes',
    ' Init_Win_bytes_forward': 'Init_Win_bytes_forward',
    ' Init_Win_bytes_backward': 'Init_Win_bytes_backward',
    ' act_data_pkt_fwd': 'act_data_pkt_fwd',
    ' min_seg_size_forward': 'min_seg_size_forward',
    ' Active Mean': 'Active Mean',
    ' Active Std': 'Active Std',
    ' Active Max': 'Active Max',
    ' Active Min': 'Active Min',
    ' Idle Mean': 'Idle Mean',
    ' Idle Std': 'Idle Std',
    ' Idle Max': 'Idle Max',
    ' Idle Min': 'Idle Min',
    ' Label': 'Label',
    'Label': 'Label'
}

# Features that match your captured JSON structure
CAPTURED_FEATURES = [
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
# DATA LOADING AND PREPROCESSING
# ============================================================================

def load_and_preprocess_data():
    """Load and preprocess all CICIDS2017 dataset files"""

    print("\n" + "=" * 80)
    print("LOADING AND PREPROCESSING DATA")
    print("=" * 80)

    all_data = []

    for filename in DATASET_FILES:
        filepath = os.path.join(DATASET_DIR, filename)

        if not os.path.exists(filepath):
            print(f"⚠️  WARNING: {filename} not found! Skipping...")
            continue

        print(f"\n📁 Loading {filename}...")

        try:
            # Load dataset
            df = pd.read_csv(filepath, encoding='utf-8', low_memory=False)
            print(f"   Raw shape: {df.shape}")

            # Standardize column names
            df.columns = df.columns.str.strip()
            df = df.rename(columns=COLUMN_MAPPING)

            # Check for Label column
            if 'Label' not in df.columns:
                print(f"   ⚠️  WARNING: No 'Label' column found in {filename}")
                continue

            # Remove duplicates
            before = len(df)
            df = df.drop_duplicates()
            after = len(df)
            print(f"   Removed {before - after} duplicates")

            # Handle missing values and infinite values
            df = df.replace([np.inf, -np.inf], np.nan)

            # Fill missing values with median for numeric columns
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            for col in numeric_cols:
                if df[col].isnull().any():
                    df[col].fillna(df[col].median(), inplace=True)

            print(f"   Processed shape: {df.shape}")
            print(f"   Labels: {df['Label'].value_counts().to_dict()}")

            all_data.append(df)

        except Exception as e:
            print(f"   ❌ ERROR loading {filename}: {str(e)}")
            continue

    if not all_data:
        raise ValueError("No data could be loaded! Please check dataset files.")

    # Combine all datasets
    print("\n🔄 Combining all datasets...")
    combined_df = pd.concat(all_data, ignore_index=True)
    print(f"   Combined shape: {combined_df.shape}")

    # Display label distribution
    print("\n📊 Label Distribution:")
    label_counts = combined_df['Label'].value_counts()
    for label, count in label_counts.items():
        print(f"   {label}: {count:,} ({count/len(combined_df)*100:.2f}%)")

    return combined_df

def prepare_features_and_labels(df):
    """Prepare features and labels for training"""

    print("\n" + "=" * 80)
    print("FEATURE ENGINEERING")
    print("=" * 80)

    # Remove rows with NaN labels
    print(f"\n🧹 Cleaning labels...")
    print(f"   Total samples before cleaning: {len(df):,}")
    df = df[df['Label'].notna()]
    print(f"   Total samples after removing NaN labels: {len(df):,}")

    # Separate features and labels
    X = df.drop(['Label'], axis=1, errors='ignore')
    y = df['Label']

    # Remove non-numeric columns (like IP addresses, timestamps, etc.)
    non_numeric_cols = X.select_dtypes(exclude=[np.number]).columns
    if len(non_numeric_cols) > 0:
        print(f"\n🗑️  Removing non-numeric columns: {list(non_numeric_cols)}")
        X = X.drop(columns=non_numeric_cols)

    # Keep only features that match captured JSON structure
    available_features = [f for f in CAPTURED_FEATURES if f in X.columns]
    missing_features = [f for f in CAPTURED_FEATURES if f not in X.columns]

    if missing_features:
        print(f"\n⚠️  Missing features (will use available features only):")
        for feat in missing_features[:10]:  # Show first 10
            print(f"   - {feat}")
        if len(missing_features) > 10:
            print(f"   ... and {len(missing_features) - 10} more")

    X = X[available_features]

    print(f"\n✅ Using {len(available_features)} features")
    print(f"   Total samples: {len(X):,}")

    # Handle any remaining NaN or Inf values
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    # Encode labels
    print("\n🏷️  Encoding labels...")
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    print(f"   Number of classes: {len(label_encoder.classes_)}")
    print(f"   Classes: {list(label_encoder.classes_)}")

    return X, y_encoded, label_encoder, available_features

def balance_dataset(X, y, label_encoder, min_samples_threshold=500):
    """
    IMPROVED: Balance the dataset using MUCH BETTER sampling strategy

    Changes from original:
    1. Increased min_samples_threshold from 100 to 500
    2. Use MEDIAN of all class counts instead of minimum (gets more data!)
    3. Removed 80% multiplier - use full median value
    4. Cap at 100,000 instead of 50,000
    """

    print("\n" + "=" * 80)
    print("BALANCING DATASET (IMPROVED STRATEGY)")
    print("=" * 80)

    unique_classes, class_counts = np.unique(y, return_counts=True)

    print(f"\n📊 Before balancing:")
    for cls, count in zip(unique_classes, class_counts):
        class_name = label_encoder.classes_[cls]
        print(f"   Class {cls} ({class_name}): {count:,} samples")

    # Remove classes with too few samples
    print(f"\n🔍 Filtering classes with at least {min_samples_threshold} samples...")
    valid_classes = unique_classes[class_counts >= min_samples_threshold]
    valid_class_counts = class_counts[class_counts >= min_samples_threshold]

    if len(valid_classes) == 0:
        raise ValueError(f"No classes have at least {min_samples_threshold} samples!")

    print(f"   Kept {len(valid_classes)} classes out of {len(unique_classes)}")

    # IMPROVED: Use MEDIAN instead of minimum for better sampling
    # This gives us much more data per class!
    median_samples = int(np.median(valid_class_counts))

    # Cap at 100,000 but use median value (no 80% multiplier!)
    target_samples = min(median_samples, 100000)
    target_samples = max(target_samples, min_samples_threshold)

    print(f"\n🎯 IMPROVED Sampling Strategy:")
    print(f"   Median class count: {median_samples:,}")
    print(f"   Target samples per class: {target_samples:,}")
    print(f"   This is MUCH BETTER than the old 326 samples!")

    # Balance by sampling
    balanced_indices = []

    for cls in valid_classes:
        cls_indices = np.where(y == cls)[0]

        if len(cls_indices) >= target_samples:
            # Undersample
            selected_indices = np.random.choice(cls_indices, target_samples, replace=False)
        else:
            # Keep all samples
            selected_indices = cls_indices

        balanced_indices.extend(selected_indices)

    balanced_indices = np.array(balanced_indices)
    np.random.shuffle(balanced_indices)

    X_balanced = X.iloc[balanced_indices].reset_index(drop=True)
    y_balanced_old = y[balanced_indices]

    # Re-encode labels to have contiguous indices
    old_to_new = {old_cls: new_cls for new_cls, old_cls in enumerate(valid_classes)}
    y_balanced = np.array([old_to_new[old_cls] for old_cls in y_balanced_old])

    # Create new label encoder with only the valid classes
    new_label_encoder = LabelEncoder()
    new_label_encoder.classes_ = label_encoder.classes_[valid_classes]

    print(f"\n📊 After balancing:")
    unique_classes_after, class_counts_after = np.unique(y_balanced, return_counts=True)
    for new_cls, count in zip(unique_classes_after, class_counts_after):
        class_name = new_label_encoder.classes_[new_cls]
        print(f"   Class {new_cls} ({class_name}): {count:,} samples")

    print(f"\n✅ Total balanced samples: {len(X_balanced):,}")
    print(f"✅ Number of classes: {len(unique_classes_after)}")
    print(f"✨ Average samples per class: {len(X_balanced) // len(unique_classes_after):,}")

    return X_balanced, y_balanced, new_label_encoder

# ============================================================================
# MODEL ARCHITECTURE
# ============================================================================

def create_model(input_dim, num_classes):
    """Create deep learning model for intrusion detection"""

    print("\n" + "=" * 80)
    print("BUILDING MODEL ARCHITECTURE")
    print("=" * 80)

    model = keras.Sequential([
        # Input layer
        layers.Input(shape=(input_dim,)),

        # First hidden layer
        layers.Dense(256, activation='relu', kernel_regularizer=keras.regularizers.l2(0.001)),
        layers.BatchNormalization(),
        layers.Dropout(DROPOUT_RATE),

        # Second hidden layer
        layers.Dense(128, activation='relu', kernel_regularizer=keras.regularizers.l2(0.001)),
        layers.BatchNormalization(),
        layers.Dropout(DROPOUT_RATE),

        # Third hidden layer
        layers.Dense(64, activation='relu', kernel_regularizer=keras.regularizers.l2(0.001)),
        layers.BatchNormalization(),
        layers.Dropout(DROPOUT_RATE),

        # Fourth hidden layer
        layers.Dense(32, activation='relu', kernel_regularizer=keras.regularizers.l2(0.001)),
        layers.BatchNormalization(),
        layers.Dropout(DROPOUT_RATE / 2),

        # Output layer
        layers.Dense(num_classes, activation='softmax')
    ])

    # Compile model
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=LEARNING_RATE),
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )

    print("\n📋 Model Summary:")
    model.summary()

    return model

# ============================================================================
# TRAINING
# ============================================================================

def train_model(model, X_train, y_train, X_val, y_val):
    """Train the model with IMPROVED callbacks"""

    print("\n" + "=" * 80)
    print("TRAINING MODEL (IMPROVED)")
    print("=" * 80)

    # Create timestamp for model versioning
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_name = f"cyberhawk_ids_model_{timestamp}"

    # Define callbacks
    checkpoint_path = os.path.join(MODEL_DIR, f"{model_name}_best.keras")

    callbacks = [
        ModelCheckpoint(
            checkpoint_path,
            monitor='val_accuracy',
            save_best_only=True,
            mode='max',
            verbose=1
        ),
        # IMPROVED: Increased patience from 10 to 15
        EarlyStopping(
            monitor='val_loss',
            patience=15,  # Wait longer before stopping
            restore_best_weights=True,
            verbose=1
        ),
        ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.5,
            patience=5,
            min_lr=1e-7,
            verbose=1
        )
    ]

    print(f"\n🚀 Starting training for UP TO {EPOCHS} epochs...")
    print(f"   ✨ Early stopping will kick in if overfitting detected")
    print(f"   ✨ Patience set to 15 epochs (instead of 10)")
    print(f"   Training samples: {len(X_train):,}")
    print(f"   Validation samples: {len(X_val):,}")
    print(f"   Batch size: {BATCH_SIZE}")

    # Train model
    history = model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        callbacks=callbacks,
        verbose=1
    )

    print(f"\n✅ Training completed!")
    print(f"   Best model saved to: {checkpoint_path}")
    print(f"   Actual epochs trained: {len(history.history['loss'])}")

    return model, history, model_name

# ============================================================================
# EVALUATION
# ============================================================================

def evaluate_model(model, X_test, y_test, label_encoder, model_name):
    """Evaluate model and generate reports"""

    print("\n" + "=" * 80)
    print("MODEL EVALUATION")
    print("=" * 80)

    # Make predictions
    print("\n🔮 Making predictions on test set...")
    y_pred_probs = model.predict(X_test, batch_size=BATCH_SIZE, verbose=1)
    y_pred = np.argmax(y_pred_probs, axis=1)

    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision, recall, f1, support = precision_recall_fscore_support(
        y_test, y_pred, average='weighted'
    )

    print(f"\n📊 Overall Metrics:")
    print(f"   Accuracy:  {accuracy:.4f}")
    print(f"   Precision: {precision:.4f}")
    print(f"   Recall:    {recall:.4f}")
    print(f"   F1-Score:  {f1:.4f}")

    # Generate classification report
    print("\n" + "=" * 80)
    print("CLASSIFICATION REPORT")
    print("=" * 80)

    class_names = label_encoder.classes_
    report = classification_report(
        y_test, y_pred,
        target_names=class_names,
        digits=4
    )
    print(report)

    # Save classification report
    report_path = os.path.join(MODEL_DIR, f"{model_name}_classification_report.txt")
    with open(report_path, 'w') as f:
        f.write("CyberHawk IDS - Classification Report\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Overall Metrics:\n")
        f.write(f"  Accuracy:  {accuracy:.4f}\n")
        f.write(f"  Precision: {precision:.4f}\n")
        f.write(f"  Recall:    {recall:.4f}\n")
        f.write(f"  F1-Score:  {f1:.4f}\n\n")
        f.write(report)

    print(f"\n💾 Classification report saved to: {report_path}")

    # Generate confusion matrix
    print("\n📈 Generating confusion matrix...")
    cm = confusion_matrix(y_test, y_pred)

    # Plot confusion matrix
    plt.figure(figsize=(12, 10))
    sns.heatmap(
        cm,
        annot=True,
        fmt='d',
        cmap='Blues',
        xticklabels=class_names,
        yticklabels=class_names,
        cbar_kws={'label': 'Count'}
    )
    plt.title('Confusion Matrix - CyberHawk IDS', fontsize=16, fontweight='bold')
    plt.xlabel('Predicted Label', fontsize=12)
    plt.ylabel('True Label', fontsize=12)
    plt.xticks(rotation=45, ha='right')
    plt.yticks(rotation=0)
    plt.tight_layout()

    # Save confusion matrix
    cm_path = os.path.join(MODEL_DIR, f"{model_name}_confusion_matrix.png")
    plt.savefig(cm_path, dpi=300, bbox_inches='tight')
    print(f"💾 Confusion matrix saved to: {cm_path}")
    plt.close()

    # Generate per-class metrics
    print("\n" + "=" * 80)
    print("PER-CLASS METRICS")
    print("=" * 80)

    per_class_metrics = []
    for i, class_name in enumerate(class_names):
        class_precision = precision_recall_fscore_support(
            y_test, y_pred, labels=[i], average=None
        )

        metrics = {
            'Class': class_name,
            'Precision': float(class_precision[0][0]),
            'Recall': float(class_precision[1][0]),
            'F1-Score': float(class_precision[2][0]),
            'Support': int(class_precision[3][0])
        }
        per_class_metrics.append(metrics)

        print(f"\n{class_name}:")
        print(f"   Precision: {metrics['Precision']:.4f}")
        print(f"   Recall:    {metrics['Recall']:.4f}")
        print(f"   F1-Score:  {metrics['F1-Score']:.4f}")
        print(f"   Support:   {metrics['Support']}")

    return {
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1_score': float(f1),
        'confusion_matrix': cm.tolist(),
        'per_class_metrics': per_class_metrics
    }

def plot_training_history(history, model_name):
    """Plot training history"""

    print("\n📊 Generating training history plots...")

    fig, axes = plt.subplots(1, 2, figsize=(15, 5))

    # Accuracy plot
    axes[0].plot(history.history['accuracy'], label='Train Accuracy', linewidth=2)
    axes[0].plot(history.history['val_accuracy'], label='Val Accuracy', linewidth=2)
    axes[0].set_title('Model Accuracy', fontsize=14, fontweight='bold')
    axes[0].set_xlabel('Epoch')
    axes[0].set_ylabel('Accuracy')
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)

    # Loss plot
    axes[1].plot(history.history['loss'], label='Train Loss', linewidth=2)
    axes[1].plot(history.history['val_loss'], label='Val Loss', linewidth=2)
    axes[1].set_title('Model Loss', fontsize=14, fontweight='bold')
    axes[1].set_xlabel('Epoch')
    axes[1].set_ylabel('Loss')
    axes[1].legend()
    axes[1].grid(True, alpha=0.3)

    plt.suptitle('CyberHawk IDS - Training History', fontsize=16, fontweight='bold', y=1.02)
    plt.tight_layout()

    # Save plot
    history_path = os.path.join(MODEL_DIR, f"{model_name}_training_history.png")
    plt.savefig(history_path, dpi=300, bbox_inches='tight')
    print(f"💾 Training history saved to: {history_path}")
    plt.close()

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution function"""

    start_time = datetime.now()
    print(f"\n⏰ Training started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        # Step 1: Load and preprocess data
        df = load_and_preprocess_data()

        # Step 2: Prepare features and labels
        X, y, label_encoder, feature_names = prepare_features_and_labels(df)

        # Step 3: Balance dataset - IMPROVED VERSION
        X_balanced, y_balanced, label_encoder = balance_dataset(X, y, label_encoder)

        # Step 4: Split data
        print("\n" + "=" * 80)
        print("SPLITTING DATA")
        print("=" * 80)

        # Check if we have enough samples
        num_classes = len(np.unique(y_balanced))
        min_samples_needed = num_classes * 10

        if len(X_balanced) < min_samples_needed:
            raise ValueError(
                f"Insufficient samples for training! "
                f"Have {len(X_balanced)} samples but need at least {min_samples_needed} "
                f"({num_classes} classes × 10 samples/class)"
            )

        print(f"\n✅ Dataset size check passed")
        print(f"   Total samples: {len(X_balanced):,}")
        print(f"   Number of classes: {num_classes}")
        print(f"   Minimum needed: {min_samples_needed}")

        X_temp, X_test, y_temp, y_test = train_test_split(
            X_balanced, y_balanced,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=y_balanced
        )

        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp,
            test_size=VALIDATION_SPLIT,
            random_state=RANDOM_STATE,
            stratify=y_temp
        )

        print(f"\n✅ Data split completed:")
        print(f"   Training set:   {len(X_train):,} samples")
        print(f"   Validation set: {len(X_val):,} samples")
        print(f"   Test set:       {len(X_test):,} samples")

        # Step 5: Standardize features
        print("\n" + "=" * 80)
        print("STANDARDIZING FEATURES")
        print("=" * 80)

        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_val_scaled = scaler.transform(X_val)
        X_test_scaled = scaler.transform(X_test)

        print("✅ Features standardized using StandardScaler")

        # Save scaler
        import joblib
        scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")
        joblib.dump(scaler, scaler_path)
        print(f"💾 Scaler saved to: {scaler_path}")

        # Save feature names
        feature_path = os.path.join(MODEL_DIR, "feature_names.json")
        with open(feature_path, 'w') as f:
            json.dump(feature_names, f, indent=2)
        print(f"💾 Feature names saved to: {feature_path}")

        # Save label encoder
        label_encoder_path = os.path.join(MODEL_DIR, "label_encoder.pkl")
        joblib.dump(label_encoder, label_encoder_path)
        print(f"💾 Label encoder saved to: {label_encoder_path}")

        # Step 6: Create model
        num_features = X_train_scaled.shape[1]
        num_classes = len(np.unique(y_train))

        model = create_model(num_features, num_classes)

        # Step 7: Train model - IMPROVED VERSION
        model, history, model_name = train_model(
            model, X_train_scaled, y_train, X_val_scaled, y_val
        )

        # Step 8: Plot training history
        plot_training_history(history, model_name)

        # Step 9: Evaluate model
        metrics = evaluate_model(model, X_test_scaled, y_test, label_encoder, model_name)

        # Step 10: Save final model
        final_model_path = os.path.join(MODEL_DIR, f"{model_name}_final.keras")
        model.save(final_model_path)
        print(f"\n💾 Final model saved to: {final_model_path}")

        # Save metrics as JSON
        metrics_path = os.path.join(MODEL_DIR, f"{model_name}_metrics.json")
        with open(metrics_path, 'w') as f:
            json.dump(metrics, f, indent=2)
        print(f"💾 Metrics saved to: {metrics_path}")

        # Save training configuration
        config = {
            'epochs': EPOCHS,
            'actual_epochs_trained': len(history.history['loss']),
            'batch_size': BATCH_SIZE,
            'learning_rate': LEARNING_RATE,
            'dropout_rate': DROPOUT_RATE,
            'num_features': num_features,
            'num_classes': num_classes,
            'class_names': label_encoder.classes_.tolist(),
            'feature_names': feature_names,
            'train_samples': len(X_train),
            'val_samples': len(X_val),
            'test_samples': len(X_test),
            'training_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'improvements': [
                'Increased epochs from 50 to 200',
                'Improved sampling strategy (median instead of minimum)',
                'Increased early stopping patience from 10 to 15',
                'More samples per class for better training'
            ]
        }

        config_path = os.path.join(MODEL_DIR, f"{model_name}_config.json")
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"💾 Configuration saved to: {config_path}")

        # Calculate training time
        end_time = datetime.now()
        duration = end_time - start_time

        print("\n" + "=" * 80)
        print("TRAINING COMPLETED SUCCESSFULLY!")
        print("=" * 80)
        print(f"\n⏰ Training duration: {duration}")
        print(f"📁 All outputs saved to: {MODEL_DIR}")
        print(f"\n🎯 Final Test Accuracy: {metrics['accuracy']:.4f}")
        print(f"📊 Final Test F1-Score: {metrics['f1_score']:.4f}")

        print("\n" + "=" * 80)
        print("✨ IMPROVEMENTS IN THIS RUN:")
        print("=" * 80)
        for improvement in config['improvements']:
            print(f"   ✓ {improvement}")

        print("\n" + "=" * 80)
        print("Files Generated:")
        print("=" * 80)
        print(f"1. Best Model: {model_name}_best.keras")
        print(f"2. Final Model: {model_name}_final.keras")
        print(f"3. Scaler: scaler.pkl")
        print(f"4. Label Encoder: label_encoder.pkl")
        print(f"5. Feature Names: feature_names.json")
        print(f"6. Classification Report: {model_name}_classification_report.txt")
        print(f"7. Confusion Matrix: {model_name}_confusion_matrix.png")
        print(f"8. Training History: {model_name}_training_history.png")
        print(f"9. Metrics: {model_name}_metrics.json")
        print(f"10. Configuration: {model_name}_config.json")

        print("\n" + "=" * 80)
        print("Thank you for using CyberHawk IDS Training Script!")
        print("=" * 80)

    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    main()