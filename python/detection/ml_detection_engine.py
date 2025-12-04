"""
MLDetectionEngine Class

Purpose: AI-powered threat detection using machine learning models.

This class wraps the existing ML model functionality from predict_realtime.py
"""

import os
import numpy as np
import joblib
from pathlib import Path


class MLDetectionEngine:
    """
    Machine Learning-based threat detection engine for network intrusion detection.

    Uses a trained neural network model to classify network flows and detect attacks.
    """

    def __init__(self, model_path=None):
        """
        Initialize MLDetectionEngine

        Args:
            model_path: Path to trained ML model file (.pkl or .h5)
        """
        self.model = None
        self.model_path = model_path or self._get_default_model_path()
        self.attack_labels = {
            0: 'BENIGN',
            1: 'DDoS',
            2: 'PortScan',
            3: 'Bot',
            4: 'Infiltration',
            5: 'Web Attack',
            6: 'Brute Force',
            7: 'DoS',
            8: 'Heartbleed'
        }

    def _get_default_model_path(self):
        """Get default model path"""
        current_dir = Path(__file__).resolve().parent
        project_root = current_dir.parent
        return project_root / "training" / "ids_model.pkl"

    def loadModel(self):
        """
        Loads trained neural network model.

        Loads the pre-trained TensorFlow/Keras model from disk for inference.

        Returns:
            dict: Status dictionary with success/error information
        """
        try:
            if not os.path.exists(self.model_path):
                return {
                    'success': False,
                    'message': f'Model file not found at {self.model_path}'
                }

            # Try loading with joblib (for sklearn models)
            try:
                self.model = joblib.load(self.model_path)
            except:
                # Try loading with tensorflow/keras
                import tensorflow as tf
                self.model = tf.keras.models.load_model(self.model_path)

            return {
                'success': True,
                'message': 'Model loaded successfully',
                'model_path': str(self.model_path)
            }

        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to load model: {str(e)}'
            }

    def predict(self, flow):
        """
        Predicts attack type from flow features.

        Args:
            flow: Flow object with extracted features

        Returns:
            str: Predicted attack type label
        """
        if self.model is None:
            result = self.loadModel()
            if not result['success']:
                return 'UNKNOWN'

        try:
            # Get features from flow
            if hasattr(flow, 'features') and flow.features:
                features = np.array(flow.features).reshape(1, -1)
            elif hasattr(flow, 'calculateFeatures'):
                features = np.array(flow.calculateFeatures()).reshape(1, -1)
            else:
                return 'INVALID_FLOW'

            # Make prediction
            prediction = self.model.predict(features)

            # Get predicted class
            if hasattr(prediction, 'shape') and len(prediction.shape) > 1:
                predicted_class = np.argmax(prediction, axis=1)[0]
            else:
                predicted_class = int(prediction[0])

            # Return attack label
            return self.attack_labels.get(predicted_class, 'UNKNOWN')

        except Exception as e:
            print(f"Prediction error: {str(e)}")
            return 'ERROR'

    def predictBatch(self, flows):
        """
        Predict attack types for multiple flows

        Args:
            flows: List of Flow objects

        Returns:
            list: List of predictions
        """
        predictions = []
        for flow in flows:
            prediction = self.predict(flow)
            predictions.append({
                'flow': flow.to_dict() if hasattr(flow, 'to_dict') else str(flow),
                'prediction': prediction
            })
        return predictions

    def filterFalsePositives(self, predictions, threshold=0.8):
        """
        Reduces false positive detections.

        Applies confidence thresholding and heuristics to filter out
        likely false positive alerts.

        Args:
            predictions: List of prediction dictionaries
            threshold: Confidence threshold (0.0 to 1.0)

        Returns:
            list: Filtered predictions
        """
        filtered = []

        for pred in predictions:
            # Skip benign predictions
            if pred.get('prediction') == 'BENIGN':
                continue

            # Apply confidence threshold if available
            confidence = pred.get('confidence', 1.0)
            if confidence < threshold:
                continue

            # Additional heuristics could go here
            # (e.g., check packet counts, flow duration, etc.)

            filtered.append(pred)

        return filtered

    def getModelInfo(self):
        """Get information about loaded model"""
        if self.model is None:
            return {'loaded': False}

        return {
            'loaded': True,
            'model_path': str(self.model_path),
            'model_type': type(self.model).__name__,
            'attack_labels': self.attack_labels
        }

    def evaluateFlow(self, flow, include_confidence=True):
        """
        Evaluate a flow and return detailed prediction

        Args:
            flow: Flow object
            include_confidence: Whether to include confidence scores

        Returns:
            dict: Detailed prediction with metadata
        """
        if self.model is None:
            self.loadModel()

        try:
            features = np.array(flow.calculateFeatures()).reshape(1, -1)
            prediction = self.model.predict(features)

            # Get class and confidence
            if hasattr(prediction, 'shape') and len(prediction.shape) > 1:
                predicted_class = np.argmax(prediction, axis=1)[0]
                confidence = float(np.max(prediction))
            else:
                predicted_class = int(prediction[0])
                confidence = 1.0

            attack_type = self.attack_labels.get(predicted_class, 'UNKNOWN')

            result = {
                'attack_type': attack_type,
                'is_attack': attack_type != 'BENIGN',
                'predicted_class': int(predicted_class),
                'src_ip': flow.srcIP,
                'dst_ip': flow.dstIP,
                'protocol': flow.protocol
            }

            if include_confidence:
                result['confidence'] = confidence

            return result

        except Exception as e:
            return {
                'attack_type': 'ERROR',
                'is_attack': False,
                'error': str(e)
            }
