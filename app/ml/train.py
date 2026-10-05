"""
ML Training Module

Generates synthetic labeled training data and trains Random Forest classifier
for threat detection.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import pickle
from pathlib import Path
from typing import Dict, Tuple
from app.ml.features import FeatureEngineer


class ThreatClassifierTrainer:
    """Trains ML model for network threat classification."""

    def __init__(self):
        self.model = None
        self.feature_names = None
        self.metrics = {}

    def generate_synthetic_training_data(self, n_samples: int = 1000) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Generate synthetic labeled training data.

        Labels:
        - 0: Normal traffic
        - 1: Suspicious/Anomalous traffic

        This is SYNTHETIC data for educational purposes.
        In production, use real labeled historical data.
        """
        np.random.seed(42)

        # Normal traffic patterns (70% of data)
        n_normal = int(n_samples * 0.7)
        normal_data = {
            'total_connections': np.random.randint(1, 50, n_normal),
            'denied_connections': np.random.randint(0, 5, n_normal),
            'deny_ratio': np.random.uniform(0, 0.2, n_normal),
            'unique_dst_ports': np.random.randint(1, 10, n_normal),
            'unique_dst_ips': np.random.randint(1, 10, n_normal),
            'port_diversity_ratio': np.random.uniform(0, 0.3, n_normal),
            'tcp_ratio': np.random.uniform(0.6, 1.0, n_normal),
            'udp_ratio': np.random.uniform(0, 0.4, n_normal),
            'connections_per_minute': np.random.uniform(0.1, 5, n_normal),
            'port_scan_score': np.random.uniform(0, 0.3, n_normal),
            'suspicious_port_ratio': np.random.uniform(0, 0.1, n_normal)
        }
        normal_labels = np.zeros(n_normal)

        # Suspicious traffic patterns (30% of data)
        n_suspicious = n_samples - n_normal

        # Port scanning patterns
        n_port_scan = n_suspicious // 3
        port_scan_data = {
            'total_connections': np.random.randint(30, 200, n_port_scan),
            'denied_connections': np.random.randint(20, 180, n_port_scan),
            'deny_ratio': np.random.uniform(0.6, 1.0, n_port_scan),
            'unique_dst_ports': np.random.randint(20, 100, n_port_scan),
            'unique_dst_ips': np.random.randint(1, 5, n_port_scan),
            'port_diversity_ratio': np.random.uniform(0.5, 1.0, n_port_scan),
            'tcp_ratio': np.random.uniform(0.8, 1.0, n_port_scan),
            'udp_ratio': np.random.uniform(0, 0.2, n_port_scan),
            'connections_per_minute': np.random.uniform(5, 30, n_port_scan),
            'port_scan_score': np.random.uniform(0.5, 1.0, n_port_scan),
            'suspicious_port_ratio': np.random.uniform(0.2, 0.8, n_port_scan)
        }

        # Brute force patterns
        n_brute_force = n_suspicious // 3
        brute_force_data = {
            'total_connections': np.random.randint(50, 300, n_brute_force),
            'denied_connections': np.random.randint(40, 280, n_brute_force),
            'deny_ratio': np.random.uniform(0.8, 1.0, n_brute_force),
            'unique_dst_ports': np.random.randint(1, 3, n_brute_force),
            'unique_dst_ips': np.random.randint(1, 2, n_brute_force),
            'port_diversity_ratio': np.random.uniform(0, 0.1, n_brute_force),
            'tcp_ratio': np.random.uniform(0.9, 1.0, n_brute_force),
            'udp_ratio': np.random.uniform(0, 0.1, n_brute_force),
            'connections_per_minute': np.random.uniform(10, 50, n_brute_force),
            'port_scan_score': np.random.uniform(0, 0.2, n_brute_force),
            'suspicious_port_ratio': np.random.uniform(0.5, 1.0, n_brute_force)
        }

        # High frequency anomalies
        n_high_freq = n_suspicious - n_port_scan - n_brute_force
        high_freq_data = {
            'total_connections': np.random.randint(100, 500, n_high_freq),
            'denied_connections': np.random.randint(10, 100, n_high_freq),
            'deny_ratio': np.random.uniform(0.1, 0.5, n_high_freq),
            'unique_dst_ports': np.random.randint(5, 30, n_high_freq),
            'unique_dst_ips': np.random.randint(3, 20, n_high_freq),
            'port_diversity_ratio': np.random.uniform(0.1, 0.4, n_high_freq),
            'tcp_ratio': np.random.uniform(0.6, 1.0, n_high_freq),
            'udp_ratio': np.random.uniform(0, 0.4, n_high_freq),
            'connections_per_minute': np.random.uniform(20, 80, n_high_freq),
            'port_scan_score': np.random.uniform(0.2, 0.6, n_high_freq),
            'suspicious_port_ratio': np.random.uniform(0.1, 0.4, n_high_freq)
        }

        suspicious_labels = np.ones(n_suspicious)

        # Combine all data
        all_data = {}
        for key in normal_data.keys():
            all_data[key] = np.concatenate([
                normal_data[key],
                port_scan_data[key],
                brute_force_data[key],
                high_freq_data[key]
            ])

        X = pd.DataFrame(all_data)
        y = pd.Series(np.concatenate([normal_labels, suspicious_labels]))

        return X, y

    def train(self, X: pd.DataFrame, y: pd.Series, test_size: float = 0.3) -> Dict:
        """
        Train Random Forest classifier.

        Returns training metrics.
        """
        self.feature_names = list(X.columns)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        # Train Random Forest
        # Using Random Forest because:
        # - Handles mixed feature types well
        # - Provides feature importance
        # - Robust to overfitting
        # - Works well with imbalanced data
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )

        self.model.fit(X_train, y_train)

        # Evaluate
        y_pred = self.model.predict(X_test)
        y_pred_train = self.model.predict(X_train)

        # Calculate metrics
        self.metrics = {
            'train_accuracy': accuracy_score(y_train, y_pred_train),
            'test_accuracy': accuracy_score(y_test, y_pred),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'classification_report': classification_report(y_test, y_pred, output_dict=True),
            'feature_importance': dict(zip(self.feature_names, self.model.feature_importances_))
        }

        return self.metrics

    def save_model(self, model_path: str = "models/threat_classifier.pkl"):
        """Save trained model to disk."""
        if self.model is None:
            raise ValueError("No model trained yet. Call train() first.")

        model_dir = Path(model_path).parent
        model_dir.mkdir(parents=True, exist_ok=True)

        with open(model_path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'feature_names': self.feature_names,
                'metrics': self.metrics
            }, f)

    def load_model(self, model_path: str = "models/threat_classifier.pkl"):
        """Load trained model from disk."""
        with open(model_path, 'rb') as f:
            data = pickle.load(f)
            self.model = data['model']
            self.feature_names = data['feature_names']
            self.metrics = data.get('metrics', {})

    def get_metrics(self) -> Dict:
        """Return training metrics."""
        return self.metrics
