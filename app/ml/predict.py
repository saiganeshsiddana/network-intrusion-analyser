"""
ML Prediction Engine

Uses trained model to predict threat probability for new network logs.
"""

import pandas as pd
import numpy as np
import pickle
from pathlib import Path
from typing import Dict, List, Tuple
from app.ml.features import FeatureEngineer


class ThreatPredictor:
    """Predicts threat probability for source IPs using trained ML model."""

    def __init__(self, model_path: str = "models/threat_classifier.pkl"):
        self.model_path = Path(model_path)
        self.model = None
        self.feature_names = None
        self.metrics = {}
        self.load_model()

    def load_model(self):
        """Load model from file."""
        if not self.model_path.exists():
            # Automatically train a default model if it doesn't exist
            print("Model file not found. Training default model...")
            from app.ml.train import ThreatClassifierTrainer
            trainer = ThreatClassifierTrainer()
            X, y = trainer.generate_synthetic_training_data()
            trainer.train(X, y)
            trainer.save_model(str(self.model_path))

        with open(self.model_path, 'rb') as f:
            data = pickle.load(f)
            self.model = data['model']
            self.feature_names = data['feature_names']
            self.metrics = data.get('metrics', {})

    def predict_source_ips(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Predict threat probability for all source IPs in events DataFrame.

        Returns DataFrame with source_ip, prediction, probability, and features.
        """
        if df.empty:
            return pd.DataFrame()

        # Extract features
        fe = FeatureEngineer(df)
        features_df = fe.extract_features_per_source()

        if features_df.empty:
            return pd.DataFrame()

        # Select only required feature columns
        X = features_df[self.feature_names]

        # Predict
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)[:, 1]  # Probability of class 1 (suspicious)

        # Combine results
        results = features_df.copy()
        results['ml_prediction'] = predictions
        results['ml_threat_probability'] = probabilities
        results['ml_confidence'] = np.where(predictions == 1, probabilities, 1 - probabilities)
        results['ml_label'] = np.where(predictions == 1, 'Suspicious', 'Normal')

        # Sort by threat probability (highest first)
        results = results.sort_values('ml_threat_probability', ascending=False)
        return results

    def predict_and_store(self, df: pd.DataFrame, database) -> pd.DataFrame:
        """Run inference and persist the current per-source ML findings."""
        results = self.predict_source_ips(df)
        database.replace_ml_predictions(results)
        return results

    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance dictionary."""
        if self.model is None or self.feature_names is None:
            return {}

        importances = self.model.feature_importances_
        return dict(zip(self.feature_names, importances))
