import os
import joblib
import pandas as pd
from typing import Dict, Any
from app.ml.feature_extractor import extract_url_features, FEATURE_COLUMNS

class PhishingPredictor:
    def __init__(self, model_path: str = None):
        if model_path is None:
            model_path = os.path.join(
                os.path.dirname(__file__), "model", "phishing_model.pkl"
            )
        self.model_path = model_path
        self.model = None
        self.feature_columns = FEATURE_COLUMNS
        self._load_model()

    def _load_model(self):
        """Loads trained model artifact if present."""
        if os.path.exists(self.model_path):
            try:
                data = joblib.load(self.model_path)
                self.model = data.get("model")
                self.feature_columns = data.get("feature_columns", FEATURE_COLUMNS)
                print(f"[ML Predictor] Successfully loaded model from {self.model_path}")
            except Exception as e:
                print(f"[ML Predictor] Error loading model file: {e}")
                self.model = None
        else:
            print(f"[ML Predictor] Model file not found at {self.model_path}. Using fallback rule predictor.")

    def predict(self, url: str) -> Dict[str, Any]:
        """
        Extracts features and returns ML prediction dictionary:
        {
            "raw_features": dict,
            "classification": "SAFE" | "SUSPICIOUS" | "PHISHING",
            "prob_safe": float (0-1),
            "prob_phishing": float (0-1),
            "confidence": float (0-100)
        }
        """
        features = extract_url_features(url)

        if self.model is not None:
            try:
                df_feat = pd.DataFrame([features])[self.feature_columns]
                probs = self.model.predict_proba(df_feat)[0]
                # Label mapping: 0 = PHISHING, 1 = SAFE
                prob_phishing = float(probs[0])
                prob_safe = float(probs[1])
            except Exception as e:
                print(f"[ML Predictor] Model inference error: {e}. Falling back to heuristic.")
                prob_phishing, prob_safe = self._heuristic_probabilities(features)
        else:
            prob_phishing, prob_safe = self._heuristic_probabilities(features)

        # Classification threshold mapping
        if prob_phishing >= 0.65:
            classification = "PHISHING"
            confidence = prob_phishing * 100
        elif prob_phishing >= 0.35:
            classification = "SUSPICIOUS"
            confidence = (0.5 + abs(prob_phishing - 0.5)) * 100
        else:
            classification = "SAFE"
            confidence = prob_safe * 100

        return {
            "raw_features": features,
            "classification": classification,
            "prob_safe": round(prob_safe, 4),
            "prob_phishing": round(prob_phishing, 4),
            "confidence": round(confidence, 1)
        }

    def _heuristic_probabilities(self, features: Dict[str, Any]) -> tuple:
        """Fallback rule-based probability estimator."""
        score = 0
        if features["is_https"] == 0:
            score += 25
        if features["is_ip"] == 1:
            score += 35
        if features["has_suspicious_keyword"]:
            score += 20 * features["suspicious_keyword_count"]
        if features["suspicious_tld"]:
            score += 25
        if features["domain_mismatch"]:
            score += 30
        if features["no_subdomains"] >= 3:
            score += 20
        if features["url_entropy"] > 4.5:
            score += 15

        prob_phishing = min(1.0, score / 100.0)
        prob_safe = 1.0 - prob_phishing
        return prob_phishing, prob_safe

# Singleton instance
predictor_instance = PhishingPredictor()
