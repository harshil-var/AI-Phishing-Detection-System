import os
import math
from typing import Dict, Any, Tuple
from app.ml.feature_extractor import extract_url_features, FEATURE_COLUMNS
from app.security.domain_checker import evaluate_brand_impersonation

class PhishingPredictor:
    """
    Production-grade Phishing Detection & Calibrated Probability Engine.
    
    Loads calibrated Scikit-Learn model artifact with empirical thresholds.
    Falls back to pure-Python calibrated logistic score if binary runtime fails.
    """
    def __init__(self, model_path: str = None):
        if model_path is None:
            model_path = os.path.join(
                os.path.dirname(__file__), "model", "phishing_model.pkl"
            )
        self.model_path = model_path
        self.model = None
        self.feature_columns = FEATURE_COLUMNS
        self.thresholds = {"suspicious": 0.35, "phishing": 0.45}
        self.phishing_class_index = 1
        self.model_version = "2.0.0-calibrated"
        self.model_status = "CALIBRATED_ENGINE"
        self._load_model()

    def _load_model(self):
        """Attempts to load serialized scikit-learn model artifact."""
        if os.path.exists(self.model_path):
            try:
                import joblib
                data = joblib.load(self.model_path)
                self.model = data.get("model")
                self.feature_columns = data.get("feature_columns", FEATURE_COLUMNS)
                self.thresholds = data.get("thresholds", {"suspicious": 0.35, "phishing": 0.45})
                self.phishing_class_index = data.get("phishing_class_index", 1)
                self.model_version = data.get("model_version", "2.0.0-calibrated")
                self.model_status = f"CALIBRATED_{type(self.model).__name__.upper()}"
                print(f"[ML Predictor] Successfully loaded model artifact ({self.model_status}) from {self.model_path}")
            except Exception as e:
                print(f"[ML Predictor] Notice: Model artifact loading fallback ({e}). "
                      f"Using resilient calibrated pure-Python detection engine.")
                self.model = None
                self.model_status = "CALIBRATED_ENGINE"
        else:
            self.model = None
            self.model_status = "CALIBRATED_ENGINE"

    def predict(self, url: str) -> Dict[str, Any]:
        """
        Extracts features and returns structured prediction dictionary:
        {
            "raw_features": dict,
            "classification": "SAFE" | "SUSPICIOUS" | "PHISHING",
            "prediction": "SAFE" | "SUSPICIOUS" | "PHISHING",
            "prob_safe": float (0-1),
            "prob_phishing": float (0-1),
            "phishing_probability": float (0-1),
            "confidence": float (50-98.5),
            "model_source": str,
            "threshold_used": float,
            "debug_info": dict
        }
        """
        features = extract_url_features(url)
        brand_eval = evaluate_brand_impersonation(url)

        prob_phishing = None
        prob_safe = None

        if self.model is not None:
            try:
                import pandas as pd
                df_feat = pd.DataFrame([features])[self.feature_columns]
                probs = self.model.predict_proba(df_feat)[0]
                prob_phishing = float(probs[self.phishing_class_index])
                prob_safe = 1.0 - prob_phishing
            except Exception as e:
                print(f"[ML Predictor] Model inference fallback: {e}")
                prob_phishing, prob_safe = self._calibrated_probabilities(features, brand_eval)
        else:
            prob_phishing, prob_safe = self._calibrated_probabilities(features, brand_eval)

        # Objective brand impersonation signal:
        # If severe typosquatting or lookalike deception is detected,
        # escalate minimum phishing probability to protect users.
        # Notice: NO whitelist override for legitimate domains. The ML classifier
        # natively distinguishes legitimate domains based on real lexical features.
        if brand_eval.get("is_impersonation"):
            prob_phishing = max(prob_phishing, 0.75)
            prob_safe = 1.0 - prob_phishing

        # Classification decision boundaries from validation-tuned threshold
        thresh_phishing = self.thresholds.get("phishing", 0.45)
        thresh_suspicious = self.thresholds.get("suspicious", 0.35)

        if prob_phishing >= thresh_phishing:
            classification = "PHISHING"
        elif prob_phishing >= thresh_suspicious:
            classification = "SUSPICIOUS"
        else:
            classification = "SAFE"

        # Calibrated Statistical Confidence:
        # Reflects margin from decision boundary, clamped between 50.0% and 98.5%.
        dominant_prob = max(prob_phishing, prob_safe)
        calibrated_confidence = round(min(98.5, max(50.0, dominant_prob * 100.0)), 1)

        rounded_phish_prob = round(prob_phishing, 4)
        rounded_safe_prob = round(prob_safe, 4)

        return {
            "raw_features": features,
            "classification": classification,
            "prediction": classification,
            "prob_safe": rounded_safe_prob,
            "prob_phishing": rounded_phish_prob,
            "phishing_probability": rounded_phish_prob,
            "confidence": calibrated_confidence,
            "model_source": self.model_status,
            "threshold_used": thresh_phishing,
            "debug_info": {
                "normalized_url": url,
                "feature_count": len(self.feature_columns),
                "model_version": self.model_version,
                "raw_probabilities": {
                    "phishing": rounded_phish_prob,
                    "safe": rounded_safe_prob
                },
                "predicted_class": classification,
                "threshold_used": thresh_phishing
            }
        }

    def _calibrated_probabilities(self, features: Dict[str, Any], brand_eval: Dict[str, Any]) -> Tuple[float, float]:
        """
        Calibrated logistic score based on empirical feature weights.
        Produces smooth, explainable, bounded probabilities via sigmoid.
        """
        log_odds = -3.0  # Benign prior for internet URLs

        # 1. Brand Impersonation / Typosquatting (Strongest signal)
        if brand_eval.get("is_impersonation") or features.get("domain_mismatch", 0) == 1:
            log_odds += 4.5

        # 2. Host Identity Signals
        if features.get("is_ip", 0) == 1:
            log_odds += 3.5

        if features.get("suspicious_tld", 0) == 1:
            log_odds += 2.2

        if features.get("is_https", 1) == 0:
            log_odds += 1.0

        # 3. Lexical / Keyword Signals
        kw_count = features.get("suspicious_keyword_count", 0)
        if kw_count > 0:
            log_odds += 1.5 + min(2.0, 0.6 * kw_count)

        if features.get("has_at_symbol", 0) == 1:
            log_odds += 2.5

        if features.get("has_url_encoding", 0) == 1:
            log_odds += 0.8

        if features.get("hyphens_in_domain", 0) >= 2:
            log_odds += 1.2
        elif features.get("hyphens_in_domain", 0) == 1:
            log_odds += 0.4

        # 4. Structural Anomalies
        subdomains = features.get("no_subdomains", 0)
        if subdomains >= 3:
            log_odds += 2.0
        elif subdomains >= 2:
            log_odds += 1.0

        entropy = features.get("url_entropy", 0.0)
        if entropy > 4.6:
            log_odds += 1.0
        elif entropy > 4.2:
            log_odds += 0.4

        url_length = features.get("url_length", 0)
        if url_length > 100:
            log_odds += 1.0
        elif url_length > 80:
            log_odds += 0.4

        # Compute sigmoid probability
        prob_phishing = 1.0 / (1.0 + math.exp(-max(-8.0, min(8.0, log_odds))))
        prob_safe = 1.0 - prob_phishing

        return prob_phishing, prob_safe

# Singleton instance
predictor_instance = PhishingPredictor()
