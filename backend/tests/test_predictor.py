import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.ml.predictor import PhishingPredictor

def test_predictor_execution():
    predictor = PhishingPredictor()
    res = predictor.predict("https://google.com")
    
    assert "classification" in res
    assert res["classification"] in ["SAFE", "SUSPICIOUS", "PHISHING"]
    assert "confidence" in res
    assert 0 <= res["confidence"] <= 100

def test_predictor_phishing_detection():
    predictor = PhishingPredictor()
    res = predictor.predict("http://192.168.1.1/paypal-verify-account-update-login")
    
    assert res["classification"] in ["SUSPICIOUS", "PHISHING"]
    assert res["prob_phishing"] > 0.5
