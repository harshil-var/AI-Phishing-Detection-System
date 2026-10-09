import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.ml.feature_extractor import extract_url_features, FEATURE_COLUMNS

def test_extract_url_features_structure():
    url = "https://www.security-update.com/paypal/login?user=admin"
    features = extract_url_features(url)
    
    for col in FEATURE_COLUMNS:
        assert col in features, f"Missing feature column: {col}"
    
    assert features["is_https"] == 1
    assert features["has_suspicious_keyword"] == 1
    assert features["domain_mismatch"] == 1
    assert features["no_dots"] >= 2

def test_ip_address_detection():
    ip_url = "http://192.168.1.1/login"
    features = extract_url_features(ip_url)
    assert features["is_ip"] == 1
    assert features["is_https"] == 0
