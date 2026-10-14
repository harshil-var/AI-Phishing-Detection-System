import sys
import os
import pytest
from fastapi.testclient import TestClient

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.services.phishing_service import scan_url
from app.security.domain_checker import check_domain_security, evaluate_brand_impersonation
from app.ml.preprocessing import validate_url, is_ssrf_dangerous_host

client = TestClient(app)

# ==========================================
# Category A: Known Legitimate Domains
# ==========================================
def test_legitimate_google():
    res = scan_url("https://google.com")
    assert res["classification"] == "SAFE"
    assert res["risk_score"] <= 30
    assert res["confidence"] <= 98.5
    assert res["confidence"] >= 50.0
    assert res["security_checks"]["domain_mismatch"] is False
    assert res["security_checks"]["is_official_brand"] is True
    assert res["security_checks"]["brand_status"] == "OFFICIAL_BRAND"

def test_legitimate_flipkart():
    res = scan_url("https://www.flipkart.com")
    assert res["classification"] == "SAFE"
    assert res["risk_score"] <= 30
    assert res["security_checks"]["domain_mismatch"] is False
    assert res["security_checks"]["is_official_brand"] is True
    assert res["security_checks"]["brand_status"] == "OFFICIAL_BRAND"
    assert any("Verified official" in r for r in res["reasons"])

def test_legitimate_github():
    res = scan_url("https://github.com")
    assert res["classification"] == "SAFE"
    assert res["risk_score"] <= 30
    assert res["security_checks"]["domain_mismatch"] is False
    assert res["security_checks"]["is_official_brand"] is True

def test_legitimate_leetcode():
    res = scan_url("https://leetcode.com")
    assert res["classification"] == "SAFE"
    assert res["risk_score"] <= 30
    assert res["prob_phishing"] < 0.20
    assert res["security_checks"]["domain_mismatch"] is False

    res_www = scan_url("https://www.leetcode.com")
    assert res_www["classification"] == "SAFE"
    assert res_www["risk_score"] <= 30

def test_legitimate_youtube():
    res = scan_url("https://www.youtube.com")
    assert res["classification"] == "SAFE"
    assert res["risk_score"] <= 30
    assert res["prob_phishing"] < 0.20
    assert res["security_checks"]["domain_mismatch"] is False

    res_apex = scan_url("https://youtube.com")
    assert res_apex["classification"] == "SAFE"
    assert res_apex["risk_score"] <= 30

def test_legitimate_microsoft():
    res = scan_url("https://www.microsoft.com")
    assert res["classification"] == "SAFE"
    assert res["risk_score"] <= 30
    assert res["security_checks"]["domain_mismatch"] is False
    assert res["security_checks"]["is_official_brand"] is True

def test_verified_phishing_fixture():
    # Verified phishing entry from PhiUSIIL dataset
    res = scan_url("http://www.teramill.com")
    assert res["classification"] in ["SUSPICIOUS", "PHISHING"]
    assert res["risk_score"] >= 60

def test_excessive_subdomains():
    res = scan_url("http://a.b.c.d.suspicious-login.xyz/verify")
    assert res["classification"] in ["SUSPICIOUS", "PHISHING"]
    assert res["risk_score"] >= 70

def test_encoded_params_and_suspicious_payload():
    res = scan_url("http://secure-portal.com/login?token=%3Cscript%3E&user=test%40example.com")
    assert res["classification"] in ["SUSPICIOUS", "PHISHING"]
    assert res["risk_score"] >= 70

# ==========================================
# Category B: Potential Impersonation & Typosquatting
# ==========================================
def test_impersonation_f1ipkart():
    """
    CRITICAL BUG REGRESSION TEST:
    Verifies that https://f1ipkart.com is detected as typosquatting
    and NOT marked SAFE or VERIFIED MATCH.
    """
    res = scan_url("https://f1ipkart.com")
    assert res["classification"] in ["SUSPICIOUS", "PHISHING"]
    assert res["risk_score"] >= 60
    assert res["security_checks"]["domain_mismatch"] is True
    assert res["security_checks"]["is_official_brand"] is False
    assert res["security_checks"]["brand_status"] == "TYPOSQUATTING_DETECTED"
    assert res["security_checks"]["detected_brand"] == "flipkart"
    # Never unconditionally 100%
    assert res["confidence"] <= 98.5
    # Reasons must reflect the typosquatting
    assert any("f1ipkart" in r.lower() or "typosquatting" in r.lower() or "flipkart" in r.lower() for r in res["reasons"])

def test_subdomain_impersonation():
    res = scan_url("https://flipkart.example.com")
    assert res["classification"] in ["SUSPICIOUS", "PHISHING"]
    assert res["security_checks"]["domain_mismatch"] is True
    assert res["security_checks"]["brand_status"] == "SUBDOMAIN_IMPERSONATION"
    assert res["security_checks"]["detected_brand"] == "flipkart"

def test_compound_brand_impersonation():
    res = scan_url("https://flipkart-login.example.com")
    assert res["classification"] in ["SUSPICIOUS", "PHISHING"]
    assert res["security_checks"]["domain_mismatch"] is True
    assert res["security_checks"]["brand_status"] in ["SUBDOMAIN_IMPERSONATION", "COMPOUND_IMPERSONATION"]

def test_homoglyph_variations():
    eval_paypa1 = evaluate_brand_impersonation("https://paypa1.com")
    assert eval_paypa1["is_impersonation"] is True
    assert eval_paypa1["detected_brand"] == "paypal"

    eval_amaz0n = evaluate_brand_impersonation("https://amaz0n.com")
    assert eval_amaz0n["is_impersonation"] is True
    assert eval_amaz0n["detected_brand"] == "amazon"

# ==========================================
# Category C: Malformed & Deceptive Inputs (SSRF)
# ==========================================
def test_empty_and_whitespace_urls():
    r1 = client.post("/api/v1/scan", json={"url": ""})
    assert r1.status_code == 400

    r2 = client.post("/api/v1/scan", json={"url": "   "})
    assert r2.status_code == 400

def test_disallowed_schemes():
    r1 = client.post("/api/v1/scan", json={"url": "javascript:alert(document.cookie)"})
    assert r1.status_code == 400
    assert "disallowed" in r1.json()["detail"].lower()

    r2 = client.post("/api/v1/scan", json={"url": "data:text/html,<script>alert(1)</script>"})
    assert r2.status_code == 400

    r3 = client.post("/api/v1/scan", json={"url": "file:///etc/passwd"})
    assert r3.status_code == 400

def test_ssrf_defense_loopback_and_metadata():
    r1 = client.post("/api/v1/scan", json={"url": "http://localhost/admin"})
    assert r1.status_code == 400
    assert "restriction" in r1.json()["detail"].lower()

    r2 = client.post("/api/v1/scan", json={"url": "http://127.0.0.1:8000/api"})
    assert r2.status_code == 400

    r3 = client.post("/api/v1/scan", json={"url": "http://169.254.169.254/latest/meta-data"})
    assert r3.status_code == 400
    assert "metadata" in r3.json()["detail"].lower()

def test_url_with_credentials_and_obfuscation():
    res = scan_url("https://user:password@malicious-portal.com/login")
    assert res["security_checks"]["https"] is True
    assert res["reasons"] is not None

def test_raw_ip_address_host():
    res = scan_url("http://93.184.216.34/verify-account")
    assert res["security_checks"]["ip_address"] is True
    assert res["classification"] in ["SUSPICIOUS", "PHISHING"]
    assert res["risk_score"] > 35

# ==========================================
# Category D: Response Consistency & Calibrated Metrics
# ==========================================
def test_response_fields_and_ranges():
    res = scan_url("https://www.google.com")
    assert 0 <= res["risk_score"] <= 100
    assert 50.0 <= res["confidence"] <= 98.5
    assert res["prob_phishing"] + res["prob_safe"] == pytest.approx(1.0, 0.001)
    assert res["classification"] in ["SAFE", "SUSPICIOUS", "PHISHING"]
    assert res["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert len(res["reasons"]) >= 2
    assert "security_checks" in res
    assert "whois_data" in res

def test_whois_unknown_handling():
    """Verify that unavailable WHOIS does not produce contradiction."""
    res = scan_url("https://f1ipkart.com")
    assert res["whois_data"]["status"] == "UNAVAILABLE"
    assert res["whois_data"]["age_days"] is None
    # Explanation should acknowledge unavailable or privacy shielded record
    assert any("whois" in r.lower() or "unavailable" in r.lower() or "typosquatting" in r.lower() for r in res["reasons"])

def test_recent_scans_integration():
    res_list = client.get("/api/v1/recent-scans").json()
    assert isinstance(res_list, list)
    if len(res_list) > 0:
        latest = res_list[0]
        assert "url" in latest
        assert "classification" in latest
        assert "risk_score" in latest
