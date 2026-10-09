from typing import Dict, Any

def calculate_risk_score(
    prob_phishing: float,
    https_info: Dict[str, Any],
    keyword_info: Dict[str, Any],
    domain_info: Dict[str, Any],
    url_info: Dict[str, Any],
    whois_info: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Computes a deterministic, normalized 0-100 Risk Score.
    
    Formula:
    Base Risk = prob_phishing * 70
    + Missing HTTPS: +10
    + Raw IP Usage: +15
    + Brand Impersonation Mismatch: +15
    + Suspicious Keywords: +10
    + Suspicious TLD: +10
    + Recent Domain (< 30 days): +10
    + Obfuscation / '@' Symbol: +10
    """
    # 1. Base score from ML model probability
    score = prob_phishing * 70.0

    # 2. Additive weights from security checks
    if not https_info.get("is_https", True):
        score += 10.0

    if url_info.get("is_ip", False):
        score += 15.0

    if domain_info.get("domain_mismatch", False):
        score += 15.0

    if keyword_info.get("has_suspicious_keywords", False):
        score += 10.0

    if domain_info.get("is_suspicious_tld", False):
        score += 10.0

    if whois_info.get("is_recent", False):
        score += 10.0

    if url_info.get("has_at_symbol", False):
        score += 10.0

    if url_info.get("entropy", 0) > 4.5:
        score += 5.0

    # Normalize to 0 - 100
    final_score = int(min(100, max(0, round(score))))

    # Severity level
    if final_score <= 30:
        severity = "LOW"
    elif final_score <= 60:
        severity = "MEDIUM"
    elif final_score <= 80:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    return {
        "risk_score": final_score,
        "severity": severity
    }
