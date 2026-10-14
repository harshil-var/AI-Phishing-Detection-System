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
    Computes a deterministic, calibrated 0-100 Risk Score consistent with classification.
    
    Formula:
    Base Risk = prob_phishing * 60
    + Brand Impersonation / Typosquatting: +25
    + Missing HTTPS: +15
    + Raw IP Usage: +20
    + Suspicious Keywords: +10 (+5 extra if count > 2)
    + Suspicious TLD: +15
    + Newly Registered Domain (< 90 days): +10
    + Obfuscation / '@' Symbol: +15
    + High Entropy / Length: +5
    """
    # 1. Base score from ML model / calibrated probability
    score = prob_phishing * 60.0

    # 2. Additive weights from verifiable security signals
    is_impersonation = domain_info.get("domain_mismatch", False)
    is_official_brand = domain_info.get("is_official_brand", False)

    if is_impersonation:
        score += 25.0

    if not https_info.get("is_https", True):
        score += 15.0

    if url_info.get("is_ip", False):
        score += 20.0

    if keyword_info.get("has_suspicious_keywords", False):
        kw_count = keyword_info.get("count", 1)
        score += 10.0 + min(10.0, kw_count * 3.0)

    if domain_info.get("is_suspicious_tld", False):
        score += 15.0

    if whois_info.get("is_recent", False):
        score += 10.0

    if url_info.get("has_at_symbol", False):
        score += 15.0

    if url_info.get("entropy", 0) > 4.5:
        score += 5.0

    if url_info.get("url_length", 0) > 85:
        score += 5.0

    # Normalize to [0, 100]
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
