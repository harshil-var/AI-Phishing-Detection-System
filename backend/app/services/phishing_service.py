import time
from typing import Dict, Any, List
from app.ml.preprocessing import clean_url, extract_domain
from app.ml.predictor import predictor_instance
from app.security.https_checker import check_https
from app.security.whois_checker import get_domain_whois
from app.security.keyword_checker import check_keywords
from app.security.domain_checker import check_domain_security
from app.security.url_checker import check_url_structure
from app.services.risk_service import calculate_risk_score
from app.services.explanation_service import generate_explanations

# In-memory recent scan history store
RECENT_SCANS: List[Dict[str, Any]] = []
MAX_RECENT_SCANS = 20

def scan_url(url: str) -> Dict[str, Any]:
    """
    Full pipeline orchestration for URL phishing analysis.
    """
    cleaned_url = clean_url(url)
    domain = extract_domain(cleaned_url)

    # 1. Run Security Checks
    https_info = check_https(cleaned_url)
    keyword_info = check_keywords(cleaned_url)
    domain_info = check_domain_security(cleaned_url)
    url_info = check_url_structure(cleaned_url)
    whois_info = get_domain_whois(cleaned_url)

    # 2. Run ML Model Prediction
    ml_result = predictor_instance.predict(cleaned_url)
    classification = ml_result["classification"]
    confidence = ml_result["confidence"]
    prob_phishing = ml_result["prob_phishing"]

    # 3. Calculate Risk Score & Severity
    risk_data = calculate_risk_score(
        prob_phishing=prob_phishing,
        https_info=https_info,
        keyword_info=keyword_info,
        domain_info=domain_info,
        url_info=url_info,
        whois_info=whois_info
    )
    risk_score = risk_data["risk_score"]
    severity = risk_data["severity"]

    # 4. Generate Explainable AI Reasons
    reasons = generate_explanations(
        classification=classification,
        https_info=https_info,
        keyword_info=keyword_info,
        domain_info=domain_info,
        url_info=url_info,
        whois_info=whois_info
    )

    # Combine structured security checks output
    security_checks = {
        "https": https_info["is_https"],
        "suspicious_keywords": keyword_info["has_suspicious_keywords"],
        "ip_address": url_info["is_ip"],
        "domain_mismatch": domain_info["domain_mismatch"],
        "suspicious_tld": domain_info["is_suspicious_tld"],
        "domain_age_days": whois_info.get("age_days"),
        "registrar": whois_info.get("registrar"),
        "url_entropy": url_info.get("entropy")
    }

    result = {
        "url": cleaned_url,
        "domain": domain,
        "classification": classification,
        "risk_score": risk_score,
        "confidence": confidence,
        "severity": severity,
        "reasons": reasons,
        "security_checks": security_checks,
        "whois_data": whois_info,
        "timestamp": int(time.time())
    }

    # Record in recent scans history
    RECENT_SCANS.insert(0, result)
    if len(RECENT_SCANS) > MAX_RECENT_SCANS:
        RECENT_SCANS.pop()

    return result

def get_recent_scans() -> List[Dict[str, Any]]:
    """Returns top recent scans."""
    return RECENT_SCANS
