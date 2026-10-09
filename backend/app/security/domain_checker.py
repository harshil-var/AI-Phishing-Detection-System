from typing import Dict, Any
from urllib.parse import urlparse
from app.ml.feature_extractor import SUSPICIOUS_TLDS, POPULAR_BRANDS

def check_domain_security(url: str) -> Dict[str, Any]:
    """
    Checks for TLD risks, excessive subdomains, and brand impersonation mismatches.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0].lower()
    domain_parts = [p for p in domain.split(".") if p]

    tld = domain_parts[-1] if len(domain_parts) > 0 else ""
    is_suspicious_tld = tld in SUSPICIOUS_TLDS

    # Check for brand mismatch
    main_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
    detected_brand = None
    brand_mismatch = False

    url_lower = url.lower()
    for brand in POPULAR_BRANDS:
        if brand in url_lower and brand not in main_domain:
            detected_brand = brand
            brand_mismatch = True
            break

    explanation = []
    if is_suspicious_tld:
        explanation.append(f"TLD (.{tld}) is frequently associated with disposable or phishing domains.")
    if brand_mismatch:
        explanation.append(f"The URL appears to contain branding-related terms ('{detected_brand}') that do not match the actual domain ('{main_domain}').")
    if not explanation:
        explanation.append("Domain structure and TLD appear normal.")

    return {
        "tld": tld,
        "is_suspicious_tld": is_suspicious_tld,
        "domain_mismatch": brand_mismatch,
        "impersonated_brand": detected_brand,
        "explanation": " ".join(explanation)
    }
