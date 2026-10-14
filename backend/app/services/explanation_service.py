from typing import List, Dict, Any

def generate_explanations(
    classification: str,
    https_info: Dict[str, Any],
    keyword_info: Dict[str, Any],
    domain_info: Dict[str, Any],
    url_info: Dict[str, Any],
    whois_info: Dict[str, Any]
) -> List[str]:
    """
    Translates raw ML & security feature flags into clear, evidence-based Explainable AI (XAI) points.
    Eliminates contradictions between classification and underlying security signals.
    """
    reasons = []

    # 1. Brand & Domain Host Evaluation
    if domain_info.get("domain_mismatch"):
        reasons.append(domain_info.get("brand_details", "Potential brand impersonation or typosquatting detected."))
    elif domain_info.get("is_official_brand"):
        reasons.append(domain_info.get("brand_details", "Verified official registered domain for protected brand."))
    elif classification == "SAFE":
        reasons.append("Domain host structure is valid and does not target known protected brands.")

    # 2. HTTPS Connection Status
    if https_info.get("is_https"):
        if classification == "SAFE":
            reasons.append("HTTPS transport encryption is active (SSL/TLS enabled).")
        else:
            reasons.append("HTTPS transport encryption is present; note that HTTPS only encrypts transmission and does not prove site authenticity.")
    else:
        reasons.append("Unencrypted connection (HTTP only): sensitive data or credentials transmitted in cleartext.")

    # 3. Keyword Analysis
    if keyword_info.get("has_suspicious_keywords"):
        kw_list = ", ".join([f"'{kw}'" for kw in keyword_info.get("matched_keywords", [])])
        reasons.append(f"Suspicious credential, banking, or urgency keywords detected in URL path: {kw_list}.")
    elif classification == "SAFE":
        reasons.append("No credential harvesting or urgency keywords found in URL path.")

    # 4. Host Type / IP Address Usage
    if url_info.get("is_ip"):
        reasons.append("Website is hosted on a raw numerical IP address rather than a legitimate registered domain name.")

    # 5. Top-Level Domain Risk
    if domain_info.get("is_suspicious_tld"):
        tld = domain_info.get("tld", "")
        reasons.append(f"Uses top-level domain (.{tld}) statistically correlated with high abuse and disposable spam domains.")

    # 6. Obfuscation Patterns
    if url_info.get("has_at_symbol"):
        reasons.append("Contains '@' symbol, a common deceptive URL technique used to disguise the real destination host.")

    if url_info.get("has_url_encoding"):
        reasons.append("URL contains percent-encoded characters, often used to bypass basic keyword filters.")

    if url_info.get("entropy", 0) > 4.5:
        reasons.append("High character entropy (randomness) detected, indicating possible parameter obfuscation or token stuffing.")

    if url_info.get("url_length", 0) > 85:
        reasons.append("Abnormally long URL structure often used to hide the true host or query payload.")

    # 7. WHOIS / Domain Age Evidence
    if whois_info.get("is_recent"):
        age = whois_info.get("age_days", "unknown")
        reasons.append(f"Domain was newly registered ({age} days old). Recently created domains carry significantly elevated risk.")
    elif whois_info.get("status") == "UNAVAILABLE" and classification != "SAFE":
        reasons.append("Domain WHOIS record is unavailable or privacy-shielded; domain age could not be independently verified.")

    # Ensure at least 2 clear reasons for any classification
    if not reasons:
        if classification == "SAFE":
            reasons.append("Standard URL lexical structure with no known threat patterns.")
            reasons.append("No credential phishing or lookalike indicators detected.")
        else:
            reasons.append("Multiple anomalous lexical and structural patterns identified across URL parameters.")

    return reasons
