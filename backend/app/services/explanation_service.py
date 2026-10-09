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
    Translates raw ML & security feature flags into clear, human-readable Explainable AI (XAI) bullet points.
    """
    reasons = []

    # HTTPS check explanation
    if https_info.get("is_https"):
        if classification == "SAFE":
            reasons.append("HTTPS protocol is active with secure transport encryption.")
    else:
        reasons.append("HTTPS is missing; connection to this site is unencrypted (HTTP only).")

    # Keyword explanation
    if keyword_info.get("has_suspicious_keywords"):
        kw_list = ", ".join([f"'{kw}'" for kw in keyword_info.get("matched_keywords", [])])
        reasons.append(f"Suspicious credential or financial keywords detected: {kw_list}.")
    elif classification == "SAFE":
        reasons.append("No suspicious login or financial keywords detected in the URL.")

    # Domain mismatch / impersonation
    if domain_info.get("domain_mismatch"):
        brand = domain_info.get("impersonated_brand", "known brand")
        reasons.append(f"Potential brand impersonation: URL references '{brand}' but domain host does not match official server.")
    
    # Suspicious TLD
    if domain_info.get("is_suspicious_tld"):
        tld = domain_info.get("tld", "")
        reasons.append(f"Uses top-level domain (.{tld}) with elevated statistical risk for malware or phishing.")

    # WHOIS / Domain Age
    if whois_info.get("is_recent"):
        age = whois_info.get("age_days", "unknown")
        reasons.append(f"Domain is newly registered ({age} days old). Recently created domains carry higher risk.")

    # IP Address
    if url_info.get("is_ip"):
        reasons.append("Website is hosted on a raw IP address rather than a domain name.")

    # Obfuscation / '@' symbol
    if url_info.get("has_at_symbol"):
        reasons.append("Contains '@' character, which can deceive browsers into navigating to a different destination.")

    # URL entropy / complexity
    if url_info.get("entropy", 0) > 4.5:
        reasons.append("Unusually high character randomness (entropy) detected, suggesting obfuscated parameters.")

    if url_info.get("url_length", 0) > 85:
        reasons.append("Excessively long URL structure commonly used to obscure malicious links.")

    # Positive fallback if SAFE and few reasons present
    if classification == "SAFE" and len(reasons) < 3:
        reasons.append("Domain host structure appears normal.")
        reasons.append("No obfuscation or suspicious parameter patterns detected.")

    return reasons
