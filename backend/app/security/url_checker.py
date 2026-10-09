import re
from typing import Dict, Any
from app.ml.feature_extractor import calculate_entropy

def check_url_structure(url: str) -> Dict[str, Any]:
    """
    Evaluates IP usage, length, entropy, special characters, and URL obfuscation.
    """
    url_length = len(url)
    is_ip = bool(re.search(r"^(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}", url))
    has_at_symbol = "@" in url
    has_url_encoding = "%" in url
    entropy = calculate_entropy(url)

    anomalies = []
    if is_ip:
        anomalies.append("URL uses a raw IP address instead of a domain name.")
    if has_at_symbol:
        anomalies.append("URL contains an '@' symbol, which can obscure the true destination domain.")
    if url_length > 75:
        anomalies.append("Unusually long URL structure.")
    if entropy > 4.5:
        anomalies.append("High character entropy detected, indicating possible obfuscation.")
    if has_url_encoding:
        anomalies.append("Contains percent-encoded characters.")

    return {
        "is_ip": is_ip,
        "has_at_symbol": has_at_symbol,
        "has_url_encoding": has_url_encoding,
        "url_length": url_length,
        "entropy": round(entropy, 2),
        "anomalies": anomalies
    }
