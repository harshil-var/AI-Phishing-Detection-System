from urllib.parse import urlparse
from typing import Dict, Any

def check_https(url: str) -> Dict[str, Any]:
    """
    Evaluates HTTPS security state and returns diagnostic information.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    parsed = urlparse(url)
    is_https = parsed.scheme.lower() == "https"

    if is_https:
        explanation = "HTTPS is enabled (SSL/TLS encrypted connection). Note: HTTPS protects transport encryption but does not guarantee the site is trustworthy."
    else:
        explanation = "HTTPS is NOT enabled. Connection is unencrypted (HTTP only), exposing credentials or data to interception."

    return {
        "is_https": is_https,
        "status": "PASS" if is_https else "WARNING",
        "explanation": explanation
    }
