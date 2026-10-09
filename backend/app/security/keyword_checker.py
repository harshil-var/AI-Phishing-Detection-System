from typing import Dict, Any, List
from app.ml.feature_extractor import SUSPICIOUS_KEYWORDS

def check_keywords(url: str) -> Dict[str, Any]:
    """
    Checks URL string for common credential-harvesting & urgency keywords.
    """
    url_lower = url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]

    has_suspicious_keywords = len(found_keywords) > 0

    return {
        "has_suspicious_keywords": has_suspicious_keywords,
        "matched_keywords": found_keywords,
        "count": len(found_keywords),
        "explanation": f"Detected suspicious keywords: {', '.join(found_keywords)}" if has_suspicious_keywords else "No suspicious keywords detected in URL."
    }
