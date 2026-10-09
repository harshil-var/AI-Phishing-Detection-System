import datetime
from typing import Dict, Any
from app.ml.preprocessing import extract_domain

try:
    import whois
except ImportError:
    whois = None

def get_domain_whois(url: str) -> Dict[str, Any]:
    """
    Performs WHOIS domain lookup with timeout & fallback for privacy/rate limits.
    """
    domain = extract_domain(url)
    default_result = {
        "domain": domain,
        "creation_date": None,
        "age_days": None,
        "registrar": "Privacy Protected / Hidden",
        "expiry_date": None,
        "is_recent": False,
        "error": None,
        "status": "UNAVAILABLE"
    }

    if not domain or domain == "localhost" or domain.replace(".", "").isdigit():
        default_result["error"] = "IP address or invalid domain name"
        return default_result

    if whois is None:
        default_result["error"] = "whois package not installed"
        return default_result

    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        # Handle list of dates if returned by whois
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0]

        expiry_date = w.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]

        age_days = None
        is_recent = False
        if isinstance(creation_date, datetime.datetime):
            # Strip timezone offset to avoid naive vs aware datetime error
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            now = datetime.datetime.now()
            age_days = (now - creation_date).days
            if age_days < 90:  # Domain registered in last 90 days
                is_recent = True

        return {
            "domain": domain,
            "creation_date": creation_date.strftime("%Y-%m-%d") if isinstance(creation_date, datetime.datetime) else str(creation_date) if creation_date else None,
            "age_days": age_days,
            "registrar": str(registrar) if registrar else "Privacy Protected / Hidden",
            "expiry_date": expiry_date.strftime("%Y-%m-%d") if isinstance(expiry_date, datetime.datetime) else str(expiry_date) if expiry_date else None,
            "is_recent": is_recent,
            "error": None,
            "status": "AVAILABLE"
        }
    except Exception as e:
        default_result["error"] = f"WHOIS lookup failed or domain privacy enabled: {str(e)[:60]}"
        return default_result
