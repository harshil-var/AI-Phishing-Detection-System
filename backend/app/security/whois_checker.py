import datetime
from typing import Dict, Any
from app.ml.preprocessing import extract_domain, is_ssrf_dangerous_host

try:
    import whois
except ImportError:
    whois = None

def get_domain_whois(url: str) -> Dict[str, Any]:
    """
    Performs WHOIS domain lookup with timeout & fallback for privacy/rate limits.
    Enforces SSRF prevention against internal networks and cloud metadata.
    """
    domain = extract_domain(url) if ("/" in url or ":" in url) else url.strip().lower()
    domain = domain.split(":")[0].strip("[]")

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

    if not domain or domain.replace(".", "").isdigit():
        default_result["error"] = "Raw IP address or invalid domain name; WHOIS domain record not applicable"
        return default_result

    # SSRF verification before network request
    is_dangerous, reason = is_ssrf_dangerous_host(domain)
    if is_dangerous:
        default_result["error"] = f"Security restriction: {reason}"
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
            "status": "AVAILABLE" if (creation_date or registrar) else "UNAVAILABLE"
        }
    except Exception as e:
        default_result["error"] = f"WHOIS lookup failed or domain privacy enabled: {str(e)[:60]}"
        return default_result
