import re
import math
from urllib.parse import urlparse
from typing import Dict, Any

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "account", "secure", "security",
    "update", "password", "bank", "wallet", "payment", "free", "claim",
    "winner", "urgent", "confirm", "signin", "support", "recover",
    "webscr", "ebayisapi", "banking", "credential", "auth", "paypal"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online", "site", "live", "vip", "work",
    "info", "gq", "cf", "tk", "ml", "ga", "fit", "surf", "rest", "cam", "icu"
}

POPULAR_BRANDS = [
    "paypal", "google", "apple", "microsoft", "amazon", "facebook", "netflix",
    "instagram", "chase", "wellsfargo", "bankofamerica", "binance", "coinbase"
]

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum([p * math.log2(p) for p in prob])

def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extract modular numerical & categorical features from a URL string.
    Ensures identical logic between ML training and real-time backend inference.
    """
    if not url:
        url = ""
    
    # Ensure scheme for parsing
    working_url = url
    if not working_url.startswith(("http://", "https://")):
        working_url = "http://" + working_url

    try:
        parsed = urlparse(working_url)
    except Exception:
        parsed = urlparse("http://invalid-url.local")

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    # Clean domain (remove port if present)
    domain = netloc.split(":")[0]

    # IP address detection
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    is_ip = 1 if re.match(ip_pattern, domain) else 0

    # Subdomain calculation
    domain_parts = [p for p in domain.split(".") if p]
    no_subdomains = max(0, len(domain_parts) - 2) if not is_ip else 0

    # TLD extraction
    tld = domain_parts[-1] if len(domain_parts) > 0 else ""
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # Keyword check
    url_lower = url.lower()
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    has_suspicious_keyword = 1 if suspicious_keyword_count > 0 else 0

    # Domain mismatch check (e.g. brand in path/subdomain but main domain is different)
    domain_mismatch = 0
    main_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
    for brand in POPULAR_BRANDS:
        if brand in url_lower and brand not in main_domain:
            domain_mismatch = 1
            break

    # Counts and Ratios
    url_length = len(url)
    domain_length = len(domain)
    path_length = len(path)
    query_length = len(query)
    fragment_length = len(fragment)

    no_dots = url.count(".")
    no_slashes = url.count("/")
    no_hyphens = url.count("-")
    no_at_symbol = url.count("@")
    no_digits = sum(c.isdigit() for c in url)
    no_letters = sum(c.isalpha() for c in url)
    
    special_chars = r"[@%+=?&~#:$!*,;]"
    no_special_chars = len(re.findall(special_chars, url))

    is_https = 1 if scheme == "https" else 0
    has_url_encoding = 1 if "%" in url else 0
    url_entropy = round(calculate_entropy(url), 4)

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "query_length": query_length,
        "fragment_length": fragment_length,
        "no_dots": no_dots,
        "no_slashes": no_slashes,
        "no_hyphens": no_hyphens,
        "no_digits": no_digits,
        "no_letters": no_letters,
        "no_special_chars": no_special_chars,
        "is_ip": is_ip,
        "has_at_symbol": 1 if no_at_symbol > 0 else 0,
        "no_subdomains": no_subdomains,
        "suspicious_tld": suspicious_tld,
        "is_https": is_https,
        "url_entropy": url_entropy,
        "suspicious_keyword_count": suspicious_keyword_count,
        "has_suspicious_keyword": has_suspicious_keyword,
        "has_url_encoding": has_url_encoding,
        "domain_mismatch": domain_mismatch
    }

FEATURE_COLUMNS = [
    "url_length", "domain_length", "path_length", "query_length", "fragment_length",
    "no_dots", "no_slashes", "no_hyphens", "no_digits", "no_letters", "no_special_chars",
    "is_ip", "has_at_symbol", "no_subdomains", "suspicious_tld", "is_https",
    "url_entropy", "suspicious_keyword_count", "has_suspicious_keyword",
    "has_url_encoding", "domain_mismatch"
]
