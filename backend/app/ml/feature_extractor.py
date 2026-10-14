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
    "info", "gq", "cf", "tk", "ml", "ga", "fit", "surf", "rest", "cam", "icu",
    "buzz", "monster", "bar", "link", "click", "download"
}

POPULAR_BRANDS = [
    "paypal", "google", "apple", "microsoft", "amazon", "facebook", "netflix",
    "instagram", "chase", "wellsfargo", "bankofamerica", "binance", "coinbase"
]

IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
SPECIAL_CHARS_PATTERN = re.compile(r"[@%+=?&~#:$!*,;]")

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum([p * math.log2(p) for p in prob])

def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extract modular numerical & categorical features from a URL string.
    Ensures identical, robust feature extraction between ML training and inference,
    eliminating spurious artifact shortcuts (e.g. www/apex subdomain bias).
    """
    if not url:
        url = ""
    
    # Normalize scheme for parsing
    working_url = url.strip()
    if not working_url.startswith(("http://", "https://")):
        working_url = "https://" + working_url

    try:
        parsed = urlparse(working_url)
    except Exception:
        parsed = urlparse("https://invalid-url.local")

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    # Clean domain (remove port if present)
    host = netloc.split(":")[0]

    # IP address detection
    is_ip = 1 if IP_PATTERN.match(host) else 0

    # Public suffix and brand impersonation parsing
    from app.security.domain_checker import parse_domain_parts, evaluate_brand_impersonation
    subdomain, domain_label, tld, reg_domain = parse_domain_parts(working_url)

    # Subdomain calculation:
    # Crucially ignore generic 'www' prefix so apex domains (leetcode.com)
    # and www domains (www.leetcode.com) are treated identically.
    if is_ip:
        no_subdomains = 0
        sub_parts = []
    else:
        raw_parts = [p for p in subdomain.split(".") if p]
        sub_parts = [p for p in raw_parts if p.lower() != "www"]
        no_subdomains = len(sub_parts)

    has_subdomain = 1 if no_subdomains > 0 else 0

    # Dots calculation without 'www.' artifact:
    host_no_www = host[4:] if host.startswith("www.") else host
    dots_in_host = host_no_www.count(".")
    dots_in_path = path.count(".")
    no_dots = dots_in_host + dots_in_path + query.count(".")

    # Path and query depth
    path_depth = len([p for p in path.split("/") if p])
    path_length = len(path)
    query_length = len(query)
    fragment_length = len(fragment)

    # Lengths and counts computed consistently on normalized URL
    url_length = len(working_url)
    domain_length = len(host_no_www)

    no_slashes = working_url.count("/")
    no_hyphens = working_url.count("-")
    hyphens_in_domain = domain_label.count("-")
    no_digits = sum(c.isdigit() for c in working_url)
    digits_in_domain = sum(c.isdigit() for c in domain_label)
    no_letters = sum(c.isalpha() for c in working_url)
    no_special_chars = len(SPECIAL_CHARS_PATTERN.findall(working_url))

    is_https = 1 if scheme == "https" else 0
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    has_at_symbol = 1 if "@" in working_url else 0
    has_url_encoding = 1 if "%" in working_url else 0

    url_entropy = round(calculate_entropy(working_url), 4)
    domain_entropy = round(calculate_entropy(domain_label), 4)

    # Keyword check
    url_lower = working_url.lower()
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    has_suspicious_keyword = 1 if suspicious_keyword_count > 0 else 0

    # Brand impersonation & typosquatting evaluation
    brand_eval = evaluate_brand_impersonation(working_url)
    domain_mismatch = 1 if brand_eval["is_impersonation"] else 0

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "query_length": query_length,
        "fragment_length": fragment_length,
        "path_depth": path_depth,
        "no_dots": no_dots,
        "dots_in_domain": dots_in_host,
        "dots_in_path": dots_in_path,
        "no_slashes": no_slashes,
        "no_hyphens": no_hyphens,
        "hyphens_in_domain": hyphens_in_domain,
        "no_digits": no_digits,
        "digits_in_domain": digits_in_domain,
        "no_letters": no_letters,
        "no_special_chars": no_special_chars,
        "is_ip": is_ip,
        "has_at_symbol": has_at_symbol,
        "no_subdomains": no_subdomains,
        "has_subdomain": has_subdomain,
        "suspicious_tld": suspicious_tld,
        "is_https": is_https,
        "url_entropy": url_entropy,
        "domain_entropy": domain_entropy,
        "suspicious_keyword_count": suspicious_keyword_count,
        "has_suspicious_keyword": has_suspicious_keyword,
        "has_url_encoding": has_url_encoding,
        "domain_mismatch": domain_mismatch
    }

FEATURE_COLUMNS = [
    "url_length", "domain_length", "path_length", "query_length", "fragment_length",
    "path_depth", "no_dots", "dots_in_domain", "dots_in_path", "no_slashes",
    "no_hyphens", "hyphens_in_domain", "no_digits", "digits_in_domain",
    "no_letters", "no_special_chars", "is_ip", "has_at_symbol",
    "no_subdomains", "has_subdomain", "suspicious_tld", "is_https",
    "url_entropy", "domain_entropy", "suspicious_keyword_count",
    "has_suspicious_keyword", "has_url_encoding", "domain_mismatch"
]
