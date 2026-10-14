import re
import functools
import unicodedata
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import tldextract
    _extractor = tldextract.TLDExtract(cache_dir=False)
except Exception:
    _extractor = None

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online", "site", "live", "vip", "work",
    "info", "gq", "cf", "tk", "ml", "ga", "fit", "surf", "rest", "cam", "icu",
    "buzz", "monster", "bar", "link", "click", "download"
}

# Catalog of protected brands with their verified official registered domains
PROTECTED_BRANDS: Dict[str, List[str]] = {
    "flipkart": ["flipkart.com"],
    "google": ["google.com", "google.co.in", "google.co.uk", "google.ca", "google.com.au"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.co.jp"],
    "paypal": ["paypal.com", "paypal.me"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "azure.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "messenger.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "github": ["github.com", "github.io"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "ebay": ["ebay.com"],
    "walmart": ["walmart.com"],
    "sbi": ["onlinesbi.sbi", "onlinesbi.com", "sbi.co.in"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"]
}

# Character substitutions commonly used in typosquatting / visual homoglyphs
HOMOGLYPH_REPLACEMENTS = [
    ("1", "l"),
    ("!", "l"),
    ("|", "l"),
    ("0", "o"),
    ("8", "b"),
    ("5", "s"),
    ("$", "s"),
    ("3", "e"),
    ("4", "a"),
    ("@", "a"),
    ("vv", "w"),
    ("rn", "m"),
    ("cl", "d"),
]

def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def normalize_homoglyphs(text: str) -> str:
    """Normalize common visually confusing character substitutions."""
    res = text.lower()
    for char, target in HOMOGLYPH_REPLACEMENTS:
        res = res.replace(char, target)
    return res

@functools.lru_cache(maxsize=32768)
def parse_domain_parts(url_or_domain: str) -> Tuple[str, str, str, str]:
    """
    Safely extract (subdomain, domain_label, suffix, full_registered_domain).
    Uses tldextract if available, otherwise resilient dot splitting.
    """
    raw = url_or_domain.strip().lower()
    if "://" not in raw:
        raw = "http://" + raw
    
    parsed = urlparse(raw)
    host = parsed.netloc.split(":")[0].strip().lower()

    # Handle Punycode / IDN
    try:
        host = host.encode("idna").decode("ascii")
    except Exception:
        pass

    if _extractor:
        try:
            ext = _extractor(host)
            subdomain = ext.subdomain
            domain_label = ext.domain
            suffix = ext.suffix
            reg_domain = f"{domain_label}.{suffix}" if suffix and domain_label else host
            return subdomain, domain_label, suffix, reg_domain
        except Exception:
            pass

    # Fallback parser
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 2:
        # Simple heuristic for common two-level TLDs like co.uk, co.in
        if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "gov", "net"} and len(parts[-1]) == 2:
            domain_label = parts[-3]
            suffix = f"{parts[-2]}.{parts[-1]}"
            subdomain = ".".join(parts[:-3])
        else:
            domain_label = parts[-2]
            suffix = parts[-1]
            subdomain = ".".join(parts[:-2])
        reg_domain = f"{domain_label}.{suffix}"
    elif len(parts) == 1:
        domain_label = parts[0]
        suffix = ""
        subdomain = ""
        reg_domain = parts[0]
    else:
        domain_label = host
        suffix = ""
        subdomain = ""
        reg_domain = host

    return subdomain, domain_label, suffix, reg_domain

def evaluate_brand_impersonation(url: str) -> Dict[str, Any]:
    """
    Evaluates whether the domain or URL is:
    1. OFFICIAL_BRAND: Legitimate official domain for a protected brand.
    2. TYPOSQUATTING_DETECTED: Lookalike domain mimicking brand via typos or homoglyphs.
    3. SUBDOMAIN_IMPERSONATION: Brand placed inside subdomain of unrelated registered domain.
    4. COMPOUND_IMPERSONATION: Brand combined with deceptive keywords (e.g. flipkart-login.example.com).
    5. NO_BRAND_TARGETED: No protected brand target detected.
    """
    subdomain, domain_label, suffix, registered_domain = parse_domain_parts(url)
    clean_domain_label = domain_label.lower()
    normalized_label = normalize_homoglyphs(clean_domain_label)

    # 1. First, check if this is an official brand domain
    for brand, official_domains in PROTECTED_BRANDS.items():
        if registered_domain in official_domains:
            return {
                "brand_status": "OFFICIAL_BRAND",
                "detected_brand": brand,
                "target_domains": official_domains,
                "is_official_brand": True,
                "is_impersonation": False,
                "similarity_score": 1.0,
                "details": f"Verified official domain ({registered_domain}) for protected brand '{brand.title()}'."
            }

    # 2. Check for typosquatting / lookalike on the registered domain label (e.g., f1ipkart)
    for brand, official_domains in PROTECTED_BRANDS.items():
        brand_len = len(brand)
        
        # Check homoglyph-normalized equality (e.g., f1ipkart -> flipkart)
        if normalized_label == brand and clean_domain_label != brand:
            return {
                "brand_status": "TYPOSQUATTING_DETECTED",
                "detected_brand": brand,
                "target_domains": official_domains,
                "is_official_brand": False,
                "is_impersonation": True,
                "similarity_score": 0.98,
                "details": f"Visual homoglyph / typosquatting detected: domain label '{clean_domain_label}' mimics brand '{brand.title()}' (official domain: {official_domains[0]})."
            }

        # Check Levenshtein distance on raw label
        raw_dist = levenshtein_distance(clean_domain_label, brand)
        norm_dist = levenshtein_distance(normalized_label, brand)
        min_dist = min(raw_dist, norm_dist)

        # Allow distance 1 for brands with length >= 4, or distance 2 for brands with length >= 7
        max_allowed_dist = 2 if brand_len >= 7 else (1 if brand_len >= 4 else 0)
        
        # Avoid false positives on very short generic words
        if min_dist > 0 and min_dist <= max_allowed_dist and abs(len(clean_domain_label) - brand_len) <= max_allowed_dist:
            sim_score = max(0.0, round(1.0 - (min_dist / max(len(clean_domain_label), brand_len)), 2))
            return {
                "brand_status": "TYPOSQUATTING_DETECTED",
                "detected_brand": brand,
                "target_domains": official_domains,
                "is_official_brand": False,
                "is_impersonation": True,
                "similarity_score": sim_score,
                "details": f"Typosquatting detected: domain '{clean_domain_label}' is within edit distance {min_dist} of protected brand '{brand.title()}' (official domain: {official_domains[0]})."
            }

    # 3. Check for Subdomain Impersonation (e.g., flipkart.example.com or flipkart-login.example.com)
    if subdomain:
        sub_parts = [p.lower() for p in subdomain.split(".") if p]
        for brand, official_domains in PROTECTED_BRANDS.items():
            for sp in sub_parts:
                norm_sp = normalize_homoglyphs(sp)
                if brand in sp or brand in norm_sp or (len(brand) >= 5 and levenshtein_distance(norm_sp, brand) <= 1):
                    return {
                        "brand_status": "SUBDOMAIN_IMPERSONATION",
                        "detected_brand": brand,
                        "target_domains": official_domains,
                        "is_official_brand": False,
                        "is_impersonation": True,
                        "similarity_score": 0.95,
                        "details": f"Deceptive subdomain impersonation: brand '{brand.title()}' is embedded in subdomain '{subdomain}', but registered domain is '{registered_domain}'."
                    }

    # 4. Check for compound domain names containing brand + keywords (e.g., flipkart-login, secure-amazon)
    for brand, official_domains in PROTECTED_BRANDS.items():
        if brand in clean_domain_label and clean_domain_label != brand:
            # Domain contains brand string plus other tokens (e.g. flipkart-verify)
            return {
                "brand_status": "COMPOUND_IMPERSONATION",
                "detected_brand": brand,
                "target_domains": official_domains,
                "is_official_brand": False,
                "is_impersonation": True,
                "similarity_score": 0.90,
                "details": f"Brand compound name detected: '{clean_domain_label}' contains brand '{brand.title()}' with unauthorized prefixes/suffixes (official domain: {official_domains[0]})."
            }

    # 5. Check if brand is in URL path/query while registered domain is unrelated (e.g. security-update.com/paypal/login)
    url_lower = url.lower()
    for brand, official_domains in PROTECTED_BRANDS.items():
        if brand in url_lower:
            return {
                "brand_status": "PATH_IMPERSONATION",
                "detected_brand": brand,
                "target_domains": official_domains,
                "is_official_brand": False,
                "is_impersonation": True,
                "similarity_score": 0.85,
                "details": f"Brand deception in URL path: URL references '{brand.title()}', but registered domain '{registered_domain}' is not an authorized domain (official domain: {official_domains[0]})."
            }

    # 5. No brand targeted
    return {
        "brand_status": "NO_BRAND_TARGETED",
        "detected_brand": None,
        "target_domains": [],
        "is_official_brand": False,
        "is_impersonation": False,
        "similarity_score": 0.0,
        "details": "No known brand impersonation or typosquatting detected."
    }

def check_domain_security(url: str) -> Dict[str, Any]:
    """
    Comprehensive domain security evaluation:
    - Accurate TLD risk inspection.
    - Public Suffix / Domain extraction.
    - Deep Typosquatting and Brand Impersonation analysis.
    """
    subdomain, domain_label, suffix, registered_domain = parse_domain_parts(url)
    is_suspicious_tld = suffix in SUSPICIOUS_TLDS

    brand_eval = evaluate_brand_impersonation(url)
    brand_status = brand_eval["brand_status"]
    is_impersonation = brand_eval["is_impersonation"]
    is_official_brand = brand_eval["is_official_brand"]
    detected_brand = brand_eval["detected_brand"]

    explanation_items = []
    if is_impersonation:
        explanation_items.append(brand_eval["details"])
    elif is_official_brand:
        explanation_items.append(brand_eval["details"])
    else:
        explanation_items.append("Domain does not appear to mimic protected brand names.")

    if is_suspicious_tld:
        explanation_items.append(f"Top-level domain (.{suffix}) has higher statistical association with disposable or malicious hosts.")

    return {
        "registered_domain": registered_domain,
        "domain_label": domain_label,
        "subdomain": subdomain,
        "tld": suffix,
        "is_suspicious_tld": is_suspicious_tld,
        "domain_mismatch": is_impersonation,
        "is_official_brand": is_official_brand,
        "brand_status": brand_status,
        "impersonated_brand": detected_brand,
        "brand_details": brand_eval["details"],
        "explanation": " ".join(explanation_items)
    }
