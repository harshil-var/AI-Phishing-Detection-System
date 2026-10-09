from urllib.parse import urlparse, unquote
import re

def clean_url(url: str) -> str:
    """Normalize and clean URL string."""
    if not url:
        return ""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def extract_domain(url: str) -> str:
    """Extract domain host name from URL."""
    cleaned = clean_url(url)
    parsed = urlparse(cleaned)
    domain = parsed.netloc.split(":")[0].lower()
    return domain
