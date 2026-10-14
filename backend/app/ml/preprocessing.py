import re
import ipaddress
from urllib.parse import urlparse, unquote
from typing import Tuple

BLOCKED_SCHEMES = {"javascript", "data", "file", "ftp", "gopher", "ssh", "telnet", "mailto"}
METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata"}

def is_ssrf_dangerous_host(host: str) -> Tuple[bool, str]:
    """
    Checks if a hostname or IP address resolves to internal, loopback, or cloud metadata endpoints.
    """
    clean_host = host.split(":")[0].strip("[]").lower()
    
    if clean_host in {"localhost", "localhost.localdomain"} or clean_host.endswith(".localhost"):
        return True, "Loopback addresses (localhost) are restricted for security."
    
    if clean_host in METADATA_HOSTS:
        return True, "Cloud metadata endpoints are restricted for security."

    try:
        ip = ipaddress.ip_address(clean_host)
        if ip.is_loopback:
            return True, "Loopback IP addresses (127.0.0.0/8, ::1) are restricted."
        if ip.is_link_local:
            return True, "Link-local addresses (169.254.0.0/16) are restricted."
        if ip.is_private:
            return True, "Private / internal network IP addresses are restricted from public scans."
        if ip.is_reserved or ip.is_multicast:
            return True, "Reserved / multicast IP ranges are not valid web targets."
    except ValueError:
        # Not a raw IP address; regular hostname
        pass

    return False, ""

def clean_url(url: str) -> str:
    """Normalize and clean URL string."""
    if not url:
        return ""
    url = url.strip()
    
    # Strip null bytes and control characters
    url = re.sub(r"[\x00-\x1f\x7f]", "", url)

    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def validate_url(url: str) -> Tuple[bool, str, str]:
    """
    Validates URL syntax, scheme, and SSRF restrictions.
    Returns (is_valid, cleaned_url_or_error_message, normalized_host).
    """
    if not url or not url.strip():
        return False, "URL string cannot be empty.", ""

    raw_input = url.strip()

    # Reject dangerous control characters
    if any(c in raw_input for c in ["\x00", "\r", "\n"]):
        return False, "URL contains invalid control characters.", ""

    # Check for forbidden schemes
    scheme_match = re.match(r"^([a-zA-Z0-9+.-]+):", raw_input)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        if scheme in BLOCKED_SCHEMES:
            return False, f"URL scheme '{scheme}:' is disallowed for security.", ""
        if scheme not in {"http", "https"}:
            return False, f"Unsupported URL scheme '{scheme}:'. Only HTTP and HTTPS are permitted.", ""

    cleaned = clean_url(raw_input)
    
    try:
        parsed = urlparse(cleaned)
    except Exception as e:
        return False, f"Malformed URL syntax: {str(e)}", ""

    host = parsed.netloc.split(":")[0].strip("[]").lower()
    if not host:
        return False, "URL does not contain a valid host name.", ""

    # SSRF verification
    is_dangerous, reason = is_ssrf_dangerous_host(host)
    if is_dangerous:
        return False, f"Security restriction: {reason}", host

    return True, cleaned, host

def extract_domain(url: str) -> str:
    """Extract domain host name from URL safely."""
    cleaned = clean_url(url)
    try:
        parsed = urlparse(cleaned)
        domain = parsed.netloc.split(":")[0].lower()
        return domain
    except Exception:
        return ""
