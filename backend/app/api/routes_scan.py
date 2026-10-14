from fastapi import APIRouter, HTTPException, status
from typing import List, Dict, Any
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.phishing_service import scan_url, get_recent_scans
from app.security.whois_checker import get_domain_whois
from app.ml.preprocessing import is_ssrf_dangerous_host

router = APIRouter(prefix="", tags=["URL Scanning"])

@router.post("/scan", response_model=ScanResponse, summary="Analyze a URL for Phishing Risk")
def analyze_url(payload: ScanRequest):
    """
    Submits a URL for comprehensive AI-powered phishing detection, security checks, and XAI explanations.
    """
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL string cannot be empty."
        )
    
    try:
        result = scan_url(payload.url)
        return result
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during URL analysis: {str(e)}"
        )

@router.get("/recent-scans", summary="Retrieve Recent Scans History")
def fetch_recent_scans():
    """
    Returns recent scans performed on the platform.
    """
    return get_recent_scans()

@router.get("/domain/{domain_name}", summary="Lookup Domain WHOIS & Threat Intelligence")
def domain_intelligence(domain_name: str):
    """
    Retrieves WHOIS information and domain security details for a given domain string.
    """
    if not domain_name or "." not in domain_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Valid domain name with extension required."
        )
    
    clean_domain = domain_name.strip().lower()
    is_dangerous, reason = is_ssrf_dangerous_host(clean_domain)
    if is_dangerous:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Security restriction: {reason}"
        )

    return get_domain_whois(clean_domain)
