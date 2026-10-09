from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class ScanRequest(BaseModel):
    url: str = Field(..., description="URL to analyze", json_schema_extra={"example": "https://example.com"})

class SecurityChecksSchema(BaseModel):
    https: bool
    suspicious_keywords: bool
    ip_address: bool
    domain_mismatch: bool
    suspicious_tld: bool
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = None
    url_entropy: Optional[float] = None

class ScanResponse(BaseModel):
    url: str
    domain: str
    classification: str = Field(..., description="SAFE, SUSPICIOUS, or PHISHING")
    risk_score: int = Field(..., ge=0, le=100)
    confidence: float = Field(..., ge=0.0, le=100.0)
    severity: str = Field(..., description="LOW, MEDIUM, HIGH, or CRITICAL")
    reasons: List[str]
    security_checks: SecurityChecksSchema
    whois_data: Optional[Dict[str, Any]] = None
    timestamp: Optional[int] = None
