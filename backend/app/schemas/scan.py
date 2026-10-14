from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class ScanRequest(BaseModel):
    url: str = Field(..., description="URL to analyze", json_schema_extra={"example": "https://example.com"})

class SecurityChecksSchema(BaseModel):
    https: bool
    https_status: Optional[str] = "PASS"
    suspicious_keywords: bool
    matched_keywords: Optional[List[str]] = []
    ip_address: bool
    domain_mismatch: bool
    brand_status: Optional[str] = "NO_BRAND_TARGETED"
    detected_brand: Optional[str] = None
    brand_details: Optional[str] = None
    is_official_brand: Optional[bool] = False
    suspicious_tld: bool
    tld: Optional[str] = None
    domain_age_days: Optional[int] = None
    whois_status: Optional[str] = "UNAVAILABLE"
    registrar: Optional[str] = None
    url_entropy: Optional[float] = None
    model_source: Optional[str] = "CALIBRATED_ENGINE"

class ScanResponse(BaseModel):
    url: str = Field(..., description="Cleaned and validated URL string")
    domain: str = Field(..., description="Registered domain or IP host")
    classification: str = Field(..., description="Canonical classification verdict: SAFE, SUSPICIOUS, or PHISHING")
    prediction: Optional[str] = Field(None, description="Explicit prediction verdict alias matching classification")
    risk_score: int = Field(..., ge=0, le=100, description="Normalized composite risk index from 0 (minimal risk) to 100 (critical risk)")
    confidence: float = Field(..., ge=0.0, le=100.0, description="Calibrated statistical confidence percentage (50.0% to 98.5%)")
    severity: str = Field(..., description="Categorical severity level: LOW (0-30), MEDIUM (31-60), HIGH (61-80), CRITICAL (81-100)")
    reasons: List[str] = Field(..., description="Explainable AI findings and risk factor statements")
    security_checks: SecurityChecksSchema = Field(..., description="Structured verifiable threat signals")
    whois_data: Optional[Dict[str, Any]] = None
    model_source: Optional[str] = None
    prob_phishing: Optional[float] = Field(None, ge=0.0, le=1.0, description="Model-estimated posterior probability of phishing [0.0 - 1.0]")
    phishing_probability: Optional[float] = Field(None, ge=0.0, le=1.0, description="Explicit probability field [0.0 - 1.0]")
    prob_safe: Optional[float] = Field(None, ge=0.0, le=1.0, description="Model-estimated posterior probability of legitimate [0.0 - 1.0]")
    timestamp: Optional[int] = None
    debug_info: Optional[Dict[str, Any]] = Field(None, description="Detailed inference diagnostics (feature count, threshold, raw probabilities)")
