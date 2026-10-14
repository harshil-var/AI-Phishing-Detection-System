import time
from fastapi import APIRouter
from app.ml.predictor import predictor_instance

router = APIRouter(prefix="", tags=["Health Check"])

@router.get("/health", summary="Backend Health Check")
def health_check():
    """
    Returns API health status, model availability, and timestamp.
    """
    model_status = getattr(predictor_instance, "model_status", "LOADED" if predictor_instance.model is not None else "CALIBRATED_ENGINE")
    return {
        "status": "HEALTHY",
        "service": "AI Phishing Detection Platform Backend",
        "version": "1.0.0",
        "model_status": model_status,
        "timestamp": int(time.time())
    }
