import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"

def test_scan_api_safe_url():
    response = client.post("/api/v1/scan", json={"url": "https://google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["url"].startswith("https://")
    assert "classification" in data
    assert "risk_score" in data
    assert "confidence" in data
    assert "reasons" in data

def test_scan_api_phishing_url():
    response = client.post("/api/v1/scan", json={"url": "http://paypal-verification-update-account.xyz/login"})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] in ["SUSPICIOUS", "PHISHING"]
    assert data["risk_score"] > 30
