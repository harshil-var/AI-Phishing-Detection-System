import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_empty_url_handling():
    response = client.post("/api/v1/scan", json={"url": ""})
    assert response.status_code == 400
    assert "detail" in response.json()

def test_whitespace_url_handling():
    response = client.post("/api/v1/scan", json={"url": "   "})
    assert response.status_code == 400

def test_missing_body_handling():
    response = client.post("/api/v1/scan", json={})
    assert response.status_code == 422
