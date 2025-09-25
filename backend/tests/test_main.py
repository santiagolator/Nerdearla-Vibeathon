import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    """Test del endpoint /health"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "message" in data

def test_ping_endpoint():
    """Test del endpoint /api/v1/ping"""
    response = client.get("/api/v1/ping")
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True

def test_root_endpoint():
    """Test del endpoint raíz /"""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "version" in data
