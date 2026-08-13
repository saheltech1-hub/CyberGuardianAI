from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_clean_input():
    response = client.post("/api/v1/analyze", json={"text": "normal system event"})
    assert response.status_code == 200
    assert response.json()["risk"] == "low"


def test_analyze_suspicious_input():
    response = client.post(
        "/api/v1/analyze",
        json={"text": "powershell used with base64 encoded command"},
    )
    assert response.status_code == 200
    assert response.json()["risk"] == "medium"
    assert len(response.json()["indicators"]) >= 2


def test_input_validation():
    response = client.post("/api/v1/analyze", json={"text": ""})
    assert response.status_code == 422
