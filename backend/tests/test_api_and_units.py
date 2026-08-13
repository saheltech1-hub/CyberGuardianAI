import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.ioc import extract_iocs
from backend.app.mitre import map_techniques
from backend.app.log_analyzer import summarize_lines
from backend.app.security_analysis import analyze_event
from urllib.parse import urlparse

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"


def test_analyze_endpoint_benign():
    r = client.post("/api/v1/analyze", json={"text": "This is a benign event"})
    assert r.status_code == 200
    body = r.json()
    assert "risk" in body
    assert isinstance(body["indicators"], list)


def test_triage_endpoint_malicious():
    payload = {
        "text": "User invoked powershell.exe and connected to 192.0.2.1 using curl"
    }
    r = client.post("/api/v1/triage", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["risk"] in ("low", "medium", "high")
    assert "iocs" in body and isinstance(body["iocs"], dict)
    assert "mitre" in body and isinstance(body["mitre"], list)
    assert "log_summary" in body and isinstance(body["log_summary"], dict)


def test_validation_empty_and_oversize():
    r = client.post("/api/v1/analyze", json={"text": ""})
    assert r.status_code == 422
    r2 = client.post("/api/v1/analyze", json={"text": "a" * 10001})
    assert r2.status_code == 422


def test_ioc_extraction():
    text = "Contact http://example.com from 203.0.113.5 with hash d41d8cd98f00b204e9800998ecf8427e"
    iocs = extract_iocs(text)
    # IPv4 exact match
    assert "203.0.113.5" in iocs["ipv4"]
    # Domain exact match
    assert "example.com" in iocs["domains"]
    # URL hostname exact match using urlparse
    assert any(urlparse(u).hostname == "example.com" for u in iocs["urls"])
    # MD5 hash exact match
    assert "d41d8cd98f00b204e9800998ecf8427e" in iocs["hashes"]


def test_mitre_mapping():
    mt = map_techniques("powershell invoked")
    assert any(item.get("id") == "T1059.001" for item in mt)


def test_log_analysis():
    lines = ["Failed password for user", "Connection from 10.0.0.1", "Random info"]
    summary = summarize_lines(lines)
    assert summary["line_count"] == 3
    assert isinstance(summary["categories"], dict)


def test_security_analysis_deterministic():
    a = analyze_event("powershell run base64")
    b = analyze_event("powershell run base64")
    assert a == b
