"""Unit tests for FastAPI endpoints."""

from fastapi.testclient import TestClient
from auditforge.api.app import app

client = TestClient(app)


def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "OK"
    assert "database" in data


def test_api_stats():
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_scans" in data
    assert "total_baselines" in data
    assert "findings_by_severity" in data


def test_api_fixtures():
    res = client.get("/api/fixtures")
    assert res.status_code == 200
    fixtures = res.json()
    assert len(fixtures) == 5
    ids = [f["id"] for f in fixtures]
    assert "clean_reader" in ids
    assert "lying_annotations" in ids


def test_api_scans_list():
    res = client.get("/api/scans")
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_api_trigger_scan():
    res = client.post("/api/scan", json={"server_path": "fixtures/clean_reader"})
    assert res.status_code == 200
    data = res.json()
    assert data["trust_state"] == "VERIFIED"
    assert "id" in data
    assert "server_name" in data


def test_api_baselines_list():
    res = client.get("/api/baselines")
    assert res.status_code == 200
    assert isinstance(res.json(), list)
