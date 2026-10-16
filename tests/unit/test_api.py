import pytest
from fastapi.testclient import TestClient
from auditforge.api import app, set_db, set_orchestrator
from auditforge.storage.database import Database
from auditforge.orchestrator import ScanOrchestrator

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    test_db_path = str(tmp_path / "api_test.db")
    test_db = Database(test_db_path)
    set_db(test_db)
    set_orchestrator(ScanOrchestrator(db_path=test_db_path, use_docker=False, use_llm=False))
    yield




def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "OK"
    assert "database" in data
    assert "ollama_host" in data
    assert "docker_image" in data


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
    assert "rogue_server" in ids
    assert "poisoned_description" in ids
    assert "lying_annotations" in ids
    assert "rug_pull" in ids


def test_api_scans_list():
    res = client.get("/api/scans")
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_api_trigger_scan_clean_reader():
    res = client.post("/api/scan", json={"server_path": "clean_reader"})
    assert res.status_code == 200
    data = res.json()
    assert data["trust_state"] == "VERIFIED"
    assert "id" in data
    assert "server_name" in data


def test_api_trigger_scan_path_traversal_rejected():
    """Verify that arbitrary external paths outside allowable project bounds return HTTP 400."""
    res = client.post("/api/scan", json={"server_path": "/etc/passwd"})
    assert res.status_code == 400
    assert "outside allowable project directory" in res.json()["detail"]


def test_api_baselines_list():
    res = client.get("/api/baselines")
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_api_approve_baseline_and_diff():
    # Approve clean_reader baseline
    res = client.post("/api/baselines/clean_reader/approve")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "APPROVED"
    assert data["server_id"] == "clean_reader"

    # Fetch approved baseline
    res_base = client.get("/api/baselines/clean_reader")
    assert res_base.status_code == 200
    assert res_base.json()["server_id"] == "clean_reader"

    # Compare identical diff
    diff_res = client.post(
        "/api/diff",
        json={"server_id": "clean_reader", "catalog_path": "fixtures/clean_reader/catalog.json"},
    )
    assert diff_res.status_code == 200
    diff_data = diff_res.json()
    assert diff_data["is_identical"] is True
