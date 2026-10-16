"""Unit tests for AuditForge FastAPI endpoints, security boundaries, and live demo actions."""

from pathlib import Path
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
    set_orchestrator(ScanOrchestrator(db=test_db, use_docker=False, use_llm=False))
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
    assert len(fixtures) >= 5
    ids = [f["id"] for f in fixtures]
    assert "clean_reader" in ids
    assert "rogue_server" in ids
    assert "rogue_server_patched" in ids
    assert "poisoned_description" in ids
    assert "poisoned_description_patched" in ids
    assert "lying_annotations" in ids
    assert "lying_annotations_patched" in ids
    assert "rug_pull" in ids


def test_api_scans_list():
    res = client.get("/api/scans")
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_api_trigger_scan_use_llm_false():
    """Verify scanning with use_llm=False works and persists scan result."""
    res = client.post("/api/scan", json={"target_id": "clean_reader", "use_llm": False})
    assert res.status_code == 200
    data = res.json()
    assert data["trust_state"] == "VERIFIED"
    assert "id" in data
    assert data["server_name"] == "clean_reader"
    assert data["stage_coverage"]["catalog_discovery"] == "PASS"
    assert data["stage_coverage"]["description_intelligence"] in {"PASS", "HEURISTIC_ONLY"}

    # Verify scan persistence in DB
    scan_id = data["id"]
    get_res = client.get(f"/api/scans/{scan_id}")
    assert get_res.status_code == 200
    assert get_res.json()["scan_id"] == scan_id


def test_api_trigger_scan_use_llm_true_no_crash():
    """Verify scanning with use_llm=True toggles orchestrator and does NOT raise db_path AttributeError."""
    res = client.post("/api/scan", json={"target_id": "clean_reader", "use_llm": True})
    assert res.status_code == 200
    data = res.json()
    assert "id" in data
    assert data["server_name"] == "clean_reader"


def test_api_trigger_scan_target_id_allowlist():
    """Verify strict allowlist: unregistered target IDs or traversal paths return 400."""
    res = client.post("/api/scan", json={"server_path": "/etc/passwd"})
    assert res.status_code == 400
    assert "Unauthorized target" in res.json()["detail"]

    res2 = client.post("/api/scan", json={"target_id": "unknown_exploit_target"})
    assert res2.status_code == 400


def test_api_baselines_and_diff():
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
        json={"server_id": "clean_reader", "catalog_path": "clean_reader"},
    )
    assert diff_res.status_code == 200
    diff_data = diff_res.json()
    assert diff_data["is_identical"] is True


def test_api_report_export_json_and_markdown():
    """Verify exporting saved scan reports in JSON and Markdown formats."""
    # First run a scan
    scan_res = client.post("/api/scan", json={"target_id": "clean_reader"})
    assert scan_res.status_code == 200
    scan_id = scan_res.json()["id"]

    # Export JSON report
    res_json = client.get(f"/api/scans/{scan_id}/report?format=json")
    assert res_json.status_code == 200
    assert res_json.headers["content-type"].startswith("application/json")
    assert scan_id in res_json.text

    # Export Markdown report
    res_md = client.get(f"/api/scans/{scan_id}/report?format=markdown")
    assert res_md.status_code == 200
    assert "AuditForge Security Audit Report" in res_md.text
    assert scan_id in res_md.text


def test_api_live_rug_pull_demo():
    """Verify live rug-pull demonstration endpoint."""
    res = client.post("/api/demo/rug-pull")
    assert res.status_code == 200
    data = res.json()
    assert data["target"] == "rug_pull"
    assert data["diff"]["is_identical"] is False
    assert "word_count" in data["diff"]["modified_tools"]
    assert data["v1_baseline_hash"] != data["v2_mutated_hash"]


def test_probe_outcomes_aggregation_regression():
    """Verify explicit aggregation ensures TOOL_ERROR, TIMEOUT, UNKNOWN, SKIPPED cannot silently count as PASS."""
    from auditforge.core.contracts import ProbeOutcome, ProbeStatus
    from auditforge.orchestrator import aggregate_probe_outcomes

    # Empty -> SKIPPED
    assert aggregate_probe_outcomes([]) == "SKIPPED"

    # All OK -> PASS
    assert aggregate_probe_outcomes([
        ProbeOutcome(case_id="1", tool_name="t1", status=ProbeStatus.OK),
        ProbeOutcome(case_id="2", tool_name="t2", status=ProbeStatus.OK),
    ]) == "PASS"

    # Any TOOL_ERROR -> ERROR
    assert aggregate_probe_outcomes([
        ProbeOutcome(case_id="1", tool_name="t1", status=ProbeStatus.OK),
        ProbeOutcome(case_id="2", tool_name="t2", status=ProbeStatus.TOOL_ERROR),
    ]) == "ERROR"

    # Any TIMEOUT -> ERROR
    assert aggregate_probe_outcomes([
        ProbeOutcome(case_id="1", tool_name="t1", status=ProbeStatus.OK),
        ProbeOutcome(case_id="2", tool_name="t2", status=ProbeStatus.TIMEOUT),
    ]) == "ERROR"

    # Any UNKNOWN -> ERROR
    assert aggregate_probe_outcomes([
        ProbeOutcome(case_id="1", tool_name="t1", status=ProbeStatus.OK),
        ProbeOutcome(case_id="2", tool_name="t2", status=ProbeStatus.UNKNOWN),
    ]) == "ERROR"

    # All SKIPPED -> SKIPPED
    assert aggregate_probe_outcomes([
        ProbeOutcome(case_id="1", tool_name="t1", status=ProbeStatus.SKIPPED),
    ]) == "SKIPPED"

    # Mixed OK and SKIPPED (no errors) -> SKIPPED (SKIPPED cannot silently count as PASS)
    assert aggregate_probe_outcomes([
        ProbeOutcome(case_id="1", tool_name="t1", status=ProbeStatus.OK),
        ProbeOutcome(case_id="2", tool_name="t2", status=ProbeStatus.SKIPPED),
    ]) == "SKIPPED"


def test_api_baseline_immutable_preservation_and_reapproval():
    """Verify existing baselines are preserved unless reapprove=True is specified."""
    # First approval
    res1 = client.post("/api/baselines/clean_reader/approve")
    assert res1.status_code == 200
    assert res1.json()["status"] == "APPROVED"

    # Second approval without reapprove=True must preserve existing baseline
    res2 = client.post("/api/baselines/clean_reader/approve")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["status"] == "PRESERVED_EXISTING"
    assert data2["preserved"] is True

    # Third approval with reapprove=True overwrites
    res3 = client.post("/api/baselines/clean_reader/approve", json={"reapprove": True})
    assert res3.status_code == 200
    assert res3.json()["status"] == "APPROVED"


def test_api_vulnerable_approval_guard():
    """Verify approving known vulnerable servers is blocked without explicit force=True."""
    for vuln_target in ["rogue_server", "poisoned_description", "lying_annotations"]:
        res = client.post(f"/api/baselines/{vuln_target}/approve")
        assert res.status_code == 400
        assert "Safety Guard" in res.json()["detail"]

        # With force=True, approval succeeds
        res_forced = client.post(f"/api/baselines/{vuln_target}/approve", json={"force": True})
        assert res_forced.status_code == 200
        assert res_forced.json()["status"] == "APPROVED"


def test_api_server_identity_trust():
    """Verify browser-controlled server_name is ignored in favor of trusted allowlisted identity."""
    res = client.post("/api/scan", json={
        "target_id": "clean_reader",
        "server_name": "spoofed_admin_server",
    })
    assert res.status_code == 200
    # Identity is derived strictly from allowlisted target ID
    assert res.json()["server_name"] == "clean_reader"

