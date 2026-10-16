"""Deterministic unit tests for KOALA model assurance integration.

These tests execute purely in-memory and in isolated temporary directories.
They do NOT require /home/psw, Ollama, network access, or external binaries,
ensuring 100% reproducible and clean execution across GitHub Actions (3.11 & 3.12).
"""

import json
from pathlib import Path
import subprocess
import pytest
from fastapi.testclient import TestClient

from auditforge.api.app import app
from auditforge.assurance.koala import (
    KoalaAssuranceRunner,
    KoalaReport,
    KoalaAuditSummary,
    KoalaControlResult,
    KoalaAuditMode,
)

SAMPLE_KOALA_JSON = {
    "audit_id": "test-audit-uuid-1234",
    "tool_version": "0.2.0",
    "generated_at": "2026-10-16T12:00:00Z",
    "disclaimer": "Koala produces evidence and gap analysis, not legal certification.",
    "target": {"model_name": "qwen2.5-coder-7b"},
    "frameworks": ["nist_ai_rmf", "eu_ai_act"],
    "summary": {
        "controls_total": 33,
        "machine_verified": 14,
        "self_attested": 0,
        "not_assessed": 10,
        "failed": 9,
        "machine_verification_percent": 42.4,
        "assessment_coverage_percent": 69.7,
    },
    "results": [
        {
            "control_id": "GOV-1.1",
            "framework": "nist_ai_rmf",
            "clause": "1.1",
            "title": "Intended use and context documented",
            "status": "pass",
            "evidence_state": "machine_verified",
            "severity": "high",
            "evidence": "Model card found with intended use sections.",
        },
        {
            "control_id": "DATA-2.1",
            "framework": "eu_ai_act",
            "clause": "Article 10",
            "title": "Training data governance documented",
            "status": "fail",
            "evidence_state": "machine_verified",
            "severity": "high",
            "evidence": "No training data lineage file found.",
        },
    ],
    "attribution": "Audited via KOALA (version 0.2.0) by DomAiyn Labs (Apache 2.0)",
    "model_id": "Qwen2.5-Coder-7B-Instruct",
}


@pytest.fixture(autouse=True)
def isolate_koala_cache(tmp_path, monkeypatch):
    """Ensure every test runs with an isolated cache directory."""
    cache_dir = tmp_path / "koala_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(KoalaAssuranceRunner, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(KoalaAssuranceRunner, "LATEST_REPORT_FILE", cache_dir / "latest_report.json")
    monkeypatch.setattr(KoalaAssuranceRunner, "HISTORICAL_DIR", cache_dir / "history")
    return cache_dir


def test_koala_assurance_runner_availability_detection(monkeypatch):
    """Verify is_available correctly inspects CLI response."""
    runner = KoalaAssuranceRunner()

    def mock_run_success(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="koala v0.2.0\n", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_run_success)
    assert runner.is_available() is True

    def mock_run_fail(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=1, stdout="", stderr="command not found")

    monkeypatch.setattr(subprocess, "run", mock_run_fail)
    assert runner.is_available() is False


def test_koala_assurance_runner_successful_static_run(monkeypatch, tmp_path):
    """Verify isolated execution of static governance audit."""
    runner = KoalaAssuranceRunner()
    model_dir = tmp_path / "mock_model"
    model_dir.mkdir()

    monkeypatch.setattr(runner, "is_available", lambda: True)

    def mock_subprocess_run(cmd, *args, **kwargs):
        out_idx = cmd.index("-o") + 1
        out_file = Path(cmd[out_idx])
        out_file.write_text(json.dumps(SAMPLE_KOALA_JSON), encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="Audit completed", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    report = runner.run_audit(model_dir=str(model_dir), frameworks=["nist_ai_rmf", "eu_ai_act"])
    assert isinstance(report, KoalaReport)
    assert report.tool_version == "0.2.0"
    assert report.audit_mode == KoalaAuditMode.STATIC_GOVERNANCE_AUDIT.value
    assert report.summary.controls_total == 33
    assert report.summary.machine_verified == 14
    assert len(report.results) == 2
    assert "DomAiyn Labs" in report.attribution

    # Verify cached retrieval
    cached = runner.get_latest_report()
    assert cached is not None
    assert cached.audit_id == report.audit_id


def test_koala_assurance_runner_runtime_probes_mode(monkeypatch, tmp_path):
    """Verify audit mode is labeled OLLAMA_RUNTIME_PROBES when target_runtime is given."""
    runner = KoalaAssuranceRunner()
    model_dir = tmp_path / "mock_model"
    model_dir.mkdir()

    monkeypatch.setattr(runner, "is_available", lambda: True)

    def mock_subprocess_run(cmd, *args, **kwargs):
        assert "-t" in cmd
        assert "ollama:qwen2.5-coder:7b" in cmd
        out_idx = cmd.index("-o") + 1
        out_file = Path(cmd[out_idx])
        out_file.write_text(json.dumps(SAMPLE_KOALA_JSON), encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="Audit completed", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    report = runner.run_audit(
        model_dir=str(model_dir),
        target_runtime="ollama:qwen2.5-coder:7b",
    )
    assert report.audit_mode == KoalaAuditMode.OLLAMA_RUNTIME_PROBES.value
    assert report.target_runtime == "ollama:qwen2.5-coder:7b"


def test_koala_assurance_runner_fails_on_unavailable(monkeypatch):
    """Verify runner fails closed if KOALA is not available."""
    runner = KoalaAssuranceRunner()
    monkeypatch.setattr(runner, "is_available", lambda: False)

    with pytest.raises(RuntimeError, match="not installed or available"):
        runner.run_audit()


def test_koala_assurance_runner_fails_on_nonzero_exit(monkeypatch, tmp_path):
    """Verify non-zero subprocess return code raises RuntimeError without fallback."""
    runner = KoalaAssuranceRunner()
    model_dir = tmp_path / "mock_model"
    model_dir.mkdir()

    monkeypatch.setattr(runner, "is_available", lambda: True)

    def mock_subprocess_run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(args=cmd, returncode=2, stdout="", stderr="Error: Framework parsing failed")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    with pytest.raises(RuntimeError, match="KOALA CLI audit failed"):
        runner.run_audit(model_dir=str(model_dir))


def test_koala_assurance_runner_fails_on_timeout(monkeypatch, tmp_path):
    """Verify subprocess timeout raises TimeoutError."""
    runner = KoalaAssuranceRunner()
    model_dir = tmp_path / "mock_model"
    model_dir.mkdir()

    monkeypatch.setattr(runner, "is_available", lambda: True)

    def mock_subprocess_run(cmd, *args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=10.0)

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    with pytest.raises(TimeoutError, match="timed out"):
        runner.run_audit(model_dir=str(model_dir), timeout_seconds=10.0)


def test_koala_assurance_runner_fails_on_malformed_json(monkeypatch, tmp_path):
    """Verify malformed JSON raises ValueError."""
    runner = KoalaAssuranceRunner()
    model_dir = tmp_path / "mock_model"
    model_dir.mkdir()

    monkeypatch.setattr(runner, "is_available", lambda: True)

    def mock_subprocess_run(cmd, *args, **kwargs):
        out_idx = cmd.index("-o") + 1
        out_file = Path(cmd[out_idx])
        out_file.write_text("{this is not valid json...", encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    with pytest.raises(ValueError, match="malformed JSON"):
        runner.run_audit(model_dir=str(model_dir))


def test_koala_assurance_runner_no_stale_report_fallback(monkeypatch, tmp_path):
    """Verify an existing historical report is NEVER loaded as a fallback for a failing run."""
    runner = KoalaAssuranceRunner()
    model_dir = tmp_path / "mock_model"
    model_dir.mkdir()

    # Pre-seed cache with an old report
    old_report = KoalaReport.model_validate(SAMPLE_KOALA_JSON)
    old_report.audit_id = "stale-audit-9999"
    KoalaAssuranceRunner.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    KoalaAssuranceRunner.LATEST_REPORT_FILE.write_text(old_report.model_dump_json(), encoding="utf-8")

    monkeypatch.setattr(runner, "is_available", lambda: True)

    def mock_subprocess_run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="Fatal runner error")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    with pytest.raises(RuntimeError):
        runner.run_audit(model_dir=str(model_dir))

    # Cache should still contain old report, but run_audit refused to return it
    assert runner.get_latest_report().audit_id == "stale-audit-9999"


def test_api_assurance_endpoints_not_assessed_and_cached(monkeypatch):
    """Verify GET /api/assurance/model returns NOT_ASSESSED when empty and does not execute."""
    client = TestClient(app)

    # 1. Fresh GET returns NOT_ASSESSED without executing
    resp = client.get("/api/assurance/model")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "NOT_ASSESSED"
    assert data["audit_mode"] == "NOT_ASSESSED"
    assert data["summary"]["controls_total"] == 0

    # 2. Seed cache manually
    cached_report = KoalaReport.model_validate(SAMPLE_KOALA_JSON)
    KoalaAssuranceRunner.LATEST_REPORT_FILE.write_text(cached_report.model_dump_json(), encoding="utf-8")

    # 3. Subsequent GET returns cached report
    resp2 = client.get("/api/assurance/model")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["audit_id"] == "test-audit-uuid-1234"
    assert data2["summary"]["controls_total"] == 33


def test_api_assurance_audit_trigger_success(monkeypatch, tmp_path):
    """Verify POST /api/assurance/audit executes fresh audit."""
    client = TestClient(app)
    model_dir = tmp_path / "mock_model"
    model_dir.mkdir()

    monkeypatch.setattr(KoalaAssuranceRunner, "is_available", lambda self: True)
    monkeypatch.setattr(KoalaAssuranceRunner, "_resolve_default_model_dir", lambda self: model_dir)

    def mock_subprocess_run(cmd, *args, **kwargs):
        out_idx = cmd.index("-o") + 1
        out_file = Path(cmd[out_idx])
        out_file.write_text(json.dumps(SAMPLE_KOALA_JSON), encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    resp = client.post("/api/assurance/audit", json={"frameworks": ["nist_ai_rmf"]})
    assert resp.status_code == 200
    data = resp.json()
    assert data["summary"]["controls_total"] == 33
    assert data["audit_mode"] == "STATIC_GOVERNANCE_AUDIT"


def test_api_assurance_audit_trigger_unavailable(monkeypatch):
    """Verify POST /api/assurance/audit returns 503 when KOALA CLI is missing."""
    client = TestClient(app)
    monkeypatch.setattr(KoalaAssuranceRunner, "is_available", lambda self: False)

    resp = client.post("/api/assurance/audit", json={})
    assert resp.status_code == 503
    assert "not installed or available" in resp.json()["detail"]


def test_api_assurance_audit_trigger_timeout(monkeypatch, tmp_path):
    """Verify POST /api/assurance/audit returns 504 on execution timeout."""
    client = TestClient(app)
    model_dir = tmp_path / "mock_model"
    model_dir.mkdir()

    monkeypatch.setattr(KoalaAssuranceRunner, "is_available", lambda self: True)
    monkeypatch.setattr(KoalaAssuranceRunner, "_resolve_default_model_dir", lambda self: model_dir)

    def mock_subprocess_run(cmd, *args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=5.0)

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    resp = client.post("/api/assurance/audit", json={})
    assert resp.status_code == 504
    assert "timed out" in resp.json()["detail"]
