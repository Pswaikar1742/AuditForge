"""Unit tests for KOALA model assurance integration."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from auditforge.api.app import app
from auditforge.assurance.koala import KoalaAssuranceRunner, KoalaReport


def test_koala_assurance_runner_loads_report():
    """Verify KoalaAssuranceRunner runs or parses a valid KOALA report."""
    runner = KoalaAssuranceRunner()
    assert runner.is_available() is True

    report = runner.run_audit()
    assert isinstance(report, KoalaReport)
    assert report.tool_version == "0.2.0"
    assert "nist_ai_rmf" in report.frameworks
    assert "eu_ai_act" in report.frameworks
    assert report.summary.controls_total > 0
    assert "DomAiyn Labs" in report.attribution


def test_api_assurance_endpoints():
    """Verify /api/assurance/model endpoint returns structured governance data."""
    client = TestClient(app)
    resp = client.get("/api/assurance/model")
    assert resp.status_code == 200
    data = resp.json()

    assert data["tool_version"] == "0.2.0"
    assert "nist_ai_rmf" in data["frameworks"]
    assert "summary" in data
    assert data["summary"]["controls_total"] > 0
    assert len(data["results"]) > 0
    assert "DomAiyn Labs" in data["attribution"]


def test_api_assurance_audit_trigger():
    """Verify /api/assurance/audit endpoint re-runs audit with specified frameworks."""
    client = TestClient(app)
    resp = client.post("/api/assurance/audit", json={"frameworks": ["nist_ai_rmf"]})
    assert resp.status_code == 200
    data = resp.json()

    assert data["frameworks"] == ["nist_ai_rmf"]
    assert data["summary"]["controls_total"] > 0
