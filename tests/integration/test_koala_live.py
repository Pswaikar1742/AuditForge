"""Live integration tests for real KOALA v0.2.0 installation and local model cards.

This test requires the host machine's actual KOALA checkout at /home/psw/KOALA/KOALA.
It is explicitly skipped in environments (e.g. CI) where KOALA is not installed.
"""

from pathlib import Path
import pytest
from auditforge.assurance.koala import KoalaAssuranceRunner, KoalaReport

KOALA_INSTALLED = Path("/home/psw/KOALA/KOALA").exists()


@pytest.mark.skipif(not KOALA_INSTALLED, reason="Live KOALA repository not found at /home/psw/KOALA/KOALA")
def test_live_koala_installation_and_audit():
    """Verify live KOALA v0.2.0 CLI executes against local model cards."""
    runner = KoalaAssuranceRunner()
    assert runner.is_available() is True

    report = runner.run_audit(frameworks=["nist_ai_rmf", "eu_ai_act"])
    assert isinstance(report, KoalaReport)
    assert report.tool_version == "0.2.0"
    assert "nist_ai_rmf" in report.frameworks
    assert "eu_ai_act" in report.frameworks
    assert report.summary.controls_total > 0
    assert "DomAiyn Labs" in report.attribution
    assert report.audit_mode == "STATIC_GOVERNANCE_AUDIT"
