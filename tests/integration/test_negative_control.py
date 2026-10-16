"""Integration test for negative control verification (clean server produces 0 findings)."""

import pytest
from auditforge.core.contracts import TrustState
from auditforge.orchestrator import ScanOrchestrator


def test_clean_reader_negative_control(tmp_path):
    """Verify clean_reader achieves TrustState.VERIFIED with zero security findings."""
    db_file = str(tmp_path / "clean_test.db")
    orchestrator = ScanOrchestrator(db_path=db_file, use_docker=False, use_llm=False)

    result = orchestrator.run_scan("fixtures/clean_reader/")

    # Assert negative control holds: 0 findings
    assert len(result.findings) == 0, f"Expected 0 findings on clean server, got {len(result.findings)}"
    assert result.trust_state == TrustState.VERIFIED
    assert len(result.snapshot.tools) == 2
    assert "word_count" in result.snapshot.tools
    assert "search_docs" in result.snapshot.tools
    assert result.scan_mode == "LIVE_SCAN"
    assert result.stage_coverage.get("static_ast") == "PASS"
    assert result.stage_coverage.get("catalog_discovery") == "PASS"
