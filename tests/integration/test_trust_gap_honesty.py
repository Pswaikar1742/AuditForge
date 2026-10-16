"""Integration test verifying truthful trust-gap evidence distinction."""

import pytest
from auditforge.analyzers.trust_gap import TrustGapAnalyzer
from auditforge.core.contracts import (
    EvidenceRecord,
    Finding,
    ProbeOutcome,
    ProbeStatus,
    ServerSnapshot,
    Severity,
    ToolRecord,
    TrustState,
)


def test_static_only_trust_gap_labeled_source_indicator():
    """Verify that static findings without runtime execution are labeled SOURCE_INDICATOR / LIKELY."""
    analyzer = TrustGapAnalyzer()

    # Tool claiming read-only
    tool = ToolRecord(
        name="view_log",
        description="View system log file",
        annotations={"readOnly": True},
    )
    snapshot = ServerSnapshot(server_id="test_server", tools={"view_log": tool})

    # Static finding (AST found os.remove)
    static_finding = Finding(
        rule_id="AST-FILE-002",
        severity=Severity.HIGH,
        tool_name="view_log",
        reason="os.remove deletes filesystem data.",
        confidence=1.0,
        remediation="Remove deletion.",
    )

    state, gap_findings, gap_evidence = analyzer.evaluate(
        snapshot=snapshot,
        findings=[static_finding],
        evidence=[],
        probe_outcomes=[],
    )

    assert state in {TrustState.TRUST_GAP, TrustState.SUSPICIOUS}
    assert len(gap_findings) == 1
    # Must explicitly state SOURCE_INDICATOR / LIKELY, not OBSERVED execution
    assert "SOURCE_INDICATOR" in gap_findings[0].reason
    assert "No runtime execution confirmed" in gap_findings[0].reason
    assert gap_evidence[0].raw_data.get("provenance") == "SOURCE_INDICATOR"


def test_runtime_trust_gap_labeled_observed_attempt():
    """Verify that dynamic probe telemetry is truthfully labeled OBSERVED_ATTEMPT."""
    analyzer = TrustGapAnalyzer()

    tool = ToolRecord(
        name="view_log",
        description="View system log file",
        annotations={"readOnly": True},
    )
    snapshot = ServerSnapshot(server_id="test_server", tools={"view_log": tool})

    # Probe outcome captured subprocess.Popen inside container
    probe = ProbeOutcome(
        case_id="case-001",
        tool_name="view_log",
        status=ProbeStatus.OK,
        telemetry_events=[{"event": "subprocess.Popen", "args": ["rm", "-rf", "/tmp"]}],
        evidence_id="ev-probe-123",
    )

    state, gap_findings, gap_evidence = analyzer.evaluate(
        snapshot=snapshot,
        findings=[],
        evidence=[],
        probe_outcomes=[probe],
    )

    assert state in {TrustState.TRUST_GAP, TrustState.SUSPICIOUS}
    assert len(gap_findings) == 1
    assert "OBSERVED_ATTEMPT" in gap_findings[0].reason
    assert gap_evidence[0].raw_data.get("provenance") == "OBSERVED_ATTEMPT"
    assert "ev-probe-123" in gap_findings[0].evidence_ids
