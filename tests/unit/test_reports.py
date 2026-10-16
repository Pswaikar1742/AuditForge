"""Unit tests for JSON and Markdown report generators."""

import json
from auditforge.core.contracts import (
    ScanResult,
    TrustState,
    ToolRecord,
    ServerSnapshot,
    Finding,
    Severity,
    EvidenceRecord,
)
from auditforge.reports.json_report import export_json_report
from auditforge.reports.markdown import generate_markdown_report


def test_json_and_markdown_report_generation(tmp_path):
    """Verify JSON export and Markdown generation from ScanResult."""
    t = ToolRecord(name="tool_1", description="Description of tool 1")
    ev = EvidenceRecord(
        evidence_id="ev-test-1",
        source="static_ast",
        summary="Test observation",
        raw_data={"line": 42},
    )
    fnd = Finding(
        id="fnd-1",
        rule_id="AST-001",
        severity=Severity.HIGH,
        reason="Test high risk finding",
        confidence=0.95,
        remediation="Fix test risk",
        evidence_ids=["ev-test-1"],
    )
    snap = ServerSnapshot(server_id="test_srv", tools={"tool_1": t})
    result = ScanResult(
        scan_id="scan-12345",
        target="fixtures/clean_reader",
        trust_state=TrustState.TRUST_GAP,
        snapshot=snap,
        findings=[fnd],
        evidence=[ev],
        summary="Audit summary test.",
    )

    # Test JSON Export
    json_path = str(tmp_path / "report.json")
    exported_path = export_json_report(result, json_path)
    assert exported_path == json_path
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["scan_id"] == "scan-12345"
    assert data["trust_state"] == "TRUST_GAP"
    assert len(data["findings"]) == 1

    # Test Markdown Generation
    md_path = str(tmp_path / "report.md")
    md_content = generate_markdown_report(result, md_path)
    assert "# 🛡️ AuditForge Security Audit Report" in md_content
    assert "scan-12345" in md_content
    assert "AST-001" in md_content
    assert "HIGH" in md_content
