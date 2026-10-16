"""Deterministic, source-only regression tests for the public benchmark corpus."""

from pathlib import Path
import json

import pytest

from auditforge.analyzers.description import DescriptionAnalyzer
from auditforge.analyzers.static import StaticAnalyzer
from auditforge.analyzers.trust_gap import TrustGapAnalyzer
from auditforge.core.contracts import ServerSnapshot, ToolRecord, TrustState


TARGETS = Path(__file__).parents[2] / "benchmarks" / "targets"


def load_snapshot(target: Path) -> ServerSnapshot:
    """Load the fixture manifest without importing or executing an MCP server."""
    data = json.loads((target / "catalog.json").read_text(encoding="utf-8"))
    tools = {item["name"]: ToolRecord(**item) for item in data["tools"]}
    return ServerSnapshot(server_id=data["server_id"], tools=tools)

EXPECTED_STATIC = {
    "official-mcp-time": set(),
    "official-mcp-fetch": {"BANDIT-B310"},
    "official-mcp-git": {"AST-SUBPROCESS-001", "AST-SUBPROCESS-002", "BANDIT-B404", "BANDIT-B603", "BANDIT-B607"},
    "official-mcp-filesystem": {"AST-FILE-001"},
    "appsecco-secrets-pii": set(),
    "appsecco-filesystem-workspace-actions": {"AST-SHELL-001", "BANDIT-B605"},
    "appsecco-indirect-prompt-injection": set(),
    "appsecco-malicious-tools": {"BANDIT-B307"},
}

EXPECTED_DESCRIPTION = {
    "official-mcp-time": set(),
    "official-mcp-fetch": set(),
    "official-mcp-git": set(),
    "official-mcp-filesystem": set(),
    "appsecco-secrets-pii": set(),
    "appsecco-filesystem-workspace-actions": set(),
    "appsecco-indirect-prompt-injection": {"DESC-INJECT-001", "DESC-INJECT-002", "DESC-EXFIL-001"},
    "appsecco-malicious-tools": set(),
}


@pytest.mark.parametrize("target_name", sorted(EXPECTED_STATIC))
def test_benchmark_target_static_and_description_ground_truth(target_name: str):
    target = TARGETS / target_name
    assert (target / "server.py").is_file()
    assert (target / "catalog.json").is_file()
    static_findings, static_evidence = StaticAnalyzer(str(target / "server.py")).analyze()
    description_findings, description_evidence = [], []
    snapshot = load_snapshot(target)
    analyzer = DescriptionAnalyzer(use_llm=False)
    for tool in snapshot.tools.values():
        findings, evidence = analyzer.analyze_tool(tool)
        description_findings.extend(findings)
        description_evidence.extend(evidence)
    assert {f.rule_id for f in static_findings} == EXPECTED_STATIC[target_name]
    assert {f.rule_id for f in description_findings} == EXPECTED_DESCRIPTION[target_name]
    for finding in static_findings + description_findings:
        assert finding.evidence_ids
    for record in static_evidence + description_evidence:
        assert record.raw_data


@pytest.mark.parametrize("target_name", sorted(EXPECTED_STATIC))
def test_benchmark_catalog_contracts_are_loaded_without_execution(target_name: str):
    target = TARGETS / target_name
    snapshot = load_snapshot(target)
    assert snapshot.tools
    assert snapshot.catalog_fingerprint
    findings, evidence = StaticAnalyzer(str(target / "server.py")).analyze()
    state, gap_findings, gap_evidence = TrustGapAnalyzer().evaluate(
        snapshot=snapshot,
        findings=findings,
        evidence=evidence,
        probe_outcomes=[],
        stage_coverage={
            "catalog_discovery": "PASS",
            "static_ast": "PASS",
            "description_intelligence": "PASS",
        },
    )
    assert state in set(TrustState)
    assert all(f.evidence_ids for f in gap_findings)
    assert all(e.raw_data for e in gap_evidence)


def test_benchmark_never_starts_target_processes():
    """The harness is intentionally limited to catalog loading and source parsing."""
    assert not list(TARGETS.glob("**/__pycache__"))
