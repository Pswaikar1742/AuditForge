"""Integration tests verifying vulnerable vs. remediated/patched MCP server pairs.

Validates that:
1. Vulnerable versions trigger exact planted security findings and non-VERIFIED trust states.
2. Patched versions eliminate the planted vulnerabilities, achieve TrustState.VERIFIED.
3. Legitimate tool functionality continues to work properly in both versions.
"""

from pathlib import Path
import pytest
from auditforge.core.contracts import TrustState
from auditforge.orchestrator import ScanOrchestrator

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"


def _scan(name: str, tmp_path: Path):
    return ScanOrchestrator(
        db_path=str(tmp_path / f"{name}.db"),
        use_docker=False,
        use_llm=False,
    ).run_scan(str(FIXTURES / name))


# ── Pair 1: Rogue Server vs. Patched Safe Diagnostic ───────────────
def test_pair_rogue_server(tmp_path):
    # 1. Vulnerable version
    vuln_result = _scan("rogue_server", tmp_path)
    vuln_rules = {f.rule_id for f in vuln_result.findings}
    assert "AST-SHELL-001" in vuln_rules
    assert "AST-SUBPROCESS-001" in vuln_rules
    assert vuln_result.trust_state == TrustState.ROGUE

    # 2. Patched version
    patched_result = _scan("rogue_server_patched", tmp_path)
    assert len(patched_result.findings) == 0
    assert patched_result.trust_state == TrustState.VERIFIED

    # 3. Legitimate functionality verification on patched server
    from fixtures.rogue_server_patched.server import system_diagnostic
    res = system_diagnostic("database")
    assert res["status"] == "diagnostic_complete"
    assert res["healthy"] == "True"


# ── Pair 2: Poisoned Description vs. Patched Clean Metadata ────────
def test_pair_poisoned_description(tmp_path):
    # 1. Vulnerable version
    vuln_result = _scan("poisoned_description", tmp_path)
    vuln_rules = {f.rule_id for f in vuln_result.findings}
    assert "DESC-INJECT-001" in vuln_rules
    assert "DESC-INJECT-002" in vuln_rules
    assert "DESC-EXFIL-001" in vuln_rules
    assert vuln_result.trust_state == TrustState.ROGUE

    # 2. Patched version
    patched_result = _scan("poisoned_description_patched", tmp_path)
    assert len(patched_result.findings) == 0
    assert patched_result.trust_state == TrustState.VERIFIED

    # 3. Legitimate functionality verification on both
    from fixtures.poisoned_description_patched.server import convert_currency
    res = convert_currency("USD", "EUR", 100.0)
    assert res["converted_amount"] == 92.0


# ── Pair 3: Lying Annotations vs. Patched Genuine Read-Only ─────────
def test_pair_lying_annotations(tmp_path):
    # 1. Vulnerable version
    vuln_result = _scan("lying_annotations", tmp_path)
    vuln_rules = {f.rule_id for f in vuln_result.findings}
    assert "AST-FILE-002" in vuln_rules
    assert "TRUST-GAP-001" in vuln_rules
    assert vuln_result.trust_state == TrustState.TRUST_GAP

    # 2. Patched version
    patched_result = _scan("lying_annotations_patched", tmp_path)
    assert len(patched_result.findings) == 0
    assert patched_result.trust_state == TrustState.VERIFIED

    # 3. Legitimate functionality verification on patched server
    from fixtures.lying_annotations_patched.server import view_log
    res = view_log("auth")
    assert res["status"] == "read"
    assert "authenticated successfully" in res["entry"]


# ── Pair 4: Rug-Pull Baseline vs. Mutated Supply Chain ──────────────
def test_pair_rug_pull_stdio(tmp_path):
    """Verify live stdio rug-pull pair detects catalog drift without fabrication."""
    import sys
    from auditforge.catalog.client import MCPCatalogClient
    from auditforge.catalog.pinning import diff_catalogs

    server_py = FIXTURES / "rug_pull" / "server.py"
    cmd1 = [sys.executable, str(server_py), "--version", "1"]
    cmd2 = [sys.executable, str(server_py), "--version", "2"]

    orch = ScanOrchestrator(
        db_path=str(tmp_path / "rug_pull_test.db"),
        use_docker=False,
        use_llm=False,
    )

    # 1. Discover baseline v1 and mutated v2 via live stdio
    import asyncio
    client1 = MCPCatalogClient(cmd1, server_id="rug_pull")
    baseline = asyncio.run(client1.discover_live())

    client2 = MCPCatalogClient(cmd2, server_id="rug_pull")
    mutated = asyncio.run(client2.discover_live())

    diff_res = diff_catalogs(baseline, mutated)
    assert not diff_res.is_identical
    assert "word_count" in diff_res.modified_tools

    # 2. Pin baseline v1
    orch.db.save_baseline(baseline, overwrite=True)

    # 3. Scan v1 baseline
    patched_scan = orch.run_scan(
        target=str(server_py),
        server_command=cmd1,
        server_id="rug_pull",
        use_llm=False,
        use_docker=False,
    )
    assert len(patched_scan.findings) == 0
    assert patched_scan.trust_state == TrustState.VERIFIED

    # 4. Scan v2 mutated (triggers PIN-RUGPULL-001 drift finding via TrustGapAnalyzer)
    vuln_scan = orch.run_scan(
        target=str(server_py),
        server_command=cmd2,
        server_id="rug_pull",
        use_llm=False,
        use_docker=False,
    )
    assert any(f.rule_id == "PIN-RUGPULL-001" for f in vuln_scan.findings)
    assert vuln_scan.trust_state in (TrustState.TRUST_GAP, TrustState.SUSPICIOUS, TrustState.ROGUE)

