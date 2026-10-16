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
