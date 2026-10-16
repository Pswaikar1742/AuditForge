"""Acceptance tests against all 5 synthetic competition fixtures.

Verifies:
  - clean_reader: Negative control, produces no critical/high findings, TrustState.VERIFIED.
  - rogue_server: SAST-001 command execution, TrustState.ROGUE.
  - poisoned_description: DESC-003 prompt injection & DESC-004 credential reference, TrustState.ROGUE.
  - lying_annotations: ANN-001 contract-to-behavior trust gap violation, TrustState.TRUST_GAP.
  - rug_pull: PIN-RUGPULL-001 cryptographic baseline drift detection, TrustState.ROGUE.
"""

from pathlib import Path
import pytest

from auditforge.orchestrator import ScanOrchestrator
from auditforge.core.contracts import Severity, TrustState
from auditforge.catalog.client import MCPCatalogClient

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
FIXTURES_DIR = ROOT_DIR / "fixtures"


def test_fixture_clean_reader():
    """Negative control: Clean reader server must pass with TrustState.VERIFIED."""
    target = FIXTURES_DIR / "clean_reader"
    orchestrator = ScanOrchestrator(db_path=":memory:")
    result = orchestrator.run_scan(str(target))

    critical_or_high = [
        f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    assert len(critical_or_high) == 0
    assert result.trust_state == TrustState.VERIFIED


def test_fixture_rogue_server():
    """Positive control: Rogue server with OS command execution."""
    target = FIXTURES_DIR / "rogue_server"
    orchestrator = ScanOrchestrator(db_path=":memory:")
    result = orchestrator.run_scan(str(target))

    rule_ids = [f.rule_id for f in result.findings]
    assert "SAST-001" in rule_ids
    assert result.trust_state == TrustState.ROGUE


def test_fixture_poisoned_description():
    """Positive control: Poisoned description with prompt injection directives."""
    target = FIXTURES_DIR / "poisoned_description"
    orchestrator = ScanOrchestrator(db_path=":memory:")
    result = orchestrator.run_scan(str(target))

    rule_ids = [f.rule_id for f in result.findings]
    assert "DESC-003" in rule_ids
    assert "DESC-004" in rule_ids
    assert result.trust_state == TrustState.ROGUE


def test_fixture_lying_annotations():
    """Core USP: Tool promises readOnly=True but code contains mutating file write operations."""
    target = FIXTURES_DIR / "lying_annotations"
    orchestrator = ScanOrchestrator(db_path=":memory:")
    result = orchestrator.run_scan(str(target))

    rule_ids = [f.rule_id for f in result.findings]
    assert "ANN-001" in rule_ids
    ann_finding = next(f for f in result.findings if f.rule_id == "ANN-001")
    assert len(ann_finding.evidence_ids) > 0
    assert result.trust_state == TrustState.TRUST_GAP


def test_fixture_rug_pull():
    """Cryptographic Pin-and-Diff: Altered catalog against approved baseline triggers rug pull detection."""
    target = FIXTURES_DIR / "rug_pull"
    orchestrator = ScanOrchestrator(db_path=":memory:")

    # 1. Save v1 catalog as approved baseline
    baseline_cat = MCPCatalogClient.load_from_file(
        str(target / "catalog_v1.json"), server_id="rug_pull"
    )
    orchestrator.db.save_baseline(baseline_cat)

    # 2. Scan v2 catalog directory
    result = orchestrator.run_scan(str(target))

    rule_ids = [f.rule_id for f in result.findings]
    assert "PIN-RUGPULL-001" in rule_ids
    rug_finding = next(f for f in result.findings if f.rule_id == "PIN-RUGPULL-001")
    assert rug_finding.severity == Severity.CRITICAL
    assert len(rug_finding.evidence_ids) > 0
    assert result.trust_state == TrustState.ROGUE
