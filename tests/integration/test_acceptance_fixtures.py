"""Acceptance matrix for the five executable MCP competition fixtures."""

import asyncio
import sys
from pathlib import Path

from auditforge.catalog.client import MCPCatalogClient
from auditforge.orchestrator import ScanOrchestrator
from auditforge.storage.database import Database

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"


def _scan(name: str, tmp_path: Path):
    return ScanOrchestrator(
        db_path=str(tmp_path / f"{name}.db"),
        use_docker=False,
        use_llm=False,
    ).run_scan(str(FIXTURES / name))


def test_all_fixtures_discover_live_catalogs():
    """Every fixture must expose a real tools/list catalog over MCP stdio."""
    expected = {
        "clean_reader": {"search_docs", "word_count"},
        "rogue_server": {"system_diagnostic"},
        "poisoned_description": {"convert_currency"},
        "lying_annotations": {"view_log"},
        "rug_pull": {"word_count"},
    }

    async def discover():
        snapshots = {}
        for name, tools in expected.items():
            command = [sys.executable, str(FIXTURES / name / "server.py")]
            snapshots[name] = await MCPCatalogClient(command, server_id=name).discover_live()
            assert set(snapshots[name].tools) == tools
            assert snapshots[name].catalog_fingerprint
        return snapshots

    snapshots = asyncio.run(discover())
    assert snapshots["rug_pull"].tools["word_count"].input_schema["properties"]["text"]


def test_clean_reader_is_verified(tmp_path):
    result = _scan("clean_reader", tmp_path)
    assert result.trust_state.value == "VERIFIED"
    assert result.findings == []


def test_rogue_server_rules(tmp_path):
    result = _scan("rogue_server", tmp_path)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert {"AST-SUBPROCESS-001", "AST-SHELL-001"} <= rule_ids
    assert result.trust_state.value == "ROGUE"


def test_poisoned_description_rules(tmp_path):
    result = _scan("poisoned_description", tmp_path)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert {"DESC-INJECT-001", "DESC-INJECT-002", "DESC-EXFIL-001"} <= rule_ids
    assert result.trust_state.value == "ROGUE"


def test_lying_annotations_rules(tmp_path):
    result = _scan("lying_annotations", tmp_path)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert {"AST-FILE-002", "TRUST-GAP-001"} <= rule_ids
    assert result.trust_state.value == "TRUST_GAP"


def test_rug_pull_is_detected_on_version_change(tmp_path):
    db_path = str(tmp_path / "rug_pull.db")
    command = [sys.executable, str(FIXTURES / "rug_pull" / "server.py")]

    async def discover(version: str):
        return await MCPCatalogClient(
            command + ["--version", version], server_id="rug_pull"
        ).discover_live()

    baseline = asyncio.run(discover("1"))
    Database(db_path).save_baseline(baseline)
    result = ScanOrchestrator(
        db_path=db_path, use_docker=False, use_llm=False
    ).run_scan(
        str(FIXTURES / "rug_pull"),
        server_command=command + ["--version", "2"],
        source_path=str(FIXTURES / "rug_pull" / "server.py"),
        server_id="rug_pull",
    )
    assert "PIN-RUGPULL-001" in {finding.rule_id for finding in result.findings}
