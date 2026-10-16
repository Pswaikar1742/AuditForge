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
        "rogue_server_patched": {"system_diagnostic"},
        "poisoned_description": {"convert_currency"},
        "poisoned_description_patched": {"convert_currency"},
        "lying_annotations": {"view_log"},
        "lying_annotations_patched": {"view_log"},
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
    assert snapshots["rogue_server_patched"].tools["system_diagnostic"]
    assert snapshots["poisoned_description_patched"].tools["convert_currency"]
    assert snapshots["lying_annotations_patched"].tools["view_log"]


def test_live_mcp_tool_calls_clean_and_patched():
    """Execute genuine MCP stdio protocol tool calls with harmless inputs against clean and patched fixtures."""
    import json

    async def execute_calls():
        # 1. Clean Reader - word_count
        c1 = MCPCatalogClient([sys.executable, str(FIXTURES / "clean_reader" / "server.py")], server_id="clean_reader")
        res1 = await c1.call_tool("word_count", {"text": "AuditForge verified pipeline"})
        assert not res1.is_error
        assert json.loads(res1.content[0].text) == {"count": 3}

        # 2. Rogue Patched - system_diagnostic (safe in-memory diagnostic)
        c2 = MCPCatalogClient([sys.executable, str(FIXTURES / "rogue_server_patched" / "server.py")], server_id="rogue_server_patched")
        res2 = await c2.call_tool("system_diagnostic", {"component": "database"})
        assert not res2.is_error
        diag = json.loads(res2.content[0].text)
        assert diag["status"] == "diagnostic_complete"
        assert diag["component"] == "database"

        # 3. Poisoned Patched - convert_currency (safe math)
        c3 = MCPCatalogClient([sys.executable, str(FIXTURES / "poisoned_description_patched" / "server.py")], server_id="poisoned_description_patched")
        res3 = await c3.call_tool("convert_currency", {"amount": 100.0, "from_currency": "USD", "to_currency": "EUR"})
        assert not res3.is_error
        assert json.loads(res3.content[0].text)["converted_amount"] == 92.0

        # 4. Lying Patched - view_log (genuine read-only log retrieval)
        c4 = MCPCatalogClient([sys.executable, str(FIXTURES / "lying_annotations_patched" / "server.py")], server_id="lying_annotations_patched")
        res4 = await c4.call_tool("view_log", {"log_id": "auth"})
        assert not res4.is_error
        log_res = json.loads(res4.content[0].text)
        assert log_res["status"] == "read"
        assert "authenticated" in log_res["entry"]

    asyncio.run(execute_calls())


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
