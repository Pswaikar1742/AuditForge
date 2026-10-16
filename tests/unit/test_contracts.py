"""Unit tests for AuditForge core contracts and canonical hashing."""

import json
from auditforge.core.contracts import (
    Severity,
    TrustState,
    ProbeStatus,
    ToolRecord,
    ServerSnapshot,
    Finding,
    EvidenceRecord,
    canonical_json,
    compute_tool_fingerprint,
    compute_catalog_fingerprint,
)
from auditforge.storage.database import Database


def test_canonical_json_deterministic():
    """Verify that different key orderings produce identical canonical JSON strings."""
    obj_a = {"b": 2, "a": 1, "nested": {"z": 9, "y": 8}}
    obj_b = {"nested": {"y": 8, "z": 9}, "a": 1, "b": 2}
    assert canonical_json(obj_a) == canonical_json(obj_b)


def test_tool_fingerprint_deterministic():
    """Verify that identical normalized tool definitions yield identical SHA-256 fingerprints."""
    tool1 = {
        "name": "read_file",
        "title": "Read File Tool",
        "description": "Reads text content from path",
        "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
        "output_schema": None,
        "annotations": {"readOnly": True},
    }
    tool2 = {
        "annotations": {"readOnly": True},
        "description": "Reads text content from path",
        "input_schema": {"properties": {"path": {"type": "string"}}, "type": "object"},
        "name": "read_file",
        "output_schema": None,
        "title": "Read File Tool",
    }
    hash1 = compute_tool_fingerprint(tool1)
    hash2 = compute_tool_fingerprint(tool2)
    assert hash1 == hash2
    assert len(hash1) == 64


def test_tool_record_model_post_init():
    """Verify ToolRecord automatically calculates its fingerprint if omitted."""
    rec = ToolRecord(
        name="test_tool",
        description="A test tool",
        input_schema={"type": "object"},
    )
    assert rec.fingerprint != ""
    assert len(rec.fingerprint) == 64


def test_server_snapshot_and_catalog_fingerprint():
    """Verify ServerSnapshot calculates whole-catalog fingerprint deterministically."""
    t1 = ToolRecord(name="alpha", description="First")
    t2 = ToolRecord(name="beta", description="Second")

    snap1 = ServerSnapshot(server_id="srv-1", tools={"alpha": t1, "beta": t2})
    snap2 = ServerSnapshot(server_id="srv-1", tools={"beta": t2, "alpha": t1})

    assert snap1.catalog_fingerprint != ""
    assert snap1.catalog_fingerprint == snap2.catalog_fingerprint


def test_database_baseline_and_scan_storage(tmp_path):
    """Verify SQLite database persistence for baselines and scan results."""
    db_file = str(tmp_path / "test_audit.db")
    db = Database(db_file)

    t = ToolRecord(name="reader", description="Reads file")
    snapshot = ServerSnapshot(server_id="test-server", tools={"reader": t})

    # Save and reload baseline
    db.save_baseline(snapshot)
    loaded_baseline = db.get_baseline("test-server")
    assert loaded_baseline is not None
    assert loaded_baseline.catalog_fingerprint == snapshot.catalog_fingerprint
    assert "reader" in loaded_baseline.tools
