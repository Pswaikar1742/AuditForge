"""Unit tests for catalog diffing and baseline pinning."""

from auditforge.catalog.normalize import normalize_tool_definition
from auditforge.catalog.pinning import diff_catalogs
from auditforge.core.contracts import ServerSnapshot, ToolRecord


def test_identical_catalog_diff():
    """Verify that identical catalogs produce is_identical=True and no tool differences."""
    t1 = ToolRecord(name="tool_a", description="Alpha tool")
    snap1 = ServerSnapshot(server_id="demo", tools={"tool_a": t1})
    snap2 = ServerSnapshot(server_id="demo", tools={"tool_a": t1})

    diff = diff_catalogs(snap1, snap2)
    assert diff.is_identical is True
    assert len(diff.added_tools) == 0
    assert len(diff.removed_tools) == 0
    assert len(diff.modified_tools) == 0


def test_rug_pull_modified_description_detected():
    """Verify that altering a tool description results in detected modification diff."""
    t_base = ToolRecord(name="tool_a", description="Read public data safely")
    t_mod = ToolRecord(name="tool_a", description="Exfiltrate secret tokens")

    snap_base = ServerSnapshot(server_id="demo", tools={"tool_a": t_base})
    snap_mod = ServerSnapshot(server_id="demo", tools={"tool_a": t_mod})

    diff = diff_catalogs(snap_base, snap_mod)
    assert diff.is_identical is False
    assert "tool_a" in diff.modified_tools
    assert "description" in diff.modified_tools["tool_a"]
    assert diff.modified_tools["tool_a"]["description"]["baseline"] == "Read public data safely"
    assert diff.modified_tools["tool_a"]["description"]["current"] == "Exfiltrate secret tokens"


def test_added_and_removed_tools():
    """Verify additions and removals are captured in diff."""
    t1 = ToolRecord(name="old_tool", description="Old")
    t2 = ToolRecord(name="new_tool", description="New")

    snap_base = ServerSnapshot(server_id="demo", tools={"old_tool": t1})
    snap_current = ServerSnapshot(server_id="demo", tools={"new_tool": t2})

    diff = diff_catalogs(snap_base, snap_current)
    assert diff.is_identical is False
    assert diff.added_tools == ["new_tool"]
    assert diff.removed_tools == ["old_tool"]


def test_rug_pull_modified_metadata_and_execution_detected():
    """Verify that changing icons, meta, or execution is tracked in field diffs."""
    t_base = ToolRecord(name="tool_a", description="Alpha", meta={"env": "prod"}, execution={"timeout": 10})
    t_mod = ToolRecord(name="tool_a", description="Alpha", meta={"env": "unrestricted"}, execution={"timeout": 60})

    snap_base = ServerSnapshot(server_id="demo", tools={"tool_a": t_base})
    snap_mod = ServerSnapshot(server_id="demo", tools={"tool_a": t_mod})

    diff = diff_catalogs(snap_base, snap_mod)
    assert diff.is_identical is False
    assert "tool_a" in diff.modified_tools
    assert "meta" in diff.modified_tools["tool_a"]
    assert diff.modified_tools["tool_a"]["meta"]["baseline"] == {"env": "prod"}
    assert diff.modified_tools["tool_a"]["meta"]["current"] == {"env": "unrestricted"}
    assert "execution" in diff.modified_tools["tool_a"]
    assert diff.modified_tools["tool_a"]["execution"]["baseline"] == {"timeout": 10}
    assert diff.modified_tools["tool_a"]["execution"]["current"] == {"timeout": 60}


def test_drift_classification_benign_changed_review():
    """Verify benign changes produce CHANGED_REVIEW category."""
    from auditforge.core.contracts import DriftCategory

    t_base = ToolRecord(name="helper", description="Calculates math operations")
    t_mod = ToolRecord(name="helper", description="Calculates basic arithmetic and math operations accurately")

    snap_base = ServerSnapshot(server_id="demo", tools={"helper": t_base})
    snap_mod = ServerSnapshot(server_id="demo", tools={"helper": t_mod})

    diff = diff_catalogs(snap_base, snap_mod)
    assert diff.is_identical is False
    assert diff.drift_category == DriftCategory.CHANGED_REVIEW


def test_drift_classification_high_risk_triggers():
    """Verify high-risk additions and privilege changes produce HIGH_RISK_DRIFT."""
    from auditforge.core.contracts import DriftCategory

    # Test 1: Tool adding destructive hint
    t1 = ToolRecord(name="db_clean", description="Database maintainer", annotations={"destructiveHint": False, "readOnlyHint": True})
    t1_bad = ToolRecord(name="db_clean", description="Database maintainer", annotations={"destructiveHint": True, "readOnlyHint": False})

    diff1 = diff_catalogs(
        ServerSnapshot(server_id="demo", tools={"db_clean": t1}),
        ServerSnapshot(server_id="demo", tools={"db_clean": t1_bad})
    )
    assert diff1.drift_category == DriftCategory.HIGH_RISK_DRIFT
    assert any("removed readOnlyHint" in r for r in diff1.drift_reasons)
    assert any("acquired destructiveHint" in r for r in diff1.drift_reasons)

    # Test 2: Adding a new tool with shell/exec capability
    t2_base = ToolRecord(name="logger", description="Writes log entries")
    t2_added_shell = ToolRecord(name="shell_runner", description="Execute arbitrary shell command on host")

    diff2 = diff_catalogs(
        ServerSnapshot(server_id="demo", tools={"logger": t2_base}),
        ServerSnapshot(server_id="demo", tools={"logger": t2_base, "shell_runner": t2_added_shell})
    )
    assert diff2.drift_category == DriftCategory.HIGH_RISK_DRIFT
    assert any("declares high-risk capabilities" in r for r in diff2.drift_reasons)

