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
