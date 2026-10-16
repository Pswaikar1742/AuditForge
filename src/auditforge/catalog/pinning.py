"""MCP Catalog Pinning and Differential Analysis."""

from typing import Any, Dict
from auditforge.core.contracts import CatalogDiff, ServerSnapshot


def diff_catalogs(baseline: ServerSnapshot, current: ServerSnapshot) -> CatalogDiff:
    """Compare baseline snapshot with current snapshot to detect tool changes and rug pulls."""
    baseline_tools = baseline.tools
    current_tools = current.tools

    baseline_names = set(baseline_tools.keys())
    current_names = set(current_tools.keys())

    added = sorted(list(current_names - baseline_names))
    removed = sorted(list(baseline_names - current_names))
    modified: Dict[str, Dict[str, Any]] = {}

    common_names = baseline_names & current_names
    for name in sorted(common_names):
        b_tool = baseline_tools[name]
        c_tool = current_tools[name]

        if b_tool.fingerprint != c_tool.fingerprint:
            field_diffs: Dict[str, Any] = {}
            for field in ("name", "title", "description", "input_schema", "output_schema", "annotations"):
                before, after = getattr(b_tool, field), getattr(c_tool, field)
                if before != after:
                    field_diffs[field] = {"baseline": before, "current": after}
            if not field_diffs:
                field_diffs["fingerprint"] = {
                    "baseline": b_tool.fingerprint,
                    "current": c_tool.fingerprint,
                }
            modified[name] = field_diffs

    is_identical = (
        baseline.catalog_fingerprint == current.catalog_fingerprint
        and not added
        and not removed
        and not modified
    )

    return CatalogDiff(
        server_id=current.server_id,
        baseline_fingerprint=baseline.catalog_fingerprint,
        current_fingerprint=current.catalog_fingerprint,
        is_identical=is_identical,
        added_tools=added,
        removed_tools=removed,
        modified_tools=modified,
    )
