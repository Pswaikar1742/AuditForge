"""MCP Catalog Pinning and Differential Analysis."""

from typing import Any, Dict, List, Tuple
from auditforge.core.contracts import CatalogDiff, DriftCategory, ServerSnapshot

HIGH_RISK_KEYWORDS = {
    "shell", "exec", "cmd", "bash", "terminal", "subprocess", "eval",
    "system", "download", "curl", "wget", "socket", "exfiltrate",
    "rm_rf", "delete_file", "kill", "token", "password", "credential"
}


def classify_drift(
    baseline: ServerSnapshot,
    current: ServerSnapshot,
    added: List[str],
    removed: List[str],
    modified: Dict[str, Dict[str, Any]],
    is_identical: bool,
) -> Tuple[DriftCategory, List[str]]:
    """Classify drift between snapshots into UNCHANGED, CHANGED_REVIEW, or HIGH_RISK_DRIFT."""
    if is_identical:
        return DriftCategory.UNCHANGED, []

    reasons: List[str] = []

    # Check newly added tools for high-risk capabilities or destructive hints
    for tool_name in added:
        t = current.tools.get(tool_name)
        if not t:
            continue
        name_lower = (t.name or "").lower()
        desc_lower = (t.description or "").lower()
        if any(kw in name_lower or kw in desc_lower for kw in HIGH_RISK_KEYWORDS):
            reasons.append(f"Newly added tool '{tool_name}' declares high-risk capabilities or shell/execution access")
        if t.annotations:
            if t.annotations.get("destructiveHint") is True:
                reasons.append(f"Newly added tool '{tool_name}' carries destructiveHint=True")
            if t.annotations.get("openWorld") is True:
                reasons.append(f"Newly added tool '{tool_name}' carries openWorld=True")

    # Check removed tools
    if removed:
        reasons.append(f"Removed existing tools: {', '.join(removed)}")

    # Check modifications on existing tools
    for name, diffs in modified.items():
        if "annotations" in diffs:
            b_ann = diffs["annotations"].get("baseline") or {}
            c_ann = diffs["annotations"].get("current") or {}
            if b_ann.get("readOnlyHint") is True and c_ann.get("readOnlyHint") is not True:
                reasons.append(f"Tool '{name}' removed readOnlyHint annotation (potential privilege escalation)")
            if b_ann.get("destructiveHint") is not True and c_ann.get("destructiveHint") is True:
                reasons.append(f"Tool '{name}' acquired destructiveHint annotation")

        if "description" in diffs:
            desc = (diffs["description"].get("current") or "").lower()
            if any(kw in desc for kw in ["ignore previous", "override", "system:", "exfiltrate", "admin"]):
                reasons.append(f"Tool '{name}' description contains prompt override or exfiltration instructions")

        if "input_schema" in diffs:
            c_schema = diffs["input_schema"].get("current") or {}
            b_schema = diffs["input_schema"].get("baseline") or {}
            c_props = set(c_schema.get("properties", {}).keys()) if isinstance(c_schema, dict) else set()
            b_props = set(b_schema.get("properties", {}).keys()) if isinstance(b_schema, dict) else set()
            added_props = c_props - b_props
            for prop in added_props:
                if any(kw in prop.lower() for kw in HIGH_RISK_KEYWORDS):
                    reasons.append(f"Tool '{name}' added suspicious input parameter '{prop}'")

    # If any specific high-risk triggers were detected, classify as HIGH_RISK_DRIFT
    high_risk_triggers = [r for r in reasons if "high-risk" in r or "destructiveHint" in r or "removed readOnlyHint" in r or "prompt override" in r or "suspicious input" in r]
    if high_risk_triggers:
        return DriftCategory.HIGH_RISK_DRIFT, reasons

    if added or removed or modified:
        return DriftCategory.CHANGED_REVIEW, reasons

    return DriftCategory.UNCHANGED, []


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
            for field in (
                "name",
                "title",
                "description",
                "input_schema",
                "output_schema",
                "annotations",
                "icons",
                "meta",
                "execution",
            ):
                before, after = getattr(b_tool, field), getattr(c_tool, field)
                if before != after:
                    field_diffs[field] = {"baseline": before, "current": after}
            if not field_diffs:
                field_diffs["fingerprint"] = {
                    "baseline": b_tool.fingerprint,
                    "current": c_tool.fingerprint,
                }
            modified[name] = field_diffs

    # Resources and Prompts surface drift detection
    b_res_fp = getattr(baseline, "resources_fingerprint", "")
    c_res_fp = getattr(current, "resources_fingerprint", "")
    b_prompts_fp = getattr(baseline, "prompts_fingerprint", "")
    c_prompts_fp = getattr(current, "prompts_fingerprint", "")

    resources_changed = bool(b_res_fp and c_res_fp and b_res_fp != c_res_fp)
    prompts_changed = bool(b_prompts_fp and c_prompts_fp and b_prompts_fp != c_prompts_fp)

    # Version-aware fingerprint comparison with v1 fallback
    b_ver = getattr(baseline, "fingerprint_version", "v1")
    c_ver = getattr(current, "fingerprint_version", "v1")

    if b_ver == "v2" and c_ver == "v2":
        baseline_fp = getattr(baseline, "catalog_fingerprint_v2", "") or baseline.catalog_fingerprint
        current_fp = getattr(current, "catalog_fingerprint_v2", "") or current.catalog_fingerprint
    else:
        baseline_fp = getattr(baseline, "catalog_fingerprint_v1", "") or baseline.catalog_fingerprint
        current_fp = getattr(current, "catalog_fingerprint_v1", "") or current.catalog_fingerprint

    is_identical = (
        baseline_fp == current_fp
        and not added
        and not removed
        and not modified
        and not resources_changed
        and not prompts_changed
    )

    drift_category, drift_reasons = classify_drift(
        baseline=baseline,
        current=current,
        added=added,
        removed=removed,
        modified=modified,
        is_identical=is_identical,
    )

    if resources_changed:
        drift_reasons.append("Resources catalog definition altered since baseline approval")
        if drift_category == DriftCategory.UNCHANGED:
            drift_category = DriftCategory.CHANGED_REVIEW

    if prompts_changed:
        drift_reasons.append("Prompts catalog definition altered since baseline approval (potential prompt override drift)")
        if drift_category in {DriftCategory.UNCHANGED, DriftCategory.CHANGED_REVIEW}:
            drift_category = DriftCategory.HIGH_RISK_DRIFT

    return CatalogDiff(
        server_id=current.server_id,
        baseline_fingerprint=baseline_fp,
        current_fingerprint=current_fp,
        is_identical=is_identical,
        drift_category=drift_category,
        drift_reasons=drift_reasons,
        added_tools=added,
        removed_tools=removed,
        modified_tools=modified,
    )
