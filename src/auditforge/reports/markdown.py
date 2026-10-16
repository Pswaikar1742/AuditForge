"""Markdown Report Generator for AuditForge."""

from pathlib import Path
from typing import Optional
from auditforge.core.contracts import ScanResult, Severity


def generate_markdown_report(result: ScanResult, output_path: Optional[str] = None) -> str:
    """Generate a clean, structured Markdown security report from a ScanResult."""
    critical_count = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in result.findings if f.severity == Severity.HIGH)
    medium_count = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
    low_count = sum(1 for f in result.findings if f.severity == Severity.LOW)
    info_count = sum(1 for f in result.findings if f.severity == Severity.INFO)

    lines = [
        f"# 🛡️ AuditForge Security Audit Report",
        f"",
        f"**Target:** `{result.target}`  ",
        f"**Scan ID:** `{result.scan_id}`  ",
        f"**Started At:** `{result.started_at}`  ",
        f"**Completed At:** `{result.completed_at or 'In Progress'}`  ",
        f"**Trust State:** **`{result.trust_state.value}`**  ",
        f"",
        f"## 📊 Executive Summary",
        f"",
        f"{result.summary or 'Automated audit performed by AuditForge.'}",
        f"",
        f"| Severity | Count |",
        f"| :--- | :--- |",
        f"| 🚨 CRITICAL | {critical_count} |",
        f"| ⚠️ HIGH | {high_count} |",
        f"| 🟡 MEDIUM | {medium_count} |",
        f"| ℹ️ LOW | {low_count} |",
        f"| 📝 INFO | {info_count} |",
        f"| **Total Findings** | **{len(result.findings)}** |",
        f"",
    ]

    if result.snapshot:
        lines.extend([
            f"## 📦 Discovered Tools Catalog",
            f"",
            f"**Catalog Fingerprint (SHA-256):** `{result.snapshot.catalog_fingerprint}`  ",
            f"**Total Tools:** `{len(result.snapshot.tools)}`  ",
            f"",
            f"| Tool Name | Fingerprint | Description |",
            f"| :--- | :--- | :--- |",
        ])
        for name, tool in sorted(result.snapshot.tools.items()):
            desc = (tool.description or "").replace("\n", " ")[:60]
            lines.append(f"| `{name}` | `{tool.fingerprint[:12]}...` | {desc} |")
        lines.append("")

    if result.diff:
        lines.extend([
            f"## 🔍 Catalog Pinning & Differential Analysis",
            f"",
            f"**Baseline Hash:** `{result.diff.baseline_fingerprint}`  ",
            f"**Current Hash:** `{result.diff.current_fingerprint}`  ",
            f"**Identical:** `{'YES' if result.diff.is_identical else 'NO (CHANGES DETECTED)'}`  ",
            f"",
        ])
        if result.diff.added_tools:
            lines.append(f"- **Added Tools:** {', '.join(f'`{t}`' for t in result.diff.added_tools)}")
        if result.diff.removed_tools:
            lines.append(f"- **Removed Tools:** {', '.join(f'`{t}`' for t in result.diff.removed_tools)}")
        if result.diff.modified_tools:
            lines.append(f"- **Modified Tools:** {', '.join(f'`{t}`' for t in result.diff.modified_tools.keys())}")
        lines.append("")

    lines.extend([
        f"## 🚨 Findings Details",
        f"",
    ])

    if not result.findings:
        lines.append("_No security findings recorded._\n")
    else:
        for idx, f in enumerate(result.findings, 1):
            tool_str = f" on `{f.tool_name}`" if f.tool_name else ""
            lines.extend([
                f"### {idx}. [{f.severity.value}] {f.rule_id}{tool_str}",
                f"",
                f"- **Finding ID:** `{f.id}`",
                f"- **Confidence:** `{f.confidence:.2f}`",
                f"- **Reason:** {f.reason}",
                f"- **Remediation:** {f.remediation}",
                f"- **Evidence References:** {', '.join(f'`{e}`' for e in f.evidence_ids) if f.evidence_ids else 'None'}",
                f"",
            ])

    md_content = "\n".join(lines)

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(md_content)

    return md_content
