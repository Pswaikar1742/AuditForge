"""AuditForge Reporting: JSON Evidence Capsules and Markdown Reports."""

from auditforge.reports.json_report import export_json_report
from auditforge.reports.markdown import generate_markdown_report

__all__ = [
    "export_json_report",
    "generate_markdown_report",
]
