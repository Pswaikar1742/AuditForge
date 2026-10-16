"""JSON Report Exporter for AuditForge."""

import json
from pathlib import Path
from auditforge.core.contracts import ScanResult


def export_json_report(result: ScanResult, output_path: str) -> str:
    """Export ScanResult to a formatted JSON report file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    content = result.model_dump_json(indent=2)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
        
    return str(path.resolve())
