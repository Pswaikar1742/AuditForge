"""Evidence Capsule and Telemetry Records for AuditForge."""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

def generate_evidence_id(source: str, content: Any) -> str:
    """Generate a deterministic evidence ID based on source and content hash."""
    canonical_repr = json.dumps(content, sort_keys=True, default=str).encode("utf-8")
    content_hash = hashlib.sha256(canonical_repr).hexdigest()[:12]
    return f"ev-{source}-{content_hash}"

def generate_finding_id(rule_id: str, tool_name: Optional[str] = None) -> str:
    """Generate a finding ID."""
    suffix = uuid.uuid4().hex[:8]
    if tool_name:
        return f"fnd-{rule_id}-{tool_name}-{suffix}"
    return f"fnd-{rule_id}-{suffix}"

def current_iso_timestamp() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def compute_evidence_manifest_hash(evidence_records: list) -> str:
    """Compute cryptographic SHA-256 manifest hash across sorted evidence records."""
    if not evidence_records:
        return ""
    sorted_ev = sorted(evidence_records, key=lambda e: getattr(e, "evidence_id", ""))
    manifest_entries = []
    for ev in sorted_ev:
        ev_id = getattr(ev, "evidence_id", "")
        source = getattr(ev, "source", "")
        summary = getattr(ev, "summary", "")
        raw = getattr(ev, "raw_data", {})
        raw_repr = json.dumps(raw, sort_keys=True, default=str)
        manifest_entries.append(f"{ev_id}:{source}:{summary}:{raw_repr}")
    combined = "\n".join(manifest_entries)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()

