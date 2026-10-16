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
