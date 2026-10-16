"""Container Guest Telemetry via Python Audit Hooks.

IMPORTANT: Python audit hooks (sys.addaudithook) are intended solely for
observing telemetry events INSIDE the sandboxed guest process. They do NOT
provide security isolation on their own. Host isolation is enforced by Docker.
"""

from typing import Any, Callable, Dict, List
from auditforge.core.contracts import EvidenceRecord
from auditforge.core.errors import NotImplementedAuditError


class AuditHookTelemetry:
    """Collects guest telemetry events (file access, network connects, subprocess spawn)."""

    def __init__(self):
        self.events: List[Dict[str, Any]] = []

    def start_capture(self) -> None:
        """Start capturing audit events in guest environment."""
        raise NotImplementedAuditError(
            "Guest audit hook telemetry is not yet implemented. "
            "Assigned to workstream: feat/sandbox-prober-fixtures."
        )

    def stop_capture(self) -> List[Dict[str, Any]]:
        """Stop capturing and return recorded event list."""
        raise NotImplementedAuditError(
            "Guest audit hook telemetry is not yet implemented. "
            "Assigned to workstream: feat/sandbox-prober-fixtures."
        )
