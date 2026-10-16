"""Container Guest Telemetry via Python Audit Hooks.

IMPORTANT: Python audit hooks (sys.addaudithook) are intended solely for
observing telemetry events INSIDE the sandboxed guest process. They do NOT
provide security isolation on their own. Host isolation is enforced by Docker.
"""

from typing import Any, Callable, Dict, List
import sys


class AuditHookTelemetry:
    """Collects guest telemetry events (file access, network connects, subprocess spawn)."""

    def __init__(self):
        self.events: List[Dict[str, Any]] = []

    def start_capture(self) -> None:
        """Start capturing audit events in guest environment."""
        def hook(event: str, args: tuple) -> None:
            if event in {"open", "socket.connect", "subprocess.Popen"}:
                self.events.append({"event": event, "args": [repr(value)[:500] for value in args]})
        sys.addaudithook(hook)

    def stop_capture(self) -> List[Dict[str, Any]]:
        """Stop capturing and return recorded event list."""
        return list(self.events)
