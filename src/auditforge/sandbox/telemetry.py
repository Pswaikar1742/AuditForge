"""Container Guest Telemetry via Python Audit Hooks.

IMPORTANT: Python audit hooks (sys.addaudithook) are intended solely for
observing telemetry events INSIDE the sandboxed guest process. They do NOT
provide security isolation on their own. Host isolation is enforced by Docker.
"""

import sys
from typing import Any, Dict, List, Optional

SECURITY_EVENTS = {
    "open",
    "os.system",
    "os.popen",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "subprocess.Popen",
    "socket.connect",
    "socket.getaddrinfo",
    "socket.bind",
    "urllib.request",
    "exec",
    "compile",
}


class AuditHookTelemetry:
    """Collects guest telemetry events (file access, network connects, subprocess spawn)."""

    _hook_installed: bool = False
    _active_instance: Optional["AuditHookTelemetry"] = None

    def __init__(self):
        self.events: List[Dict[str, Any]] = []
        self._is_capturing: bool = False
        self._ensure_hook()

    @classmethod
    def _ensure_hook(cls) -> None:
        if not cls._hook_installed:
            try:
                sys.addaudithook(cls._global_hook)
                cls._hook_installed = True
            except Exception:
                pass

    @classmethod
    def _global_hook(cls, event_name: str, args: tuple) -> None:
        if cls._active_instance and cls._active_instance._is_capturing:
            if event_name in SECURITY_EVENTS:
                str_args = [str(a) for a in args]
                # Filter internal framework files
                if any("auditforge" in s or "site-packages" in s for s in str_args):
                    return

                actual_event = event_name
                if event_name == "open" and len(args) >= 2:
                    mode = str(args[1])
                    if any(m in mode for m in ("w", "a", "+", "x")):
                        actual_event = "open_for_write"
                elif event_name in ("os.remove", "os.unlink", "os.rmdir"):
                    actual_event = "open_for_write"

                cls._active_instance.events.append({
                    "event": actual_event,
                    "args": str_args,
                })

    def start_capture(self) -> None:
        """Start capturing audit events."""
        self.events = []
        self._is_capturing = True
        AuditHookTelemetry._active_instance = self

    def stop_capture(self) -> List[Dict[str, Any]]:
        """Stop capturing and return recorded event list."""
        self._is_capturing = False
        captured = list(self.events)
        self.events = []
        if AuditHookTelemetry._active_instance is self:
            AuditHookTelemetry._active_instance = None
        return captured
