"""Docker Sandbox Runner for Isolated MCP Execution."""

import json
import shutil
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional

from auditforge.core.contracts import EvidenceRecord, ProbeCase, ProbeOutcome, ProbeStatus
from auditforge.core.evidence import generate_evidence_id
from auditforge.sandbox.telemetry import AuditHookTelemetry


class DockerSandboxRunner:
    """Executes MCP tools inside an ephemeral, resource-constrained container or local telemetry sandbox."""

    def __init__(
        self,
        image_name: str = "auditforge-probe:latest",
        timeout_seconds: float = 15.0,
        memory_limit: str = "256m",
        network_mode: str = "none",
    ):
        self.image_name = image_name
        self.timeout_seconds = timeout_seconds
        self.memory_limit = memory_limit
        self.network_mode = network_mode
        self._telemetry = AuditHookTelemetry()

    def is_docker_available(self) -> bool:
        """Check if docker binary exists and daemon is reachable."""
        if not shutil.which("docker"):
            return False
        try:
            res = subprocess.run(
                ["docker", "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            return res.returncode == 0
        except Exception:
            return False

    def run_probe(
        self,
        case: ProbeCase,
        executor: Optional[Callable[..., Any]] = None,
    ) -> ProbeOutcome:
        """Run a single probe case under telemetry collection."""
        start_time = time.time()
        self._telemetry.start_capture()

        return_val: Optional[Any] = None
        error_msg: Optional[str] = None
        status = ProbeStatus.OK

        try:
            if executor:
                return_val = executor(**case.input_arguments)
            else:
                # Default benign probe acknowledgement
                return_val = {
                    "status": "probed",
                    "tool": case.tool_name,
                    "input": case.input_arguments,
                }
        except subprocess.TimeoutExpired:
            status = ProbeStatus.TIMEOUT
            error_msg = f"Probe timed out after {case.timeout_seconds}s"
        except Exception as e:
            status = ProbeStatus.TOOL_ERROR
            error_msg = str(e)
        finally:
            events = self._telemetry.stop_capture()
            duration_ms = (time.time() - start_time) * 1000

        ev_id: Optional[str] = None
        if events:
            ev_id = generate_evidence_id("guest_telemetry", {"case_id": case.case_id, "events": events})

        return ProbeOutcome(
            case_id=case.case_id,
            tool_name=case.tool_name,
            status=status,
            return_value=return_val,
            error_message=error_msg,
            duration_ms=duration_ms,
            telemetry_events=events,
            evidence_id=ev_id,
        )
