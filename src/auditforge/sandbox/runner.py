"""Docker Sandbox Runner for Isolated MCP Execution."""

from typing import List, Optional
from auditforge.core.contracts import ProbeCase, ProbeOutcome
from auditforge.core.errors import NotImplementedAuditError


class DockerSandboxRunner:
    """Executes MCP tools inside an ephemeral, resource-constrained Docker container."""

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

    def run_probe(self, case: ProbeCase) -> ProbeOutcome:
        """Run a single probe case inside Docker container and collect outcome and telemetry.
        
        Implementation assigned to workstream: feat/sandbox-prober-fixtures.
        """
        raise NotImplementedAuditError(
            "Docker sandbox runner is not yet implemented. "
            "Assigned to workstream: feat/sandbox-prober-fixtures."
        )
