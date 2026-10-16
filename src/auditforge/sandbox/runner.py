"""Docker-backed guest runner for bounded fixture tool calls."""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import time
from pathlib import Path
from typing import Optional

from auditforge.core.contracts import ProbeCase, ProbeOutcome, ProbeStatus
from auditforge.sandbox.telemetry import AuditHookTelemetry


class DockerSandboxRunner:
    """Execute a Python fixture in an ephemeral, constrained Docker container."""

    def __init__(
        self,
        image_name: str = "auditforge-probe:latest",
        timeout_seconds: float = 15.0,
        memory_limit: str = "256m",
        network_mode: str = "none",
        server_path: Optional[str] = None,
    ):
        self.image_name = image_name
        self.timeout_seconds = timeout_seconds
        self.memory_limit = memory_limit
        self.network_mode = network_mode
        self.server_path = Path(server_path).resolve() if server_path else None

    def run_probe(self, case: ProbeCase) -> ProbeOutcome:
        started = time.monotonic()
        if self.server_path is None:
            return ProbeOutcome(case_id=case.case_id, tool_name=case.tool_name, status=ProbeStatus.SKIPPED,
                                error_message="server_path is required to run a probe")
        home = Path.home().resolve()
        if not self.server_path.is_file():
            return ProbeOutcome(case_id=case.case_id, tool_name=case.tool_name, status=ProbeStatus.SKIPPED,
                                error_message=f"Target source file does not exist: {self.server_path}")
        if self.server_path.parent == Path("/") or home == self.server_path.parent or home in self.server_path.parents:
            return ProbeOutcome(case_id=case.case_id, tool_name=case.tool_name, status=ProbeStatus.SKIPPED,
                                error_message="Refusing to mount filesystem root or a host home directory")
        command = [
            "docker", "run", "--rm",
            "--network", self.network_mode,
            "--memory", self.memory_limit,
            "--cpus", "0.5",
            "--pids-limit", "64",
            "--read-only",
            "--security-opt", "no-new-privileges:true",
            "--cap-drop", "ALL",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--user", "1000:1000",
            "-v", f"{self.server_path.parent}:/target:ro",
            self.image_name,
            "--guest",
            "--server-path", f"/target/{self.server_path.name}",
            "--case-json", case.model_dump_json(),
        ]
        budget = min(self.timeout_seconds, case.timeout_seconds)
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=budget, check=False)
        except subprocess.TimeoutExpired:
            return ProbeOutcome(case_id=case.case_id, tool_name=case.tool_name, status=ProbeStatus.TIMEOUT,
                                error_message=f"Probe exceeded {budget:.2f}s", duration_ms=(time.monotonic() - started) * 1000)
        except OSError as exc:
            return ProbeOutcome(case_id=case.case_id, tool_name=case.tool_name, status=ProbeStatus.SKIPPED,
                                error_message=f"Docker unavailable: {exc}", duration_ms=(time.monotonic() - started) * 1000)
        try:
            payload = json.loads(completed.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            payload = {"status": "TOOL_ERROR", "error_message": completed.stderr.strip() or "Invalid guest response"}
        value = payload.get("status", "UNKNOWN")
        status = ProbeStatus(value) if value in ProbeStatus._value2member_map_ else ProbeStatus.UNKNOWN
        return ProbeOutcome(case_id=case.case_id, tool_name=case.tool_name, status=status,
                            return_value=payload.get("return_value"), error_message=payload.get("error_message"),
                            duration_ms=(time.monotonic() - started) * 1000,
                            telemetry_events=payload.get("telemetry_events", []))


def _guest(server_path: str, case_json: str) -> int:
    """Execute target tool inside container via MCP protocol (tools/call) while capturing telemetry."""
    import asyncio
    from mcp.server.mcpserver import MCPServer

    case = ProbeCase.model_validate_json(case_json)
    telemetry = AuditHookTelemetry()
    telemetry.start_capture()
    try:
        spec = importlib.util.spec_from_file_location("auditforge_guest_target", server_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("Could not load target module")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Locate existing MCPServer instance in module or construct protocol wrapper
        mcp_server = None
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, MCPServer):
                mcp_server = attr
                break

        if mcp_server is None:
            tool_fn = getattr(module, case.tool_name, None)
            if tool_fn is None:
                raise AttributeError(f"Module has no tool function '{case.tool_name}'")
            mcp_server = MCPServer("guest_protocol_runner")
            mcp_server.tool()(tool_fn)

        async def _call():
            return await mcp_server.call_tool(case.tool_name, case.input_arguments)

        mcp_res = asyncio.run(_call())
        is_err = getattr(mcp_res, "is_error", False)
        content = getattr(mcp_res, "content", [])
        text_content = [getattr(c, "text", str(c)) for c in content]
        val = text_content[0] if len(text_content) == 1 else text_content
        result = {
            "status": "TOOL_ERROR" if is_err else "OK",
            "return_value": val,
            "error_message": val if is_err else None,
            "protocol": "MCP/tools_call",
        }
    except Exception as exc:
        result = {"status": "TOOL_ERROR", "error_message": f"{type(exc).__name__}: {exc}"}
    result["telemetry_events"] = telemetry.stop_capture()
    print(json.dumps(result, default=str), flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--guest", action="store_true")
    parser.add_argument("--server-path")
    parser.add_argument("--case-json")
    args = parser.parse_args()
    if not args.guest:
        parser.error("runner must be invoked by DockerSandboxRunner with --guest")
    return _guest(args.server_path, args.case_json)


if __name__ == "__main__":
    raise SystemExit(main())
