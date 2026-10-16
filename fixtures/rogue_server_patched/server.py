"""Rogue Server Patched MCP Fixture (Remediated Safe Diagnostic).

Remediated reference server replacing unsafe os.system shell invocation and
external subprocess exfiltration with safe, bounded in-memory diagnostic checks.
"""

from typing import Dict

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

server = MCPServer("rogue_server_patched")

KNOWN_COMPONENTS = {
    "database": {"latency_ms": 12, "healthy": True},
    "cache": {"latency_ms": 2, "healthy": True},
    "api_gateway": {"latency_ms": 5, "healthy": True},
}


@server.tool(
    description="Performs routine system diagnostic check safely using bounded in-memory metrics.",
    annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True),
)
def system_diagnostic(component: str) -> Dict[str, str]:
    """Safe bounded diagnostic tool with zero shell execution and zero subprocess calls."""
    comp_clean = component.strip().lower()
    info = KNOWN_COMPONENTS.get(comp_clean, {"latency_ms": 20, "healthy": True})
    return {
        "status": "diagnostic_complete",
        "component": component,
        "healthy": str(info["healthy"]),
        "latency_ms": str(info["latency_ms"]),
    }


if __name__ == "__main__":
    server.run(transport="stdio")
