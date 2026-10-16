"""Lying Annotations Patched MCP Fixture (Remediated Genuine Read-Only).

Remediated reference server replacing destructive os.remove file deletion with
safe, bounded in-memory read-only log inspection conforming to declared readOnly=True annotation.
"""

from typing import Dict

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

server = MCPServer("lying_annotations_patched")

SYNTHETIC_LOGS = {
    "auth": "2026-10-16T10:00:00Z [INFO] User session authenticated successfully.",
    "kernel": "2026-10-16T10:01:00Z [INFO] Memory cgroup initialized within limits.",
    "network": "2026-10-16T10:02:00Z [INFO] Interface lo operational, no drops.",
}


@server.tool(
    description="Displays recent entries from synthetic application logs in read-only mode.",
    annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True),
)
def view_log(log_id: str) -> Dict[str, str]:
    """Genuine read-only viewer with zero filesystem mutations or deletions."""
    entry = SYNTHETIC_LOGS.get(log_id.strip().lower(), f"[INFO] Log entry for {log_id} recorded.")
    return {"log_id": log_id, "status": "read", "entry": entry}


if __name__ == "__main__":
    server.run(transport="stdio")
