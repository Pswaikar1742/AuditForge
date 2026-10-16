"""MCP Client for Catalog Discovery over stdio."""

import json
from pathlib import Path
from typing import List, Optional
from auditforge.catalog.normalize import normalize_tool_definition
from auditforge.core.contracts import ServerSnapshot, ToolRecord
from auditforge.core.errors import NotImplementedAuditError, MCPConnectionError


class MCPCatalogClient:
    """Client for discovering MCP tool catalogs from live servers or snapshots."""

    def __init__(self, command: Optional[List[str]] = None):
        self.command = command or []

    async def discover_live(self) -> ServerSnapshot:
        """Connect to live MCP server over stdio and query tools/list.
        
        Implementation assigned to workstream feat/mcp-catalog-pinning.
        """
        raise NotImplementedAuditError(
            "Live stdio MCP server discovery is not yet implemented. "
            "Assigned to workstream: feat/mcp-catalog-pinning."
        )

    @classmethod
    def load_from_file(cls, file_path: str, server_id: Optional[str] = None) -> ServerSnapshot:
        """Load catalog snapshot from a JSON file or directory containing catalog.json."""
        path = Path(file_path)
        if not path.exists():
            raise MCPConnectionError(f"Catalog path not found: {file_path}")

        if path.is_dir():
            found = None
            for cand in ["catalog.json", "catalog_v2.json", "catalog_v1.json"]:
                if (path / cand).exists():
                    found = path / cand
                    break
            if not found:
                jsons = list(path.glob("*.json"))
                if jsons:
                    found = jsons[0]
            if found:
                path = found
            else:
                raise MCPConnectionError(f"No catalog JSON found in directory: {file_path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        raw_tools = data.get("tools", [])
        tools_dict = {}

        if isinstance(raw_tools, list):
            for t in raw_tools:
                norm = normalize_tool_definition(t)
                tools_dict[norm.name] = norm
        elif isinstance(raw_tools, dict):
            for name, t in raw_tools.items():
                if isinstance(t, dict) and "name" not in t:
                    t["name"] = name
                norm = normalize_tool_definition(t)
                tools_dict[norm.name] = norm

        sid = server_id or data.get("server_id", path.stem)
        return ServerSnapshot(
            server_id=sid,
            tools=tools_dict,
        )
