"""MCP Client for Catalog Discovery over stdio."""

import asyncio
from contextlib import asynccontextmanager
import json

from mcp import ClientSession, StdioServerParameters, stdio_client, types
from pathlib import Path
from typing import List, Optional
from auditforge.catalog.normalize import normalize_tool_definition
from auditforge.core.contracts import ServerSnapshot, compute_catalog_fingerprint
from auditforge.core.errors import MCPConnectionError


class MCPCatalogClient:
    """Client for discovering MCP tool catalogs from live servers or snapshots."""

    def __init__(self, command: Optional[List[str]] = None, *, server_id=None,
                 timeout_seconds: float = 10.0):
        self.command = list(command or [])
        self.server_id = server_id or " ".join(self.command)
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.timeout_seconds = timeout_seconds

    @asynccontextmanager
    async def _session(self):
        """Launch the supplied transport command; callers must supply an isolated runtime.

        For untrusted targets use the sandbox worker's restricted Docker command.
        This transport adapter does not itself provide host isolation.
        """
        if not self.command:
            raise MCPConnectionError("A stdio server command is required")
        try:
            async with asyncio.timeout(self.timeout_seconds):
                params = StdioServerParameters(command=self.command[0], args=self.command[1:])
                async with stdio_client(params) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        yield session
        except Exception as exc:
            raise MCPConnectionError(f"MCP stdio operation failed: {exc}") from exc

    async def discover_live(self) -> ServerSnapshot:
        """Initialize a real MCP session and retrieve every tools/list page, resources, and prompts."""
        tools = {}
        cursors = set()
        cursor = None
        capabilities = {}
        resources_dict = {"status": "UNSUPPORTED", "items": []}
        prompts_dict = {"status": "UNSUPPORTED", "items": []}

        async with self._session() as session:
            # 1. Capture server info and capabilities if available
            try:
                server_info = getattr(session, "server_info", None)
                server_caps = getattr(session, "server_capabilities", None)
                if server_info:
                    capabilities["server_info"] = server_info.model_dump() if hasattr(server_info, "model_dump") else str(server_info)
                if server_caps:
                    capabilities["capabilities"] = server_caps.model_dump() if hasattr(server_caps, "model_dump") else str(server_caps)
            except Exception:
                pass

            # 2. Discover Tools (paginated)
            while True:
                page = await session.list_tools(
                    params=types.PaginatedRequestParams(cursor=cursor) if cursor else None
                )
                for raw in page.tools:
                    tool = normalize_tool_definition(raw)
                    if tool.name in tools:
                        raise MCPConnectionError(f"Duplicate tool name: {tool.name}")
                    tools[tool.name] = tool
                cursor = page.next_cursor
                if cursor is None:
                    break
                if not cursor or cursor in cursors:
                    raise MCPConnectionError("Invalid or repeated tools/list cursor")
                cursors.add(cursor)

            # 3. Discover Resources (distinguishing empty vs unsupported vs error)
            if hasattr(session, "list_resources"):
                try:
                    res_page = await session.list_resources()
                    res_items = []
                    for r in getattr(res_page, "resources", []):
                        r_data = r.model_dump() if hasattr(r, "model_dump") else (r if isinstance(r, dict) else str(r))
                        res_items.append(r_data)
                    resources_dict = {
                        "status": "OK" if res_items else "EMPTY",
                        "items": res_items,
                    }
                except Exception as e:
                    resources_dict = {
                        "status": "UNSUPPORTED" if "not supported" in str(e).lower() or "method not found" in str(e).lower() else "ERROR",
                        "error": str(e),
                        "items": [],
                    }

            # 4. Discover Prompts (distinguishing empty vs unsupported vs error)
            if hasattr(session, "list_prompts"):
                try:
                    prompt_page = await session.list_prompts()
                    prompt_items = []
                    for p in getattr(prompt_page, "prompts", []):
                        p_data = p.model_dump() if hasattr(p, "model_dump") else (p if isinstance(p, dict) else str(p))
                        prompt_items.append(p_data)
                    prompts_dict = {
                        "status": "OK" if prompt_items else "EMPTY",
                        "items": prompt_items,
                    }
                except Exception as e:
                    prompts_dict = {
                        "status": "UNSUPPORTED" if "not supported" in str(e).lower() or "method not found" in str(e).lower() else "ERROR",
                        "error": str(e),
                        "items": [],
                    }

        tools_fp = compute_catalog_fingerprint(tools)
        import hashlib
        from auditforge.core.contracts import canonical_json
        res_fp = hashlib.sha256(canonical_json(resources_dict).encode("utf-8")).hexdigest()
        prompts_fp = hashlib.sha256(canonical_json(prompts_dict).encode("utf-8")).hexdigest()

        return ServerSnapshot(
            server_id=self.server_id,
            tools=tools,
            resources=resources_dict,
            prompts=prompts_dict,
            capabilities=capabilities,
            tools_fingerprint=tools_fp,
            resources_fingerprint=res_fp,
            prompts_fingerprint=prompts_fp,
            catalog_fingerprint=tools_fp,
            fingerprint_version="v2",
        )

    async def call_tool(self, name: str, arguments: dict):
        """Make a real call in a fresh session and return the full SDK result.

        The transport command MUST run targets in a restricted container.
        Tool error results remain available to the caller as is_error=True.
        """
        async with self._session() as session:
            return await session.call_tool(name, arguments)

    @classmethod
    def load_from_file(cls, file_path: str, server_id: Optional[str] = None) -> ServerSnapshot:
        """Load catalog snapshot from a JSON file (used for fixtures and testing)."""
        path = Path(file_path)
        if path.is_dir():
            cat_candidate = path / "catalog.json"
            if cat_candidate.exists():
                path = cat_candidate
        if not path.exists():
            raise MCPConnectionError(f"Catalog file not found: {file_path}")

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
        resources_dict = data.get("resources", {"status": "EMPTY", "items": []})
        prompts_dict = data.get("prompts", {"status": "EMPTY", "items": []})
        capabilities = data.get("capabilities", {})
        
        tools_fp = compute_catalog_fingerprint(tools_dict)
        import hashlib
        from auditforge.core.contracts import canonical_json
        res_fp = hashlib.sha256(canonical_json(resources_dict).encode("utf-8")).hexdigest()
        prompts_fp = hashlib.sha256(canonical_json(prompts_dict).encode("utf-8")).hexdigest()

        fp_version = data.get("fingerprint_version", "v2" if ("resources" in data or "prompts" in data) else "v1")

        return ServerSnapshot(
            server_id=sid,
            tools=tools_dict,
            resources=resources_dict,
            prompts=prompts_dict,
            capabilities=capabilities,
            tools_fingerprint=tools_fp,
            resources_fingerprint=res_fp,
            prompts_fingerprint=prompts_fp,
            catalog_fingerprint=tools_fp,
            fingerprint_version=fp_version,
        )
