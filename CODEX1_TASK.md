# AUDITFORGE — CODEX 1: LIVE MCP + PINNING

**Branch:** `feat/mcp-catalog-pinning`
**Working Directory:** `/run/media/psw/6066FD4C66FD2406/Projects/Auditforge/auditforge-mcp`
**Virtual Environment:** `.venv/bin/python`

Read `AGENTS.md` and `docs/CONTRACTS.md`. Use ONLY this assigned worktree.
Your complete ownership is live MCP protocol interaction and catalog pinning.

Inspect the installed MCP SDK (`.venv/bin/python -c "import mcp; print(mcp.__file__)"`) and write code against that actual version (`mcp==2.3.0`).

### MANDATORY IMPLEMENTATION:
1. Implement genuine MCP stdio connection in `src/auditforge/catalog/client.py` using `mcp.stdio_client`, `ClientSession`, and `StdioServerParameters`.
2. Convert at least two team-owned Python fixtures (`fixtures/clean_reader/` and `fixtures/rug_pull/`) into functioning MCP servers that expose tools over stdio (`mcp.server.fastmcp` or `mcp.server.lowlevel`).
3. Implement real tool listing and pagination support (`client.list_tools()`).
4. Make a harmless real `call_tool` invocation and validate the result.
5. Serialize complete normalized MCP tool definitions into deterministic JSON using `contracts.canonical_json`.
6. Implement SHA-256 per-tool and whole-catalog hashes.
7. Store a reviewer-approved baseline in SQLite without overwriting it during later scans.
8. Reconnect, retrieve the actual changed catalog and produce a field-level diff (`diff_catalogs`).
9. Add automated tests in `tests/unit/test_mcp_client.py` and `tests/integration/test_mcp_live.py` for stable hashes, schema/description mutation, and baseline preservation.

### Minimum demonstration:
- Discover a real `word_count` tool.
- Call it with a harmless string.
- Receive and verify the actual response.
- Approve the current definition.
- Change the fixture's description or input schema.
- Rescan the changed MCP server.
- Show the exact changed field and different fingerprint.
- Preserve the old approved fingerprint.

No preloaded `catalog.json` may be presented as a real MCP connection.
Do not launch unknown external servers on the host. Coordinate with the container worker so real dynamic calls use a restricted runtime.
Deliver tested implementation, commit to `feat/mcp-catalog-pinning`, push to `origin`, and write `CODEX1_REPORT.md` documenting commit SHA, commands executed, actual output, and integration instructions.
