# CODEX1 live MCP implementation report

Implementation commit: `573fd4c4d09f5df1c48378cf3b6137e11ccc487e`.
Branch and push destination: `origin/feat/mcp-catalog-pinning`.
PR destination: `develop` (no PR created).

## Files inspected

`AGENTS.md`, `CODEX1_TASK.md`, `docs/CONTRACTS.md`, `pyproject.toml`,
`src/auditforge/core/{contracts,errors}.py`, `src/auditforge/catalog/{client,normalize,pinning}.py`,
`src/auditforge/storage/database.py`, both fixture server files,
`tests/unit/test_pinning.py`, installed MCP SDK signatures and model fields, `.gitignore`.

## Files changed / created

- `src/auditforge/catalog/client.py`: actual SDK initialization, paginated listing, duplicate/cursor checks, bounded sessions, actual tool calling and error propagation. File loading remains a separate explicit API.
- `src/auditforge/catalog/normalize.py`: preserve explicitly empty schemas.
- `src/auditforge/catalog/pinning.py`: field diffs include title and output schema.
- `src/auditforge/storage/database.py`: insert-only approvals and canonical snapshot JSON, with no database schema changes.
- `fixtures/clean_reader/server.py`: MCPServer stdio registration and honest read-only annotations.
- `fixtures/rug_pull/server.py`: selectable v1/v2 real MCP catalogs; both implementations only count words.
- `tests/unit/test_mcp_client.py`: canonical hashing, mutations, approval preservation, pagination and invalid cursors, missing command.
- `tests/integration/test_mcp_live.py`: actual Docker stdio discovery, word_count response validation, repeat fingerprint, reconnect mutation and SQLite approval preservation.
- `tests/integration/Dockerfile.mcp`: MCP 2.3.0 test runtime.
- `CODEX1_REPORT.md`: this handoff (separate documentation commit).

Frozen contracts, sandbox runner, static rules and UI were not changed.

## Executed verification

SDK inspection:

```sh
.venv/bin/python -c "import mcp; print(mcp.__file__)"
```

Actual import path:
`/run/media/psw/6066FD4C66FD2406/Projects/Auditforge/auditforge-mcp/.venv/lib/python3.12/site-packages/mcp/__init__.py`

Additional Python `inspect.signature` / `model_fields` checks confirmed installed version `2.3.0`,
`list_tools(*, params=...)`, `next_cursor`, `is_error`, and `MCPServer`.
Importing `mcp.server.fastmcp` raised the SDK's migration error: FastMCP was renamed to MCPServer.

```sh
docker info --format '{{.ServerVersion}}'
docker build -f tests/integration/Dockerfile.mcp -t auditforge-mcp-test:2.3.0 .
PYTHONPATH=src .venv/bin/python -m pytest tests/unit/test_mcp_client.py
PYTHONPATH=src .venv/bin/python -m pytest -s
git diff --check
```

Docker version output: `29.6.0`. Image build exited 0, installing `mcp-2.3.0`.
Focused tests: `3 passed in 0.84s`. Final full-suite raw output:

```text
LIVE_CALL {"meta":null,"content":[{"type":"text","text":"{\n  \"count\": 3\n}","annotations":null,"meta":null}],"structured_content":{"result":{"count":3}},"is_error":false,"result_type":"complete"}
.LIVE_DIFF {"server_id":"rug_pull","baseline_fingerprint":"d6303de2bc0ff102ecf113d11c656caff143da515c481c1826b2320091bc9933","current_fingerprint":"508c7fe457bc82c15683584da7cdbd99b7643e23344f0edb4f0c75d9337c96fe","is_identical":false,"added_tools":[],"removed_tools":[],"modified_tools":{"word_count":{"description":{"baseline":"Count words in text in-memory.","current":"Count words after optional lowercase normalization."},"input_schema":{"baseline":{"properties":{"text":{"title":"Text","type":"string"}},"required":["text"],"title":"word_countArguments","type":"object"},"current":{"properties":{"text":{"title":"Text","type":"string"},"lowercase":{"default":false,"title":"Lowercase","type":"boolean"}},"required":["text"],"type":"object","title":"word_countArguments"}}}}}
................
17 passed in 14.92s
```

`git diff --check` exited 0 with no output.

Earlier verification exposed the venv's editable import pointing at sibling `Forger`;
initial focused run reported 3 failures against that checkout. All subsequent verification
uses `PYTHONPATH=src`. An early full run before image availability reported
`15 passed, 2 skipped`. First actual integration run exposed use of the old
`nextCursor` attribute (`2 failed, 15 passed`); corrected to the installed SDK's
`next_cursor`, then reran successfully. Final run above has no skips.

## Integration instructions

Build the image and run the exact full-suite command above from this worktree.
Use `MCPCatalogClient(command, server_id="stable-logical-id")` with a restricted
Docker stdio command, then `await client.discover_live()`; explicitly approve a
reviewed snapshot with `Database.save_baseline(snapshot)`. A later discovery never
writes the baseline. Compare with `diff_catalogs(db.get_baseline(id), current)`.
`await client.call_tool("word_count", {"text": "AuditForge counts three"})`
returns the SDK result whose text JSON is `{"count": 3}`.
See `live_client` in the integration test for the complete runtime command.

Each actual test server ran non-root with network disabled, 256MB memory and swap
ceiling, 0.5 CPU, read-only filesystem and fixture mount, dropped capabilities,
no new privileges, a PID limit, 10-second operation budget, and explicit container
cleanup. No target tool ran on the host. There was no separate container worker in
this session; this scoped test harness supplies the restricted runtime without
modifying the sandbox worker's runner.

## Limitations and deferred work

The client accepts a transport command; callers must enforce container isolation.
It is not a sandbox. The default timeout covers each whole discovery/call session.
Pagination is verified with a controlled session test; the real fixture catalogs
fit in one page. Normalization follows exactly the frozen six-field fingerprint
contract; newer SDK fields outside that contract are not fingerprinted.
Baseline replacement/reapproval workflow is intentionally not provided; an existing
approval is preserved even if save_baseline is called again. The tests explicitly
perform the approval step; they do not assert that a human independently reviewed
the fixture. No security verdict, AST analysis or telemetry evidence is claimed.
Live integration tests explicitly SKIP if the test image is unavailable.

## Publication

Implementation push command: `git push origin feat/mcp-catalog-pinning`.

```text
To https://github.com/Pswaikar1742/AuditForge.git
   1a7ee60..573fd4c  feat/mcp-catalog-pinning -> feat/mcp-catalog-pinning
```
