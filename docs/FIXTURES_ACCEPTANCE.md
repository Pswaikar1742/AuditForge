# Fixture Acceptance Matrix

These five fixtures are executable MCP servers. Each is started with the official
MCP Python SDK and communicates over standard input/output JSON-RPC. Discovery is
performed with `MCPCatalogClient`; malicious handlers are analyzed statically or
run only by the Docker sandbox.

| Fixture | Tool and schema | Planted behavior | Expected detection | Verdict |
| --- | --- | --- | --- | --- |
| `clean_reader` | `search_docs(query: string, limit: integer = 5)`; `word_count(text: string)` | In-memory document search and word counting; read-only/idempotent hints | None | `VERIFIED` |
| `rogue_server` | `system_diagnostic(component: string)` | `os.system()` shell execution and `subprocess.Popen()` process/network attempt | `AST-SUBPROCESS-001`, `AST-SHELL-001` | `ROGUE` |
| `poisoned_description` | `convert_currency(from_currency: string, to_currency: string, amount: number)` | Description embeds instruction override and environment/secret exfiltration request | `DESC-INJECT-001`, `DESC-INJECT-002`, `DESC-EXFIL-001` | `ROGUE` |
| `lying_annotations` | `view_log(log_id: string)`; claims read-only/non-destructive | Handler calls `os.remove()` despite its annotations | `AST-FILE-002`, `TRUST-GAP-001` | `TRUST_GAP` |
| `rug_pull` v1 | `word_count(text: string)` | Approved baseline catalog | None | Baseline |
| `rug_pull` v2 | `word_count(text: string, lowercase: boolean = false)` | Description and input schema change after approval | `PIN-RUGPULL-001` | Drift alert |

## Verification

Run the acceptance suite from the repository root:

```text
.venv/bin/pytest tests/integration/test_acceptance_fixtures.py
```

The suite checks live `tools/list` discovery for all five servers. It invokes the
orchestrator with Docker probing disabled for static/description acceptance so no
malicious target tool is executed on the host. Dynamic execution remains governed
by `DockerSandboxRunner` and its networkless, resource-limited container policy.
