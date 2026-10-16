# AuditForge public reference benchmark matrix

This is a reproducible, source-only corpus. Each local target is a small
representative Python handler and JSON catalog, not an unreviewed copy of
upstream code. Tests load catalogs and parse Python ASTs; they do not start
target MCP processes. `DYNAMIC_PROBE` is recorded as supported by the pipeline
but deferred for these fixtures until a Docker guest harness is enabled.

References: [official MCP servers](https://github.com/modelcontextprotocol/servers)
and [Appsecco vulnerable MCP servers lab](https://github.com/appsecco/vulnerable-mcp-servers-lab).
The official repository documents Time, Fetch, Git, and Filesystem; Appsecco
documents the intentionally vulnerable lab. URLs are used as provenance because
upstream `main` is mutable; no upstream source is executed by this benchmark.

| Target | Original reference | Language / transport | Label and ground truth | Modes | Expected vs actual findings | Gaps / false-positive handling | Exact validation |
|---|---|---|---|---|---|---|---|
| Official MCP Time | [MCP Time](https://github.com/modelcontextprotocol/servers/tree/main/src/time) | Python / stdio | Benign timezone calculation; no side effects | STATIC_AST, DESCRIPTION_INTELLIGENCE, PINNING, DYNAMIC_PROBE | Expected none; actual none | No known FP in this fixture; runtime deferred | `python -m pytest tests/benchmarks/test_benchmark_targets.py -k time` |
| Official MCP Fetch | [MCP Fetch](https://github.com/modelcontextprotocol/servers/tree/main/src/fetch) | Python / stdio | Benign URL fetching; network is declared, not covert exfiltration | STATIC_AST, DESCRIPTION_INTELLIGENCE, PINNING, DYNAMIC_PROBE | Expected no malicious finding; actual `BANDIT-B310` | Known FP: Bandit flags URL opening; network policy must distinguish declared URL fetch from unexpected destinations | `python -m pytest tests/benchmarks/test_benchmark_targets.py -k fetch` |
| Official MCP Git | [MCP Git](https://github.com/modelcontextprotocol/servers/tree/main/src/git) | Python / stdio | Benign repository operations; fixed git CLI subprocess | STATIC_AST, DESCRIPTION_INTELLIGENCE, PINNING, DYNAMIC_PROBE | Expected capability warning only; actual `AST-SUBPROCESS-001`, `AST-SUBPROCESS-002`, `BANDIT-B404`, `BANDIT-B603`, `BANDIT-B607` | Known FP: current AST/Bandit rules flag subprocess use and do not model executable/argument allowlists | `python -m pytest tests/benchmarks/test_benchmark_targets.py -k git` |
| Official MCP Filesystem | [MCP Filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) | TypeScript / stdio | Legitimate bounded read/write capability | STATIC_AST, DESCRIPTION_INTELLIGENCE, PINNING, DYNAMIC_PROBE | Expected capability warning only; actual `AST-FILE-001` | Representative Python adapter models the write boundary; path allowlist reconciliation deferred | `python -m pytest tests/benchmarks/test_benchmark_targets.py -k filesystem` |
| Appsecco Secrets + PII | [Appsecco lab](https://github.com/appsecco/vulnerable-mcp-servers-lab) | JavaScript upstream / stdio lab; Python representative | Intentionally exposed API-key-shaped value, email, and environment token | STATIC_AST, DESCRIPTION_INTELLIGENCE, PINNING, DYNAMIC_PROBE | Expected secret/PII finding; actual none | Missing capability: no secret/PII AST detector exists yet; this is not a safety pass | `python -m pytest tests/benchmarks/test_benchmark_targets.py -k secrets` |
| Appsecco Filesystem Workspace Actions | [Workspace actions](https://github.com/appsecco/vulnerable-mcp-servers-lab/tree/main/vulnerable-mcp-server-filesystem-workspace-actions) | JavaScript upstream / stdio lab; Python representative | Path traversal plus caller-controlled shell execution | STATIC_AST, DESCRIPTION_INTELLIGENCE, PINNING, DYNAMIC_PROBE | Expected shell finding; actual `AST-SHELL-001`, `BANDIT-B605` | Path traversal dataflow and runtime proof require container coverage; host execution prohibited | `python -m pytest tests/benchmarks/test_benchmark_targets.py -k workspace` |
| Appsecco Indirect Prompt Injection | [Indirect injection](https://github.com/appsecco/vulnerable-mcp-servers-lab/tree/main/vulnerable-mcp-server-indirect-prompt-injection) | JavaScript upstream / stdio lab; Python representative | Malicious tool-response/description instruction override | STATIC_AST, DESCRIPTION_INTELLIGENCE, PINNING, DYNAMIC_PROBE | Expected description findings; actual `DESC-INJECT-001`, `DESC-INJECT-002`, `DESC-EXFIL-001` | Layer 0 catches metadata text; indirect response payload analysis and LLM layer deferred | `python -m pytest tests/benchmarks/test_benchmark_targets.py -k prompt` |
| Appsecco Malicious Tools | [Malicious code execution](https://github.com/appsecco/vulnerable-mcp-servers-lab/tree/main/vulnerable-mcp-server-malicious-code-exec) | JavaScript upstream / stdio lab; Python representative | Unsafe expression evaluation in a tool | STATIC_AST, DESCRIPTION_INTELLIGENCE, PINNING, DYNAMIC_PROBE | Expected unsafe-eval finding; actual `BANDIT-B307` | Bandit detects the eval, but the native AST rules do not; no empty result is interpreted as safe | `python -m pytest tests/benchmarks/test_benchmark_targets.py -k malicious` |

## Exact full validation commands

```bash
python -m pytest tests/benchmarks/
.venv/bin/pytest tests/benchmarks/  # required when the project venv exists
```

The benchmark asserts detector output, evidence linkage, catalog fingerprints,
and contract reconciliation. Documented detector blind spots are expected actual
results, never fabricated findings or proof of safety.
