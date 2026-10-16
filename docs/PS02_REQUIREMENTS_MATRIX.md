# AUDITFORGE — PS02 MANDATORY REQUIREMENTS & TOOL SELECTION MATRIX

**Problem Statement:** PS02 — MCP Server Security Auditor  
**Team:** InnoVision  
**Track:** Open Weight AI & Open Source Tools  
**Evaluation Standard:** Evidence-First, Zero Fake Findings, Zero Fabricated Evidence  

---

## 1. Mandatory Functional Requirements vs. Recommended Tool Choices

| # | Mandatory PS02 Requirement | Mandatory Core Functionality | Recommended / Permitted Tooling | AuditForge Implementation Choice | Rationale & Evidence Link |
|---|---|---|---|---|---|
| **1** | **Static Handler Scanner** | Parse handler source code to detect command injection, unsafe deserialization, hardcoded secrets, and unnecessary file/network access. | Semgrep (custom rules), Bandit, ESLint security plugins, Gitleaks. | Python AST Visitor + Bandit security rules + regex secret entropy scanner (`StaticAnalyzer`). | Pure AST guarantees zero false negatives on syntax trees; Bandit integration flags CWE-78/CWE-88; secret scanner catches private keys/tokens. [static.py](file:///run/media/psw/6066FD4C66FD2406/Projects/Auditforge/Forger/src/auditforge/analyzers/static.py) |
| **2** | **Description & Text Analyzer** | Analyze tool names, descriptions, and parameter schemas using an open-weight model to flag text aimed at instructing the AI rather than informing the user. | Qwen3-8B / Qwen3-4B via Ollama, Prompt Guard 2. | `qwen2.5-coder:7b` via local Ollama + Layer 0 delimiter/regex heuristics (`DescriptionAnalyzer`). | Apache 2.0 open-weight model with verified verbatim quote citation; bounded at ADVISORY severity to prevent hallucinations. [description.py](file:///run/media/psw/6066FD4C66FD2406/Projects/Auditforge/Forger/src/auditforge/analyzers/description.py) |
| **3** | **Dynamic Container Prober** | Run the target MCP server in an isolated container, call tools with schema-valid test inputs, and flag behaviors mismatched with declared descriptions/schemas. | Docker sandboxing with `strace` and `mitmproxy`. | Ephemeral non-root Docker guest (`network_mode="none"`, memory capped at 256MB, CPU 50%, `no-new-privileges:true`, `cap-drop ALL`) with Python `sys.addaudithook` telemetry + official `MCPServer.call_tool` protocol. | Docker namespaces guarantee host containment; internal audit hooks capture unauthorized `subprocess.Popen`, `socket.connect`, and `open` calls without host risk. [runner.py](file:///run/media/psw/6066FD4C66FD2406/Projects/Auditforge/Forger/src/auditforge/sandbox/runner.py) |
| **4** | **Pin-and-Diff Fingerprinting** | Fingerprint the approved tool list deterministically, store baseline in SQLite, and alert on any post-approval drift or rug-pull. | SHA-256 fingerprinting in SQLite with `deepdiff`. | Canonical key sorting, whitespace normalization, SHA-256 tool & catalog hashing (`contracts.py`), SQLite storage (`database.py`), and field-level diff engine (`pinning.py`). | Detects parameter additions, type alterations, and description modifications with exact before-and-after values. [pinning.py](file:///run/media/psw/6066FD4C66FD2406/Projects/Auditforge/Forger/src/auditforge/mcp/pinning.py) |
| **5** | **Evidence-First Reporting** | Output audit findings with unique ID, severity, raw evidence capsules, and remediation fix per finding. | SARIF 2.1.0 or human-readable Markdown report + JSON capsule export. | Structured JSON Evidence Capsule (`ScanResult`) conforming to frozen schema + GitHub-flavored Markdown generator + Typer/Click CLI. | Ensures every finding is cryptographically verifiable and includes raw unedited AST line quotes or container events. [reports/](file:///run/media/psw/6066FD4C66FD2406/Projects/Auditforge/Forger/src/auditforge/reports/) |
| **6** | **Controlled Competition Test Set** | 3–5 small MCP servers (mix of clean and deliberately vulnerable/poisoned) to self-demonstrate scanner accuracy. | Official MCP Python SDK and MCP Inspector for testing. | 5 Authentic MCP Stdio Servers: `clean_reader` (negative control), `rogue_server`, `poisoned_description`, `lying_annotations`, and `rug_pull` (version-switch). | Fully callable over stdio JSON-RPC 2.0 handshake using official MCP SDK (`mcp>=1.2.0`). [fixtures/](file:///run/media/psw/6066FD4C66FD2406/Projects/Auditforge/Forger/fixtures/) |
| **7** | **Interactive Web View & CLI** | Interactive dashboard to inspect scans, view trust-gap reconciliations, and review baselines. | Typer CLI with optional FastAPI + React web view. | Click/Typer CLI (`cli.py`), FastAPI backend (`api/app.py`), and Vite + React Mission Control dashboard (`dashboard/`). | Real-time scan triggering, baseline approval, diff inspection, and evidence drill-down backed by SQLite. [dashboard/](file:///run/media/psw/6066FD4C66FD2406/Projects/Auditforge/Forger/dashboard/) |

---

## 2. Detector Coverage & Truth-in-Reporting Accounting Rules

To eliminate false safety claims and misleading status indicators:

1. **LLM Execution Failure:** If the local open-weight model is offline, times out, or errors, `stage_coverage["description_intelligence"]` MUST be reported as `"ERROR"` or `"SKIPPED"`, never `"PASS"`. If only Layer 0 regex runs, report `"HEURISTIC_ONLY"`.
2. **Baseline Pinning:** If a server has never been approved, `stage_coverage["baseline_pinning"]` MUST be reported as `"NOT_PINNED"`, never `"PASS"`. Only servers with a valid existing baseline comparison receive `"PASS"`.
3. **Dynamic Probing:** If a tool call times out or encounters container errors, `stage_coverage["dynamic_probing"]` MUST be reported as `"ERROR"`. If Docker is disabled or no runnable source is available, report `"SKIPPED"`.
4. **Static Findings vs Runtime Telemetry:** AST code findings must remain strictly classified as `SOURCE_INDICATOR / LIKELY`. Only container audit hook events may be classified as `OBSERVED_ATTEMPT` or `OBSERVED_EFFECT`.
5. **Clean Server Verdict:** A server receives `TrustState.VERIFIED` ONLY when all mandatory stages execute with 100% coverage and zero findings are detected. `findings: []` alone is never proof of safety without complete stage execution.
