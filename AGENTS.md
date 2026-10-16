# AUDITFORGE AGENT OPERATING DIRECTIVE & CODE OF CONDUCT (AGENTS.md)

**Status:** Canonical & Operative for All Autonomous & Assisted Coding Agents (Codex, Antigravity, Claude, Cursor)  
**Project:** AuditForge — Evidence-First MCP Security Auditor  
**Problem Statement:** PS02 — MCP Server Security Auditor  
**Lead Integrator:** Lead Systems Architect / Repository Maintainer  

---

## 1. Zero Tolerance Policies (Non-Negotiable)

1. **Zero Fake Findings / Zero Mocked Results:** Never simulate security results or emit pre-cooked PASS/FAIL outcomes. If an analyzer cannot run or has not been implemented, it MUST raise `NotImplementedAuditError` or log an explicit `SKIPPED` status with verifiable rationale. Never return an empty `findings: []` list as proof of safety.
2. **Zero Fabricated Evidence:** Every finding must link to one or more `EvidenceRecord` capsules containing raw, unedited AST line quotes, LLM extraction quotes, or sandbox audit events.
3. **Zero Destructive Git Operations:** No agent may `git push --force`, rebase another agent's active branch, or delete remote branches. Never rewrite commit timestamps or commit history to conceal code provenance.
4. **Zero Host Execution for Target MCP Tools:** Target MCP servers must never execute directly on the host OS during dynamic probing. Dynamic analysis must run exclusively inside ephemeral, resource-constrained Docker containers (`network_mode="none"`, memory capped at 256MB, CPU quota 50%).
5. **No Unauthorized Schema Alteration:** `src/auditforge/core/contracts.py` is **FROZEN**. No agent may alter data models, field names, or enum values without explicit review from the Integration Architect.

---

## 2. Workstream Boundaries & Ownership Matrix

Agents work exclusively within assigned Git worktrees and feature branches:

| Branch | Worktree Directory | Primary Responsibilities | Prohibited Edits |
|---|---|---|---|
| `feat/mcp-catalog-pinning` | `../auditforge-mcp` | MCP stdio client discovery, tool normalization, SHA-256 canonical hashing, catalog baseline storage, field-level diffs | Do not alter static AST, Docker runner, or UI |
| `feat/static-description-llm` | `../auditforge-analysis` | Python AST scanning, Bandit integration, secrets detection, deterministic description checks, Qwen3.5 semantic prompt injection detection | Do not alter MCP transport client or Docker sandbox runner |
| `feat/sandbox-prober-fixtures` | `../auditforge-sandbox` | Docker guest runner, safe schema-valid probe generation, timeout handling, guest audit hook telemetry, 5 controlled test fixtures | Do not alter FastAPI endpoints, SQLite schema, or React UI |
| `feat/report-api-ui` | `../auditforge-ui` | JSON evidence capsule export, Markdown reports, FastAPI REST endpoints, React/Vite dashboard evidence browser | Do not alter core hashing logic or AST analyzer rules |
| `develop` | `AuditForge/` (root) | Integration orchestrator, end-to-end integration tests, doctor scripts, release packaging | Feature work belongs in feature branches |

---

## 3. Evidence-First Verification Mandate

No feature, bug fix, or PR may be described as "Complete" or "Done" without executed acceptance evidence.
Every PR and handoff must document:
- **Files Inspected**
- **Files Changed / Created**
- **Exact Verification Commands Executed**
- **Actual Raw Output / Terminal Logs**
- **Known Limitations & Deferred Work**
- **Commit SHA and PR Destination** (`develop` only)

---

## 4. PS02 Mandatory Problem Statement Requirements

1. **Protocol Discovery:** Connect to any MCP compliant server over stdio transport and extract full tool declarations.
2. **Deterministic Fingerprinting:** Normalize definitions and generate canonical SHA-256 hashes per tool and across the catalog.
3. **Static Vulnerability Inspection:** Parse server Python source code using AST + Bandit to detect dangerous imports, process spawns, shell injections, file deletions, and credential access.
4. **Open-Weight Description Intelligence:** Scan tool descriptions and annotations using local Qwen3.5 / Llama3.2 via Ollama to detect prompt injection, scope expansion, and hidden instruction overrides.
5. **Containerized Dynamic Probing:** Execute schema-valid probe inputs inside an isolated Docker sandbox with non-root privileges and strict resource limits.
6. **Contract-to-Behavior Trust Gap Reconciliation:** Reconcile claimed contracts (annotations like `readOnly=True`, docstrings) against observed static and dynamic behaviors.
7. **Baseline Pinning & Rug Pull Alerts:** Detect when a server changes capabilities, adds arguments, or modifies descriptions between approved runs.
8. **Verifiable Reporting:** Output structured JSON evidence capsules and human-readable Markdown reports.

---

## 5. Security & Sandbox Guardrails

- Dynamic probes must enforce strict timeouts (default 10s).
- Network must be disabled (`network_mode="none"`) unless an explicit network rule is being tested.
- Telemetry hooks (`sys.addaudithook`) inside the guest container capture `open`, `socket.connect`, `subprocess.Popen` calls and forward them as telemetry.
- Telemetry hooks must NEVER be claimed as host security isolation. Host isolation is provided by Docker container namespaces.
