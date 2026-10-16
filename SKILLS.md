# AUDITFORGE TEAM AGENT ROLES & WORKFLOW SKILLS (SKILLS.md)

**Notice:** This document defines role specializations, engineering prerequisites, module scopes, and verification procedures. It supplements, and does not replace, the mandatory operational rules in [`AGENTS.md`](file:///run/media/psw/6066FD4C66FD2406/Projects/Auditforge/Forger/AGENTS.md).

---

## 1. Role: MCP Protocol Engineer

- **Assigned Branch:** `feat/mcp-catalog-pinning`
- **Worktree:** `../auditforge-mcp`
- **Target Module Paths:**
  - `src/auditforge/catalog/client.py`
  - `src/auditforge/catalog/normalize.py`
  - `src/auditforge/catalog/pinning.py`
  - `tests/unit/test_pinning.py`
  - `tests/integration/test_mcp_client.py`
- **Core Responsibilities:**
  - Implement genuine stdio client discovery using the official `mcp>=2.0.0` Python SDK (`ClientSession`, `stdio_client`, `StdioServerParameters`).
  - Query `session.list_tools()` over JSON-RPC stdio transport.
  - Normalize tool schemas (handling camelCase `inputSchema` / snake_case `input_schema`, default values, descriptions).
  - Compute deterministic tool SHA-256 fingerprints and catalog-level hashes.
  - Implement baseline snapshot storage and field-level `CatalogDiff` detection.
- **Verification Commands:**
  ```bash
  python -m pytest tests/unit/test_pinning.py -v
  python -m auditforge.cli pin fixtures/clean_reader/catalog.json --id clean_reader
  python -m auditforge.cli diff fixtures/rug_pull/catalog_v2.json --id clean_reader
  ```
- **Definition of Done:**
  - Live server discovery connects and retrieves tool listings without mocking.
  - Pinning and diffing catch additions, removals, and modifications deterministically.
  - No edits to static analyzer or Docker modules.

---

## 2. Role: Static Security Analysis Engineer

- **Assigned Branch:** `feat/static-description-llm`
- **Worktree:** `../auditforge-analysis`
- **Target Module Paths:**
  - `src/auditforge/analyzers/static.py`
  - `tests/unit/test_static.py`
- **Core Responsibilities:**
  - Parse MCP server Python source code using `ast.parse`.
  - Walk the AST to detect dangerous function calls: `os.system`, `subprocess.*`, `shutil.rmtree`, `eval`, `exec`, `open(..., 'w')`, `socket.*`.
  - Integrate Bandit AST security scanner (`bandit.core.manager`) for automated rule matching.
  - Extract exact line numbers, AST node names, and code snippets into `EvidenceRecord` capsules.
  - Generate typed `Finding` objects with rule IDs (e.g., `AST-SHELL-001`, `AST-FILE-WRITE-002`, `AST-NET-003`).
- **Verification Commands:**
  ```bash
  python -m pytest tests/unit/test_static.py -v
  ```
- **Definition of Done:**
  - Successfully detects malicious patterns in `fixtures/rogue_server/server.py` and `fixtures/lying_annotations/server.py`.
  - Zero false positives on `fixtures/clean_reader/server.py`.
  - Every finding contains valid `evidence_ids` referencing captured line numbers.

---

## 3. Role: Open-Weight AI Engineer

- **Assigned Branch:** `feat/static-description-llm`
- **Worktree:** `../auditforge-analysis`
- **Target Module Paths:**
  - `src/auditforge/analyzers/description.py`
  - `src/auditforge/analyzers/trust_gap.py`
  - `tests/unit/test_description.py`
- **Core Responsibilities:**
  - Implement **Layer 0** deterministic regex/heuristic scans (markdown injection, system tags like `<IMPORTANT>`, hidden exfiltration instructions).
  - Implement **Layer 1 & 2** semantic evaluation using local open-weight models (`qwen3.5:9b`, fallback `llama3.2:latest`) via Ollama HTTP API (`/api/generate`).
  - Extract verbatim evidence quotes from the prompt/description into `EvidenceRecord` capsules.
  - Reconcile declared claims (descriptions, annotations) against AST/probe evidence to calculate `TrustState`.
- **Verification Commands:**
  ```bash
  python -m pytest tests/unit/test_description.py -v
  ```
- **Definition of Done:**
  - Flags prompt injection in `fixtures/poisoned_description/catalog.json` with verbatim quoted evidence.
  - Passes negative control `fixtures/clean_reader/catalog.json` without false positives.
  - Fallback mechanism works if Ollama service is unavailable (switches to Layer 0 with explicit warning).

---

## 4. Role: Container Security and Dynamic Testing Engineer

- **Assigned Branch:** `feat/sandbox-prober-fixtures`
- **Worktree:** `../auditforge-sandbox`
- **Target Module Paths:**
  - `src/auditforge/sandbox/runner.py`
  - `src/auditforge/sandbox/telemetry.py`
  - `src/auditforge/sandbox/probe_cases.py`
  - `docker/Dockerfile.probe`
  - `fixtures/*/server.py`
  - `tests/unit/test_sandbox.py`
- **Core Responsibilities:**
  - Build and maintain the probe container image (`docker/Dockerfile.probe`).
  - Implement `DockerSandboxRunner` enforcing ephemeral execution, resource constraints (256MB memory, 50% CPU quota), network isolation (`none`), and non-root execution.
  - Implement schema-valid probe generation (`generate_probe_cases`) based on tool JSON schemas.
  - Implement guest-side Python audit hooks (`sys.addaudithook`) to capture file opens and socket calls as telemetry.
  - Handle container timeouts, runtime crashes, and non-zero exit codes into structured `ProbeOutcome`.
- **Verification Commands:**
  ```bash
  docker build -f docker/Dockerfile.probe -t auditforge-probe:latest .
  python -m pytest tests/unit/test_sandbox.py -v
  ```
- **Definition of Done:**
  - Tools execute inside Docker without host privilege leakage.
  - Rogue server actions are trapped and recorded in telemetry.
  - Clean server tools execute and return valid outputs.

---

## 5. Role: Reporting and Frontend Engineer

- **Assigned Branch:** `feat/report-api-ui`
- **Worktree:** `../auditforge-ui`
- **Target Module Paths:**
  - `src/auditforge/reports/json_report.py`
  - `src/auditforge/reports/markdown.py`
  - `src/auditforge/api/app.py`
  - `dashboard/`
  - `tests/unit/test_reports.py`
- **Core Responsibilities:**
  - Export self-contained JSON evidence capsules compliant with the frozen `ScanResult` schema.
  - Render executive and technical Markdown reports with severity tables, tool inventories, and diff views.
  - Expand FastAPI endpoints for triggering scans, viewing history, browsing findings, and diff comparisons.
  - Connect React/Vite dashboard to FastAPI backend, displaying real-time scan progress, findings details, evidence inspection modal, and baseline diff viewer.
- **Verification Commands:**
  ```bash
  python -m pytest tests/unit/test_reports.py -v
  python -m uvicorn auditforge.api.app:app --port 8000 &
  curl http://127.0.0.1:8000/health
  cd dashboard && npm run build
  ```
- **Definition of Done:**
  - Real scan data from SQLite renders accurately in the React dashboard.
  - Findings detail view displays verbatim evidence capsules.
  - JSON and Markdown reports are valid and reproducible.

---

## 6. Role: Integration and QA Engineer

- **Assigned Branch:** `develop`
- **Worktree:** `AuditForge/` (root)
- **Target Module Paths:**
  - `src/auditforge/orchestrator.py`
  - `src/auditforge/cli.py`
  - `tests/integration/`
  - `scripts/verify.sh`
  - `docs/STATUS.md`
- **Core Responsibilities:**
  - Orchestrate end-to-end audit pipelines in `orchestrator.py`.
  - Review and merge PRs from the four feature branches into `develop`.
  - Maintain the master verification script (`scripts/verify.sh`).
  - Keep `docs/STATUS.md` synchronized with executed test evidence.
  - Prepare the final release package and demo script for hackathon submission.
- **Verification Commands:**
  ```bash
  bash scripts/verify.sh
  ```
- **Definition of Done:**
  - All unit and integration test suites pass on `develop`.
  - `auditforge doctor` and `auditforge scan` execute without regressions.
  - Zero conflicts between merged feature branches.
