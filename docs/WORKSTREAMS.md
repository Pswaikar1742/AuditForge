# AUDITFORGE PARALLEL WORKSTREAMS & GIT ORCHESTRATION

## 1. Branch Hierarchy & Flow

```text
main (Submission / Release)
  └── develop (Integration baseline)
        ├── feat/mcp-catalog-pinning      (Worktree: ../auditforge-mcp)
        ├── feat/static-description-llm   (Worktree: ../auditforge-analysis)
        ├── feat/sandbox-prober-fixtures  (Worktree: ../auditforge-sandbox)
        └── feat/report-api-ui            (Worktree: ../auditforge-ui)
```

- **Master Integrator:** Integration Architect.
- **Rules of Engagement:**
  1. Every feature branch is branched directly from `develop`.
  2. Pull requests MUST target `develop`. Merges to `main` occur only after end-to-end regression validation.
  3. No cross-module edits outside an agent's assigned ownership boundaries.
  4. Changes to `src/auditforge/core/contracts.py` are strictly prohibited without Integrator sign-off.

---

## 2. Worktree Directory Mapping

| Worktree Path | Active Branch | Primary Owner | Module Boundaries |
|---|---|---|---|
| `/run/media/psw/6066FD4C66FD2406/Projects/Auditforge/auditforge-mcp` | `feat/mcp-catalog-pinning` | MCP Protocol Engineer | `src/auditforge/catalog/`, pinning tests |
| `/run/media/psw/6066FD4C66FD2406/Projects/Auditforge/auditforge-analysis` | `feat/static-description-llm` | Static & LLM Engineer | `src/auditforge/analyzers/`, static & prompt tests |
| `/run/media/psw/6066FD4C66FD2406/Projects/Auditforge/auditforge-sandbox` | `feat/sandbox-prober-fixtures` | Sandbox & Prober Engineer | `src/auditforge/sandbox/`, `docker/`, `fixtures/` |
| `/run/media/psw/6066FD4C66FD2406/Projects/Auditforge/auditforge-ui` | `feat/report-api-ui` | Reporting & UI Engineer | `src/auditforge/reports/`, `src/auditforge/api/`, `dashboard/` |
| `/run/media/psw/6066FD4C66FD2406/Projects/Auditforge/Forger` | `develop` | Integration Architect | `orchestrator.py`, `cli.py`, `tests/integration/`, `scripts/` |

---

## 3. Recommended PR Merge Order

To ensure clean, non-conflicting integration into `develop`:

1. **Step 1: MCP Catalog & Pinning (`feat/mcp-catalog-pinning`)**
   - Provides genuine MCP client connection and live tool discovery required by the orchestrator.
2. **Step 2: Static & Description Analyzers (`feat/static-description-llm`)**
   - Adds AST parsing, Bandit detection, and local Qwen prompt injection evaluation.
3. **Step 3: Sandbox Prober & Fixtures (`feat/sandbox-prober-fixtures`)**
   - Adds Docker runner, dynamic schema-valid inputs, and verified test fixtures.
4. **Step 4: Report Engine, API & Dashboard (`feat/report-api-ui`)**
   - Connects the completed audit results into REST endpoints, Markdown/JSON reports, and the React UI.
5. **Step 5: Master Integration Validation on `develop`**
   - Full test run (`scripts/verify.sh`) before promoting `develop` to `main`.
