# AUDITFORGE WORKSTREAM OWNERSHIP & TEAMMATE ISOLATION DIRECTIVE (OWNERSHIP.md)

**Status:** Canonical & Operative  
**Integration Branch:** `develop`  
**Foundation Anchor Commit:** `1a7ee601a3b88faa3c100711d5fab61567a6ed04` (`main`)  
**Timestamp:** 2026-10-16T10:18:00+05:30  

---

## 1. Human Teammate Protection Policy (Strict Isolation)

### 1.1 Teammate Branch Status
- **Current Remote Inspection:** `git ls-remote --heads origin` lists `main`, `develop`, `feat/mcp-catalog-pinning`, `feat/sandbox-prober-fixtures`, `feat/static-description-llm`, and `feat/report-api-ui`.
- **Human Branch Declaration Status:** `UNKNOWN` / `AWAITING_DECLARATION`.
- If the human teammate creates or pushes an independent branch (e.g. `feat/human-*`, `fix/*`, or custom branch), or operates from a separate local clone, it is immediately registered as **HUMAN-PROTECTED**.

### 1.2 Non-Interference Mandates
1. **Zero Modifications:** No autonomous agent may checkout, commit to, amend, rebase, reset, or push to any human-protected branch.
2. **Zero Destructive Commands:** Under no circumstances shall `git clean`, `git reset --hard`, `git push --force`, or broad `git add -A` be run against unreviewed or teammate paths.
3. **No Unapproved Integration:** Human commits shall never be merged or cherry-picked into `develop` without explicit review and approval from the human teammate and repository owner.
4. **Collision Preemption:** If an autonomous workstream proposes changes touching modules edited by the teammate, work must halt immediately to request explicit ownership boundaries.

---

## 2. Workstream Boundaries & File Ownership Matrix

| Workstream / Agent | Assigned Branch | Dedicated Worktree | Owned Modules & Scopes | Forbidden Files & Scopes |
|---|---|---|---|---|
| **Human Teammate (Protected)** | *Declared upon creation* | Independent / Separate | Declared feature files & custom components | Autonomous agents forbidden from editing |
| **Codex 1 (MCP & Pinning)** | `feat/mcp-catalog-pinning` | `../auditforge-mcp` | `src/auditforge/catalog/*`, `tests/unit/test_mcp_client.py`, `tests/integration/test_mcp_live.py` | AST analyzers, Docker sandbox, UI, contracts |
| **Codex 2 (Sandbox & Prober)** | `feat/sandbox-prober-fixtures` | `../auditforge-sandbox` | `src/auditforge/sandbox/*`, `docker/*`, `fixtures/*` | FastAPI routes, contracts, UI, catalog client |
| **AGY Analysis** | `feat/static-description-llm` | `../auditforge-analysis` | `src/auditforge/analyzers/*` | Docker runner, MCP client transport |
| **AGY UI & Reports** | `feat/report-api-ui` | `../auditforge-ui` | `src/auditforge/reports/*`, `dashboard/*`, `api/*` | Core contracts, AST scanning rules |
| **Lead Integrator (AGY Develop)** | `develop` | `./Forger` (Root) | `orchestrator.py`, `cli.py`, integration orchestration | Direct feature branch writes |

---

## 3. Communication & Collision Protocol

If any merge conflict, overlapping file modification, or ambiguous ownership occurs:
1. Stop execution on the conflicting module immediately.
2. Log the exact conflicting file and branch in `docs/OWNERSHIP.md`.
3. Request explicit ownership clarification from the repository maintainer.
