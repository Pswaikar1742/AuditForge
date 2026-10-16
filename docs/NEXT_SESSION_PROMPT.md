# 🚀 AUDIT FORGE — Next Session Handover Prompt

> **Usage:** Copy and paste the block below into the next agent or developer session. It contains all context, active architecture, directory maps, testing verification status, and next actionable steps.

---

```markdown
## Context & Identity
You are continuing development on **AUDIT FORGE** (Problem Statement: **PS02 — MCP Server Security Auditor**).
Workspace root: `OpenForge Hackathon/audit-forge`
Reference Playbook: `PS02_MCP_Security_Auditor_Competition_Playbook.pdf` (34 pages)
Project Rules: Strictly follow `AGENTS.md` (Zero AI slop, no mocked findings, no hallucinations, evidence capsules mandatory, synthetic fixtures only).

## Current Project Status
- **Core Engine Completed & Verified**:
  - `src/audit_forge/models.py`: Pydantic contracts for `Finding`, `EvidenceCapsule`, `ToolDefinition`, `CatalogSnapshot`, `ScanResult`, `Baseline`, `TrustState` (`UNSCANNED`, `REVIEW`, `APPROVED`, `REVOKED`).
  - `src/audit_forge/database.py`: SQLite persistence layer with foreign keys, WAL mode, scan history, baselines, and trust transitions.
  - `src/audit_forge/analyzers/static.py`: AST static security scanner implementing `SAST-001` (OS command injection `shell=True`), `SAST-002` (code injection `eval`/`exec`), `SAST-003` (unsafe deserialization `pickle.loads`), `SAST-004` (path traversal), `SAST-005` (dynamic URL SSRF), and `SECR-001` (hardcoded fake secret patterns + Shannon entropy).
  - `src/audit_forge/analyzers/description.py`: Deterministic Layer 0 analyzer checking invisible Unicode zero-width characters (`DESC-001`), bidi control overrides (`DESC-002`), prompt injection / AI imperatives (`DESC-003`), and credential theft mentions (`DESC-004`). Layer 2 Ollama Qwen3 bridge prepared.
  - `src/audit_forge/analyzers/trust_gap.py`: Core USP module correlating declared tool annotations against observed code capabilities and runtime telemetry: `ANN-001` (readOnlyHint=true write violation), `ANN-002` (openWorldHint=false network violation), `ANN-003` (destructiveHint=false), `ANN-004` (missing hints), `CAP-002` (undeclared elevated capability).
  - `src/audit_forge/analyzers/pin_diff.py`: Cryptographic tool catalog fingerprinter (canonical tool JSON, per-tool SHA-256, catalog SHA-256) detecting live rug pulls and drift (`DIFF-001`, `DIFF-002`, `DIFF-003`).
  - `src/audit_forge/analyzers/dynamic.py` & `src/audit_forge/sandbox/`: Runtime audit hooks telemetry (`sys.addaudithook`) and hardened Docker container specification (`--network none`, `--read-only`, non-root `65532:65532`, dropped capabilities).
  - `src/audit_forge/orchestrator.py`: Full scan orchestrator linking all 7 pipeline stages.
  - `src/audit_forge/reports/`: Human-readable Markdown and machine-readable JSON report generators.
  - `src/audit_forge/cli.py`: Typer + Rich CLI (`python -m audit_forge.cli scan <target>`, `python -m audit_forge.cli baseline list/approve`).
  - `src/audit_forge/api.py`: FastAPI backend server (`uvicorn audit_forge.api:app --reload`) on port 8000.
  - `dashboard/`: Custom React + Vite dashboard with dark mode, live FastAPI connectivity, one-click synthetic fixture runner, and interactive Evidence Capsule trace explorer.
  - `fixtures/`: All 5 synthetic competition fixtures created and verified:
    - Fixture A: `clean_reader` (Negative control: 0 findings)
    - Fixture B: `rogue_server` (SAST-001, SAST-003, SECR-001)
    - Fixture C: `poisoned_description` (DESC-001, DESC-003, DESC-004)
    - Fixture D: `rug_pull` (DIFF-001, DIFF-002, DIFF-003)
    - Fixture E: `lying_annotations` (ANN-001 USP demonstration)
  - `tests/`: 17/17 pytest tests passing cleanly (`python -m pytest tests -v`).

## Quick Verification Commands
```bash
# 1. Run all unit & acceptance tests (all 17 must pass)
$env:PYTHONPATH="src"; python -m pytest tests -v

# 2. Run CLI scan on any fixture
$env:PYTHONPATH="src"; python -m audit_forge.cli scan fixtures/fixture_b_rogue_server

# 3. Start FastAPI backend (port 8000)
$env:PYTHONPATH="src"; python -m uvicorn audit_forge.api:app --host 127.0.0.1 --port 8000

# 4. Start React Dashboard (port 3000)
cd dashboard && npm run dev
```

## Next Tasks for the Incoming Developer / Agent
1. **Docker Image Build**: Run `docker build -t audit-forge-probe -f docker/Dockerfile.probe docker/` to enable fully containerized probing with network isolation.
2. **Layer 2 Local Model Integration**: Verify Ollama connection with `qwen3:4b` or `qwen3:1.7b` for semantic prompt injection classification.
3. **Live MCP Server Stdio Client**: Complete live `mcp` SDK v2 Stdio client connection in `src/audit_forge/analyzers/catalog.py` for live process spawning.
4. **Prepare Competition Video & Presentation Slides**: Demonstrate the 5 fixtures, the Contract-to-Behavior Trust Gap USP, and the live dashboard.
```
