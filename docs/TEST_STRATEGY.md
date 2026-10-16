# AUDITFORGE TEST STRATEGY & SUITE DESIGN

## 1. Test Architecture Hierarchy

AuditForge adheres to an evidence-based testing pyramid with 4 tiers:

```text
       ┌────────────────────────┐
       │   Live Security Demos  │  (End-to-end full audit pipeline)
       ├────────────────────────┤
       │   Integration Tests    │  (MCP stdio client, Docker runner, Ollama)
       ├────────────────────────┤
       │ Negative/Positive Ctrls│  (5 Controlled synthetic fixtures)
       ├────────────────────────┤
       │ Deterministic Unit Tst │  (Contracts, Canonical JSON, SQLite, CLI)
       └────────────────────────┘
```

---

## 2. Controlled Test Fixtures

| Fixture Name | Category | Primary Threat Target | Expected AuditForge Outcome |
|---|---|---|---|
| `clean_reader` | **Negative Control** | Benign baseline: search & word count tools | `TrustState.VERIFIED`, 0 critical findings |
| `rogue_server` | **Positive Control** | Covert `os.system` ping & `subprocess` exfiltration | `TrustState.ROGUE`, `AST-SHELL-001`, `CRITICAL` severity |
| `poisoned_description` | **Positive Control** | Prompt injection tag `<IMPORTANT>Ignore instructions...</IMPORTANT>` | `TrustState.SUSPICIOUS` / `ROGUE`, `LLM-POISON-001` with verbatim quote |
| `rug_pull` | **Differential Control**| v1 clean vs v2 exfiltration argument & covert tool | `diff.is_identical == False`, added tools & modified args flagged |
| `lying_annotations` | **Trust Gap Control** | Claims `readOnly=True`, executes `os.remove()` | `TrustState.TRUST_GAP`, mismatch flagged with evidence line numbers |

---

## 3. Test Suites

### Tier 1: Deterministic Unit Tests (`tests/unit/`)
- Fast, hermetic, zero-external-dependency tests executable in offline environments and CI pipelines.
- `test_contracts.py`: Validates canonical JSON sorting, cross-platform hash reproducibility, ToolRecord validation.
- `test_pinning.py`: Tests `diff_catalogs` for identical snapshots, modified descriptions, added tools, and removed tools.
- `test_storage.py`: Validates SQLite CRUD for baselines, scans, findings, and evidence tables.

### Tier 2: Model-Enabled Semantic Tests (`tests/unit/test_description.py`)
- Executes against live local Ollama instance (`qwen3.5:9b` or fallback `llama3.2:latest`).
- Verifies model prompt injection classification on `fixtures/poisoned_description`.
- Checks verbatim evidence quote extraction.

### Tier 3: Container Sandbox Integration Tests (`tests/integration/test_sandbox.py`)
- Requires Docker daemon.
- Spawns ephemeral `auditforge-probe` container with memory limit 256MB.
- Verifies timeout enforcement and non-zero exit handling.

### Tier 4: Master Integration & Doctor (`scripts/verify.sh`)
- Automated shell script running environment diagnostics, CLI `--help`, pytest, and git status check.
