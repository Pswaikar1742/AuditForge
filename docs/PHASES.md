# 📅 AUDIT FORGE — 8-Phase Development Roadmap

| Phase | Description | Status | Key Deliverables |
|:---:|:---|:---:|:---|
| **Phase 1** | Project Foundation & Data Models | ✅ Completed | `models.py`, `config.py`, `database.py`, `pyproject.toml`, `.gitignore`, `.env.example` |
| **Phase 2** | Catalog Discovery & Static AST Scanner | ✅ Completed | `catalog.py`, `static.py` (SAST-001 to SAST-005, SECR-001, CAPS) |
| **Phase 3** | Description & Schema Analyzer | ✅ Completed | `description.py` (DESC-001 to DESC-008, Layer 0 Unicode & AI imperatives) |
| **Phase 4** | Dynamic Prober & Telemetry Sandbox | ✅ Completed | `dynamic.py`, `audit_hooks.py`, `docker_runner.py`, `Dockerfile.probe` |
| **Phase 5** | Pin-and-Diff Fingerprinting Engine | ✅ Completed | `pin_diff.py` (Canonical JSON hashing, DIFF-001, trust state transitions) |
| **Phase 6** | Report Engine & Interactive CLI | ✅ Completed | `markdown.py`, `json_report.py`, `cli.py` (Typer + Rich terminal UX) |
| **Phase 7** | REST API & Custom Web Dashboard | ✅ Completed | `api.py` (FastAPI), React + Vite web dashboard in `dashboard/` |
| **Phase 8** | Integration Acceptance & Fixture Verification | ✅ Completed | All 5 synthetic fixtures (A-E) verified, 17/17 automated tests passing |

---

## Acceptance Test Matrix

- [x] **UT-01 (Static Command Injection):** Detects `subprocess` with `shell=True` at line number (`SAST-001`).
- [x] **UT-02 (Static Code Injection):** Detects `eval`/`exec`/`compile` (`SAST-002`).
- [x] **UT-03 (Static Deserialization):** Detects `pickle.loads` (`SAST-003`).
- [x] **UT-04 (Secret Scanner):** Flags hardcoded key patterns with Shannon entropy threshold (`SECR-001`).
- [x] **UT-05 (Unicode Steganography):** Detects zero-width invisible characters (`DESC-001`).
- [x] **UT-06 (Bidi Override):** Detects bidirectional formatting deception (`DESC-002`).
- [x] **UT-07 (Prompt Injection Imperatives):** Flags AI-directed instruction overrides (`DESC-003`).
- [x] **UT-08 (Canonical Fingerprint):** Canonical JSON produces identical SHA-256 regardless of dict key order.
- [x] **UT-09 (Catalog Drift):** Altering tool schema triggers `DIFF-001` and transitions state to `REVOKED`.
- [x] **UT-10 (Lying Annotations):** Detects `readOnlyHint=true` contradiction with file write capabilities (`ANN-001`).
- [x] **AT-01 (Clean Reader Baseline):** Negative control fixture A yields exactly 0 critical/high findings.
