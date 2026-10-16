# CONTRIBUTING TO AUDITFORGE

Thank you for contributing to **AuditForge** (PS02 — MCP Server Security Auditor, OpenForge Hackathon 2026).

---

## 1. Development Principles

- **Evidence First:** Claims of security or vulnerability detection must be accompanied by raw, verifiable evidence capsules.
- **Contract Strictness:** All modules interface through [`src/auditforge/core/contracts.py`](file:///run/media/psw/6066FD4C66FD2406/Projects/Auditforge/Forger/src/auditforge/core/contracts.py). Schema changes require Integration Architect review.
- **Isolated Worktrees:** Development occurs in assigned Git worktrees linked to feature branches.
- **Honest Provenance:** Never alter Git history or commit timestamps.

---

## 2. Git Workflow & Branching Strategy

```text
main (Submission / Release)
  └── develop (Integration branch)
        ├── feat/mcp-catalog-pinning
        ├── feat/static-description-llm
        ├── feat/sandbox-prober-fixtures
        └── feat/report-api-ui
```

- **Feature Branches:** Created from `develop`.
- **Target Branch:** Pull requests must target `develop`. Merges to `main` are reserved exclusively for stable releases verified by the integration architect.
- **Commit Messages:** Use conventional commits:
  - `feat(catalog): implement live stdio tool discovery`
  - `fix(pinning): handle null annotations in fingerprint calculation`
  - `test(static): add positive control tests for subprocess AST`
  - `docs(contracts): document finding ID generation rules`

---

## 3. Pull Request Checklist

Before submitting a PR to `develop`:
1. Ensure all deterministic unit tests pass:
   ```bash
   python -m pytest tests/unit/ -v
   ```
2. Verify `auditforge doctor` passes without errors:
   ```bash
   python -m auditforge.cli doctor
   ```
3. Complete all fields in `.github/pull_request_template.md`.
4. Ensure no unauthorized files outside your workstream ownership were modified.
