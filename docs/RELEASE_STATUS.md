# AuditForge — release inventory and verification gate

**Snapshot date:** 2026-10-16  
**Baseline audited:** `main@7ab33d8789372bd7a821f9aee413b2b0e878e570`  
**Release policy:** A commit is considered verified only after GitHub Actions passes on **that exact commit** and relevant local integration tests are recorded. This document is an inventory, not a claim of production certification.

## Branch inventory

| Ref | Status as observed before documentation release |
| --- | --- |
| `main` | Already includes the 2026-10-16 release merge (`7ab33d8`) |
| `develop` | Integration head `e3825f8`; `main` was 3 commits ahead with no resulting file differences |
| AttackLab PR #2 | Open draft, `feat/attacklab-benchmark@32f0f0b`; implemented files were integrated into `develop` before its release merge |
| Detection PR #3 | Open draft, `feat/detection-hardening-v1@782b225`; detector implementation was integrated independently into `develop` before release |

**Do not blindly merge either draft PR again.** Compare actual file diffs, test contracts and commit lineage before closing as superseded or merging any missing patch.

## Included in `main`

- Controlled MCP stdio discovery, 16 target registrations (8 executable local fixtures, 8 source-only benchmark representatives).
- Static AST/Bandit, normalization and contextual prompt-injection triage, optional model providers.
- Docker-supported probes, trust-gap reconciliation, vulnerable/patched comparison and live rug-pull diff.
- Versioned SHA-256 catalog fingerprints and evidence integrity checksums; these are not authenticated external signatures.
- SQLite local storage and optional SQLAlchemy/PostgreSQL persistence and Redis job queue/in-memory fallback.
- Guided/Advanced React UI, Security Intelligence, Jobs & Queue, Evidence Vault and reports.
- Curated four-document BM25 lexical retrieval with finding explanations; no production vector search claimed.
- AttackLab synthetic load/accuracy benchmarking and detection-hardening evaluation data.

## Verification matrix

| Gate | Required evidence |
| --- | --- |
| GitHub Actions 3.11 and 3.12 | Both unit-test matrix jobs green at exact release SHA |
| Python tests | Unit + integration + benchmark summaries, with optional external dependencies described |
| Frontend | `npm --prefix dashboard run build` and browser/API smoke tests |
| Local services | `/api/health`, `/api/fixtures`, `/api/pairs`, a real `POST /api/scan` |
| Vulnerable/patch | Real rule ID + evidence and actual coverage, not hardcoded verdicts |
| Rug pull | Live protocol v1-v2 diff, source fingerprint and storage integrity |
| Security intelligence | Retrieval with actual cited local sources and honest unavailable fallback |
| Queue/storage | SQLite path and optional Postgres/Redis mode tested independently |

## CI issue identified during release audit

The first `main@7ab33d8` GitHub Actions run ([38892387541](https://github.com/Pswaikar1742/AuditForge/actions/runs/38892387541)) failed at collection: `ModuleNotFoundError: No module named 'sqlalchemy'`. The previous workflow installed `.[dev]` but queue/storage unit tests import the optional `prod` extras. This release follow-up updates CI to install `.[dev,prod]`; **verify the new workflow run before treating this fix as complete**.

## Local operation

Use the [README quickstart](../README.md) for safe manual backend/frontend startup; ports 8000 and 5173. The existing `run.sh` terminates any processes on those ports with `fuser -k`, so only run it when safe. `docker-compose.yml` refers to Dockerfiles that are not included in the inspected repository root/dashboard; deployment requires additional validation. Never assume the Compose file is a validated production deployment.

## Remaining production work

- Independently evaluated real-world attack datasets and prompt-injection hardening; current synthetic/author-labelled results do not establish general detection recall.
- Authenticated, tenant-isolated job APIs, cancellation/recovery stress tests and safe external MCP execution isolation.
- Persistent, versioned and access-controlled intelligence retrieval (current BM25 index is in-memory).
- Document provenance/licensing review and post-merge browser/integration evidence.
- Secure Compose images, secrets and Docker socket isolation before exposing services.
