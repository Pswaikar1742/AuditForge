# AuditForge — Evidence-First MCP Security Auditor

[![CI](https://github.com/Pswaikar1742/AuditForge/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Pswaikar1742/AuditForge/actions/workflows/ci.yml)

> **Don't trust the label. Audit the behavior.**

**Team InnoVision · OpenForge Hackathon 2026 · PS02: MCP Server Security Auditor**

AuditForge audits Model Context Protocol (MCP) servers by comparing claimed tool capabilities with static source evidence, protocol-discovered metadata, selected runtime observations and approved catalog baselines. It reports findings with evidence references, stage coverage and machine-readable reports. An inconclusive or skipped check is **not** proof of safety.

## What's implemented

| Capability | Current implementation |
| --- | --- |
| MCP discovery | Official Python MCP SDK and controlled local stdio fixtures |
| Static analysis | Python AST, Bandit and contract-to-behavior trust-gap checks |
| Description security | Normalization, heuristic/contextual triage and optional bounded Ollama/OpenAI-compatible inference |
| Dynamic probing | Restricted Docker-based probing of supported local targets |
| Catalog integrity | Versioned SHA-256 fingerprints for tools, resources and prompts; approved baselines and live rug-pull comparison |
| Evidence and reports | Linked evidence records, SHA-256 integrity **checksum**, JSON and Markdown reports; a checksum is not an external tamper-proof signature |
| Dashboard | React/Vite Guided Demo and Advanced Audit, target catalog, comparisons, Evidence Vault and reports |
| Security intelligence (RAG-style retrieval) | Four curated local knowledge documents, in-memory BM25 lexical retrieval and evidence-grounded explanations; **not** a pgvector/embedding implementation |
| Asynchronous jobs | Redis-backed queue option with in-memory development fallback, job API and dashboard monitor |
| Persistence | SQLite standalone default, optional SQLAlchemy-backed PostgreSQL path |
| Benchmarks | AttackLab synthetic 100K-item deterministic evaluation; **not** 100K live/concurrent MCP scans |
| Model assurance | Separate KOALA governance audit integration; not an MCP security certification |

## Quickstart — local SQLite demo

Requires Python **3.11 or 3.12**, Node.js/npm and the project dependencies. Docker is needed for supported dynamic probes; Ollama is optional.

```bash
git clone https://github.com/Pswaikar1742/AuditForge.git
cd AuditForge
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev,prod]'
npm --prefix dashboard ci
```

Start the backend (terminal 1):

```bash
.venv/bin/python -m uvicorn auditforge.api.app:app --host 127.0.0.1 --port 8000
```

Start the frontend (terminal 2):

```bash
npm --prefix dashboard run dev -- --host 127.0.0.1 --port 5173 --strictPort
```

Open **http://127.0.0.1:5173/**. API health: **http://127.0.0.1:8000/api/health**; API docs: **http://127.0.0.1:8000/docs**. Check that the header shows **API Connected** before running a demo.

Or use `bash run.sh` in a trusted local terminal; **caution:** the current script uses `fuser -k` on ports 8000 and 5173, terminating processes on those ports. Use the manual commands above when you need to preserve other services.

### Audit and demo commands

```bash
PYTHONPATH=src .venv/bin/python -m auditforge.cli doctor
PYTHONPATH=src .venv/bin/python -m auditforge.cli scan fixtures/rogue_server/ --no-llm
PYTHONPATH=src .venv/bin/python -m auditforge.cli scan fixtures/clean_reader/ --no-llm
PYTHONPATH=src .venv/bin/python -m auditforge.cli demo
```

The CLI `demo` command recreates the separate `auditforge_demo.db`; back up that file if you have data to retain. The regular scan uses the configured database. Keep external/untrusted MCP command execution disabled until isolated discovery and execution are fully validated.

Run tests:

```bash
.venv/bin/python -m pytest tests/unit/ -q
.venv/bin/python -m pytest tests/integration/ tests/benchmarks/ -q
npm --prefix dashboard run build
```

Some integration checks require local Docker, Ollama or KOALA setup. CI currently runs deterministic unit tests for Python 3.11 and 3.12; passing CI is not a guarantee of full-system deployment readiness.

## Optional distributed services

`DATABASE_URL` selects the SQLAlchemy/PostgreSQL path; absent it, SQLite remains the standalone default. `REDIS_URL` configures the optional broker, with a development in-memory fallback. `AUDITFORGE_INFERENCE_PROVIDER` selects `ollama`, `openai_compatible` or `disabled`. See [`.env.example`](.env.example) and [the production architecture design](docs/PRODUCTION_ARCHITECTURE.md).

`docker-compose.yml` is a development **blueprint**, not a verified turnkey deployment: service Dockerfile paths and secrets/network permissions must be reviewed and completed before running it. Never use sample DB passwords or mount the Docker socket in an untrusted deployment.

## Current scope and limitations

- The target catalog has **8 executable team-controlled local fixtures** and **8 source-only benchmark representatives**. The latter do not execute their original upstream repositories.
- The AttackLab 100K measurements cover deterministic description analysis on synthetic data, not concurrent live MCP audits. See [AttackLab methodology](docs/ATTACKLAB.md) and [detection limitations](docs/ATTACKLAB_DETECTION_GAPS.md).
- Hardening improved the published regression examples, but independent small-set recall remains limited. See [detection hardening](docs/DETECTION_HARDENING.md).
- Security intelligence currently uses curated **BM25 lexical retrieval**; embedding/vector indexing, externally verified ingestion and larger-scale retrieval evaluation are not yet demonstrated.
- Production-level authentication, tenancy, host isolation for arbitrary third-party MCP servers, queue recovery guarantees and end-to-end scalability require additional security testing.
- KOALA reports governance checks separately from MCP tool safety and cannot by themselves certify regulatory compliance.

## Documentation

- [Release inventory and verification checklist](docs/RELEASE_STATUS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Production architecture proposal](docs/PRODUCTION_ARCHITECTURE.md)
- [API contracts](docs/API_CONTRACT.md)
- [Security and limits](docs/SECURITY.md)
- [Development](docs/DEVELOPMENT.md)
- [AttackLab benchmarks](docs/ATTACKLAB.md)
- [Detection hardening](docs/DETECTION_HARDENING.md)
- [Contribution guide](CONTRIBUTING.md)

## License

Apache-2.0. Developed by **Team InnoVision** for OpenForge Hackathon 2026.
