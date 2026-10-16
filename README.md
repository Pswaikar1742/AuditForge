# 🛡️ AUDITFORGE — Evidence-First MCP Security Auditor

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![MCP SDK](https://img.shields.io/badge/MCP%20SDK-v2-green.svg)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-178%20Passing-brightgreen.svg)](tests/)
[![Zero Mock Results](https://img.shields.io/badge/Evidence-Zero%20Mock%20Results-orange.svg)](AGENTS.md)
[![Track](https://img.shields.io/badge/OpenForge-Track%201%20Open%20Weight%20AI-orange.svg)](https://github.com/Pswaikar1742/AuditForge)

> **"Don't trust the label. Audit the behavior."**  
> *Team InnoVision | OpenForge Hackathon 2026 | Problem Statement PS02: MCP Server Security Auditor*

---

## 📌 Executive Summary & Vision

Model Context Protocol (MCP) servers act as bridge layers granting Large Language Models access to system tools, file trees, local databases, and external APIs. However, current MCP ecosystems suffer from **blind trust**: agents and users rely on tool docstrings, claimed annotations (e.g. `readOnlyHint=true`), and unverified schemas.

**AuditForge** is an enterprise-grade, evidence-first security auditor that reconciles **claimed contracts** against **observed runtime and static behavior**. Every finding is backed by cryptographic proof—raw AST line quotes, LLM extraction quotes, and containerized kernel telemetry—with zero simulated or mocked outcomes.

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                       AUDITFORGE                                       │
│                                                                                        │
│  ┌───────────────────────┐   ┌──────────────────────────┐   ┌───────────────────────┐  │
│  │   Interactive UI      │   │     Typer / Rich CLI     │   │  Evidence Vault       │  │
│  │ Guided & Advanced Mode│   │   Doctor, Scan, Diff     │   │  JSON & Markdown      │  │
│  └───────────┬───────────┘   └────────────┬─────────────┘   └───────────┬───────────┘  │
│              │                            │                             │              │
│              └────────────────────────────┼─────────────────────────────┘              │
│                                           ▼                                            │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                              FastAPI Control Plane                               │  │
│  │  REST API | RAG Intelligence | Asynchronous Task Queues | Stdio Protocol Bridge   │  │
│  └───────────────────┬──────────────────────────────────────────┬───────────────────┘  │
│                      │                                          │                      │
│       Sync In-Process│                           Task Dispatch  │                      │
│                      ▼                                          ▼                      │
│  ┌──────────────────────────────────────┐            ┌──────────────────────────────┐  │
│  │          Audit Orchestrator          │            │  Redis 7 Task Broker         │  │
│  │                                      │            │  + Async Worker Daemon       │  │
│  │  • Stdio Discovery & Normalization   │            └──────────────┬───────────────┘  │
│  │  • Hardened AST & Bandit Analysis    │                           │                  │
│  │  • Multi-Layer Prompt Injection (NLP)│                           ▼                  │
│  │  • Ephemeral Docker Probing (none)   │            ┌──────────────────────────────┐  │
│  │  • Trust Gap Reconciliation          │            │  Worker Pool Nodes           │  │
│  │  • Catalog Pinning & Drift Diffs     │            │  (Concurrent Scan Workers)   │  │
│  └───────────────────┬──────────────────┘            └──────────────┬───────────────┘  │
│                      │                                              │                  │
│                      └───────────────────────┬──────────────────────┘                  │
│                                              ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                          Dual Persistence Engine                                 │  │
│  │  • Developer Mode: Zero-Dependency SQLite WAL + Canonical SHA-256 Hashes          │  │
│  │  • Enterprise Mode: PostgreSQL 16 Connection Pooling + JSONB Evidence Capsules   │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Master 1-Command Startup

Launch the entire stack (FastAPI backend, Vite React dashboard, automated port cleanup, readiness healthcheck, and browser) with a single command:

```bash
./run.sh
```

- Cleans existing listeners on ports `8000` (API) and `5173` (UI).
- Spawns the uvicorn backend and polls `/api/health` until ready.
- Boots the Vite React dashboard and auto-opens your browser.
- Cleanly shuts down the entire process tree on `Ctrl+C`.

---

## 🚀 Key Architectural Pillars

### 1. 🛡️ Hardened Multi-Layer Detection (M1)
- **Evasion-Resistant Normalization:** Unicode NFKC normalization, selective zero-width character stripping (U+200B, U+2060, U+FEFF), whitespace collapse, and markdown stripping.
- **Multi-Encoding Decoders:** Automatically identifies and decodes Base64, Rot13, Hex, and URL-encoded adversarial payloads before heuristic inspection.
- **Contextual AST Triage:** Differentiates production vulnerabilities from test mocks, example code, and benign references. Honors inline suppression (`# auditforge: ignore`) and tracks tainted variable flows.
- **Pluggable Architecture:** Extensible `DetectionProvider` SPI supporting heuristic regex, semantic LLM, and contextual rule providers.

### 2. 🧠 RAG Security Intelligence & Remediation Playbooks (M2)
- **Grounded Vulnerability Corpus:** Curated repository of MCP vulnerability patterns (`data/vulnerability_corpus.json`) covering command execution, prompt injection, and privilege escalation.
- **BM25 Trust-Tier Indexing:** High-speed, deterministic lexical retrieval for grounding audit findings without hallucination risk.
- **Actionable Remediation Playbooks:** Returns exact code-fix diffs, safe implementation alternatives, and security control mappings (`/api/intelligence/remediation`).
- **Quarantine Sandbox Generator:** Automatically generates isolated, privilege-stripped sandbox wrappers for detected vulnerable tools (`/api/intelligence/quarantine`).

### 3. ⚡ Production PostgreSQL & Distributed Job Queues (M3)
- **Dual Storage Engine:** Seamless fallback between zero-setup SQLite WAL (air-gapped/local) and clustered PostgreSQL 16 (enterprise).
- **Redis Asynchronous Job Queues:** Background audit dispatching (`POST /api/jobs/submit`) and polling (`GET /api/jobs/{id}`) with retry logic and status tracking.
- **Worker Daemon:** Scalable worker process (`python -m auditforge.queue.worker`) for high-throughput batch auditing.
- **Database Migration CLI:** Non-destructive SQLite-to-PostgreSQL migration with row count and cryptographic integrity verification (`python scripts/migrate.py`).
- **Docker Compose Orchestration:** Full multi-container stack (`docker-compose.yml`) orchestrating Postgres, Redis, API, Worker, and UI.

### 4. 🔍 Interactive Mission Control Dashboard
- **Dual Operational Modes:**
  - **Guided Demo Mode:** Human-friendly explanations, preconfigured vulnerable vs. clean targets, and expected outcomes.
  - **Advanced Audit Mode:** Raw AST inspection, full JSON evidence capsules, container telemetry, and cryptographic fingerprints.
- **16 Registered Targets:** Instant selection across 5 live competition fixtures, 3 remediated patches, and 8 official MCP benchmarks.
- **Saved Markdown Reports Vault:** In-browser browsing and rendering of historical audit reports (`/api/reports`).
- **Live Supply Chain Diff Viewer:** Visual side-by-side diffing of modified schemas, added tools, and altered annotations (`PIN-RUGPULL-001`).

### 5. 📋 Evidence Integrity & KOALA Model Assurance
- **Zero Mock Policy:** Dynamic analysis runs exclusively in ephemeral Docker containers (`network_mode="none"`, memory capped at 256MB, CPU quota 50%).
- **Tamper-Evident Evidence Capsules:** Cryptographic SHA-256 evidence digests seal findings at observation time.
- **Sponsor KOALA Integration:** Evaluates local models (Qwen 2.5 Coder) against NIST AI RMF and EU AI Act with unique per-run temp isolation and runtime vs. static audit differentiation.

---

## 💻 Tech Stack

| Component | Technology | Rationale |
|---|---|---|
| **Backend Runtime** | Python 3.12 | Peak performance and full MCP SDK v2 compatibility |
| **MCP Protocol** | Official MCP Python SDK (`mcp>=2.0.0`) | Compliant stdio client discovery and schema normalization |
| **CLI Framework** | Typer + Rich | Formatted diagnostics, interactive progress, and doctor checks |
| **Static Analysis** | Python `ast` + Bandit | Node visitor for shell injection, file mutations, and credential access |
| **Open-Weight AI** | Qwen 2.5 Coder / Llama 3.2 via Ollama | Zero proprietary API dependence; 100% local, air-gapped inference |
| **Sandbox Isolation** | Docker (`auditforge-probe:latest`) | Non-root, 256MB RAM cap, 50% CPU quota, `network_mode="none"` |
| **Guest Telemetry** | Python Audit Hooks (`sys.addaudithook`) | Intercepts `subprocess.Popen`, `socket.connect`, and `open` calls |
| **Primary Persistence** | SQLite (WAL) / PostgreSQL 16 | Seamless dual-engine persistence with canonical JSON serialization |
| **Task Queue** | Redis 7 + Background Worker | Horizontally scalable async scanning with exponential backoff |
| **API Control Plane** | FastAPI + Uvicorn | High-throughput REST API with Pydantic v2 schemas |
| **Dashboard** | React + Vite + Tailwind CSS + Lucide | Mission control UI with live streaming and evidence inspection |
| **Assurance Sidecar**| KOALA v0.2.0 (DomAiyn Labs) | NIST AI RMF and EU AI Act model governance auditing |
| **Test Suite** | pytest (178 passing tests) | Deterministic unit, integration, benchmark, and queue suites |

---

## 🎯 Benchmark Matrix & Registered Targets

AuditForge includes 16 built-in targets covering live MCP servers, remediated patches, and source benchmarks:

| Target ID | Type | Vulnerability / Threat Vector | Expected Trust State |
|---|---|---|---|
| `clean_reader` | Live MCP | Baseline Safe Read-Only File Tool | `VERIFIED` |
| `rogue_server` | Live MCP | Shell Command Injection (`os.system`) | `ROGUE` |
| `rogue_server_patched` | Live MCP | Remediated In-Memory Safe Diagnostic | `VERIFIED` |
| `poisoned_description` | Live MCP | Adversarial Prompt Injection / Hidden Override | `ROGUE` |
| `poisoned_description_patched` | Live MCP | Remediated Parameter Arithmetic | `VERIFIED` |
| `lying_annotations` | Live MCP | Contract-to-Behavior Trust Gap (`readOnly=True` but writes) | `TRUST_GAP` |
| `lying_annotations_patched` | Live MCP | Remediated Genuine Read-Only Tool | `VERIFIED` |
| `rug_pull` | Live MCP | Supply Chain Catalog Drift & Injected Tools | `ROGUE` |
| `official-mcp-time` | Benchmark | Official Time MCP Server | `VERIFIED` |
| `official-mcp-fetch` | Benchmark | Official Fetch Server (SSRF / URL Open Audit) | `SUSPICIOUS` |
| `official-mcp-git` | Benchmark | Official Git Server (Process Spawns) | `SUSPICIOUS` |
| `official-mcp-filesystem`| Benchmark | Official Filesystem Server (Scoped File Operations) | `VERIFIED` |
| `official-mcp-memory` | Benchmark | Official Memory Server (In-Memory Knowledge Graph) | `VERIFIED` |
| `appsecco-mcp-command-exec` | Benchmark | Appsecco Command Execution Vulnerability Suite | `ROGUE` |
| `appsecco-mcp-path-traversal` | Benchmark | Appsecco Path Traversal Vulnerability Suite | `ROGUE` |
| `appsecco-mcp-sql-injection` | Benchmark | Appsecco SQL Injection Vulnerability Suite | `ROGUE` |

---

## 🛠️ Step-by-Step Installation & Usage

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/Pswaikar1742/AuditForge.git
cd AuditForge

# Create and activate virtual environment (Python 3.12 recommended)
uv venv --python /home/psw/.local/bin/python3.12 .venv
source .venv/bin/activate

# Install editable package with dev dependencies
uv pip install -e ".[dev]"
```

### 2. Verify Environment (Doctor)

```bash
python -m auditforge.cli doctor
```

All 6 environment checks (Python version, Docker availability, Probe image, MCP SDK, Database, and Ollama) will be evaluated with actionable diagnostic hints.

### 3. Run Test Suite (178 Tests)

```bash
python -m pytest tests/ -v
```

### 4. Run CLI Audit & Pinning

```bash
# Execute full multi-stage audit on an MCP server
python -m auditforge.cli scan fixtures/clean_reader/server.py --id clean_reader

# Pin an approved cryptographic baseline
python -m auditforge.cli pin fixtures/clean_reader/catalog.json --id clean_reader

# Detect catalog drift or rug-pull mutation against pinned baseline
python -m auditforge.cli diff fixtures/rug_pull/catalog_v2.json --id clean_reader
```

### 5. Run Full End-to-End Demo Script

```bash
./scripts/demo.sh
```

Executes all 6 validation stages:
1. System diagnostics & doctor check
2. Clean baseline audit & pinning (`clean_reader`)
3. Remote Code Execution detection (`rogue_server`)
4. Prompt injection detection (`poisoned_description`)
5. Trust-gap detection (`lying_annotations`)
6. Dynamic supply chain rug-pull drift detection (`rug_pull`)

---

## 🐳 Enterprise Deployment (Docker Compose)

To run the complete distributed enterprise stack (FastAPI + Worker + PostgreSQL + Redis + React Dashboard):

```bash
docker-compose up --build -d
```

- **React Dashboard:** [http://localhost:5173](http://localhost:5173)
- **FastAPI Documentation:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **PostgreSQL Database:** `localhost:5432` (`auditforge` / `auditforge`)
- **Redis Queue Broker:** `localhost:6379`

### Migrating Existing Data (SQLite ➔ PostgreSQL)

```bash
python scripts/migrate.py --sqlite data/auditforge.db --postgres postgresql://auditforge:auditforge@localhost:5432/auditforge
```

---

## 🌐 Complete REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Healthcheck and service readiness probe |
| `GET` | `/api/targets` | List all 16 registered audit targets and benchmarks |
| `GET` | `/api/scans` | List historical audit scans with pagination and filters |
| `GET` | `/api/scans/{id}` | Retrieve complete audit evidence capsule for a scan |
| `POST` | `/api/scan` | Trigger immediate synchronized multi-stage audit |
| `POST` | `/api/compare/pair_rug_pull` | Compare v1 vs v2 authentic stdio processes for rug-pull drift |
| `POST` | `/api/pin` | Pin an approved canonical catalog baseline |
| `GET` | `/api/pin/{server_id}` | Retrieve pinned baseline details and SHA-256 fingerprint |
| `POST` | `/api/diff/{server_id}` | Compare submitted catalog against pinned baseline |
| `GET` | `/api/intelligence/recommendations/{finding_id}` | Retrieve grounded RAG remediation for a finding |
| `POST` | `/api/intelligence/remediation` | Synthesize complete remediation playbook and safe code patch |
| `POST` | `/api/intelligence/quarantine` | Generate isolated quarantine sandbox wrapper for dangerous tool |
| `POST` | `/api/jobs/submit` | Submit asynchronous audit task to Redis queue |
| `GET` | `/api/jobs/{job_id}` | Query status and result of asynchronous queue job |
| `GET` | `/api/jobs` | Monitor Redis worker queue metrics and active jobs |
| `GET` | `/api/reports` | List all saved Markdown audit reports |
| `GET` | `/api/reports/{filename}` | Retrieve raw Markdown content of saved audit report |
| `GET` | `/api/assurance/model` | Retrieve latest KOALA model governance assurance audit |
| `POST` | `/api/assurance/audit` | Execute live KOALA model evaluation against NIST / EU AI Act |

---

## 🔒 Security & Containment Guardrails

In strict adherence to the project directive:
1. **Zero Host Execution:** Target MCP code is **never** executed directly on the host operating system during dynamic analysis.
2. **Strict Docker Isolation:** Probes run inside ephemeral containers configured with:
   - `network_mode: "none"` (No outbound or inbound network access)
   - `mem_limit: 256m` (Strict memory ceiling)
   - `cpu_quota: 50000` / `cpu_period: 100000` (Max 50% single CPU core)
   - `user: "1000:1000"` (Non-root execution)
   - Ephemeral read-only root filesystems with isolated `/tmp` tmpfs mounts.
3. **Audit Hook Telemetry:** Monitored via internal Python audit hooks (`sys.addaudithook`) to capture low-level system attempts without substituting container security boundaries.

---

## 👥 Authors & Attribution

- Developed by **Team InnoVision** for **OpenForge Hackathon 2026** (Problem Statement PS02: MCP Server Security Auditor).
- Protected human teammate workstream: `Shlok` (UI & Dashboard foundations).
- Released under the [Apache 2.0 License](LICENSE).
