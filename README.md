# 🛡️ AUDITFORGE — Evidence-First MCP Security Auditor

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![MCP SDK](https://img.shields.io/badge/MCP%20SDK-v2-green.svg)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Track](https://img.shields.io/badge/OpenForge-Track%201%20Open%20Weight%20AI-orange.svg)](https://github.com/Pswaikar1742/AuditForge)

> **"Don't trust the label. Audit the behavior."**  
> *Team InnoVision | OpenForge Hackathon 2026 | Problem Statement PS02: MCP Server Security Auditor*

---

## 📌 Problem & Vision

Model Context Protocol (MCP) servers act as bridge layers between Large Language Models and host system tools, APIs, and databases. However, existing MCP deployments rely almost entirely on blind faith in tool names, docstrings, and claimed metadata annotations.

**AuditForge** is an open-source, evidence-first security auditor for MCP servers that systematically reconciles **claimed contracts** against **observed runtime and static behavior**.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                              AUDITFORGE                                │
│                                                                        │
│  ┌──────────────┐   ┌───────────────┐   ┌───────────────────────────┐  │
│  │  CLI (Typer) │   │ React / Vite  │   │  Evidence Reports Engine  │  │
│  │   + Rich     │   │   Dashboard   │   │  JSON Capsules & Markdown │  │
│  └──────┬───────┘   └───────┬───────┘   └─────────────┬─────────────┘  │
│         │                   │                         │                │
│         └───────────┬───────┴─────────────────────────┘                │
│                     ▼                                                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      Audit Orchestrator                          │  │
│  │  scan() → catalog → static → desc → prober → trust gap → report  │  │
│  └──────────┬───────────┬───────────┬───────────┬───────────────────┘  │
│             │           │           │           │                      │
│      ┌──────▼─────┐ ┌───▼────┐  ┌───▼────┐  ┌───▼─────┐                │
│      │ MCP Client │ │ Static │  │ Desc   │  │ Dynamic │                │
│      │ Discovery  │ │ AST +  │  │ Layer  │  │ Docker  │                │
│      │ & Pinning  │ │ Bandit │  │ 0+1+2  │  │ Sandbox │                │
│      └────────────┘ └────────┘  └────────┘  └─────────┘                │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      SQLite & Cryptographic Store                │  │
│  │  SHA-256 Canonical Fingerprints | Verifiable Evidence Capsules   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Architectural Pillars

1. **Protocol Discovery & Canonical Normalization:** Connects via MCP stdio transport, normalizes JSON schemas, and computes deterministic SHA-256 fingerprints for tools and catalogs.
2. **Static AST & Bandit Analysis:** Deep AST inspection for dangerous calls (`os.system`, `subprocess`, file mutations, socket connections, credential access).
3. **Open-Weight Description Intelligence:** Layer 0 deterministic heuristic screening combined with Layer 1 & 2 semantic analysis via local **Qwen3.5:9b** / **Llama3.2** through Ollama.
4. **Isolated Container Probing:** Ephemeral Docker sandbox execution with non-root security, memory limits (256MB), CPU quotas, disabled network (`none`), and guest telemetry.
5. **Contract-to-Behavior Trust Gap Analysis:** Identifies discrepancies when a tool claimed to be `readOnly=True` or benign performs writes or network calls.
6. **Catalog Pinning & Rug Pull Alerts:** Detects unauthorized post-deployment changes, newly injected tools, or poisoned descriptions across versions.
7. **Verifiable Evidence Capsules:** Every finding includes exact code lines, LLM quotes, or container telemetry logs.

---

## 💻 Tech Stack

| Component | Technology | Rationale |
|---|---|---|
| **Backend Runtime** | Python 3.12 | Optimal performance and full MCP SDK v2 compatibility |
| **MCP Integration** | Official MCP Python SDK (`mcp>=2.0.0`) | Standards compliance for stdio client and tool schemas |
| **CLI** | Typer + Rich | Formatted terminal diagnostics, tables, and progress bars |
| **Static Analysis** | Python `ast` + Bandit | AST node visitor for shell injection, file writes, and secrets |
| **Open-Weight AI** | Qwen3.5:9b / Llama3.2 via Ollama | Zero proprietary API dependence; 100% local inference |
| **Sandbox Isolation** | Docker (`auditforge-probe:latest`) | Namespace isolation, resource limits, and network isolation |
| **Guest Telemetry** | Python Audit Hooks (`sys.addaudithook`) | In-container telemetry for file and socket events |
| **Storage & Hashing**| SQLite + SHA-256 | Canonical JSON serialization and local persistence |
| **API** | FastAPI + Uvicorn | REST API for dashboard integration and CI pipelines |
| **Dashboard** | React + Vite + Tailwind/Lucide | Real-time scan monitoring and evidence capsule inspection |
| **Tests** | pytest | Deterministic unit and integration test suite |

---

## ⚡ Quickstart

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/Pswaikar1742/AuditForge.git
cd AuditForge

# Create and activate virtual environment
uv venv --python /home/psw/.local/bin/python3.12 .venv
source .venv/bin/activate

# Install editable package with dev dependencies
uv pip install -e ".[dev]"
```

### 2. Run Diagnostics & Health Check

```bash
# Run system doctor
python -m auditforge.cli doctor
```

### 3. Run Unit Tests

```bash
python -m pytest tests/unit/ -v
```

### 4. Catalog Pinning & Diff Example

```bash
# Pin an approved baseline
python -m auditforge.cli pin fixtures/clean_reader/catalog.json --id clean_reader

# Compare against a modified rug-pull catalog
python -m auditforge.cli diff fixtures/rug_pull/catalog_v2.json --id clean_reader
```

---

## 👥 Parallel Workstream Branches & Worktrees

Development is partitioned across dedicated branches and worktrees to avoid conflicts:

- `feat/mcp-catalog-pinning` (`../auditforge-mcp`): MCP stdio client discovery & catalog pinning.
- `feat/static-description-llm` (`../auditforge-analysis`): Static AST scanning & Qwen prompt injection detection.
- `feat/sandbox-prober-fixtures` (`../auditforge-sandbox`): Docker sandbox runner & test fixtures.
- `feat/report-api-ui` (`../auditforge-ui`): FastAPI REST service & React/Vite dashboard.
- `develop`: Integration branch where tested feature PRs merge.
- `main`: Release branch for tested hackathon submissions.

See [`docs/WORKSTREAMS.md`](file:///run/media/psw/6066FD4C66FD2406/Projects/Auditforge/Forger/docs/WORKSTREAMS.md) for full coordination rules.

---

## 📄 License & Attribution

- Released under the [Apache 2.0 License](LICENSE).
- Developed by **Team InnoVision** for OpenForge Hackathon 2026.
- Pre-event exploratory research and architecture plans disclosed per event rules. All core competition commits and workstreams are tracked with authentic git provenance.
