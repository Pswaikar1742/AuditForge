# AUDITFORGE — CANONICAL REST API CONTRACT (v1.0)

**Project:** AuditForge — Evidence-First MCP Security Auditor  
**Lead Backend Architect:** Integration Orchestrator  
**Frontend Collaborator:** Shlok (Dashboard Lead)  
**Security Boundary:** Localhost binding (`127.0.0.1:8000`), strict CORS (`http://localhost:5173`, `http://127.0.0.1:5173`, `http://localhost:3000`), zero host execution for untrusted code.

---

## 1. Authorized Registered Target IDs (Allowlist)

Web clients and dashboards must submit registered target IDs. Arbitrary executable paths, path traversals (`/etc/`, `../`), or untrusted scripts are strictly rejected with `HTTP 400 Bad Request`.

| Target ID | Name / Role | Expected Security Verdict | Planted Finding Rules |
|---|---|---|---|
| `clean_reader` | Fixture A: Clean Reader | `VERIFIED` | 0 findings (Negative Control) |
| `rogue_server` | Fixture B: Rogue Server (Vulnerable) | `ROGUE` | `AST-SHELL-001`, `AST-SUBPROCESS-001` |
| `rogue_server_patched` | Fixture B (Patched): Safe Diagnostic | `VERIFIED` | 0 findings (Remediated Safe Diagnostic) |
| `poisoned_description` | Fixture C: Poisoned Description (Vulnerable) | `ROGUE` | `DESC-INJECT-001`, `DESC-INJECT-002`, `DESC-EXFIL-001` |
| `poisoned_description_patched` | Fixture C (Patched): Clean Metadata | `VERIFIED` | 0 findings (Remediated Clean Metadata) |
| `lying_annotations` | Fixture D: Lying Annotations (Vulnerable) | `TRUST_GAP` | `AST-FILE-002`, `TRUST-GAP-001` |
| `lying_annotations_patched` | Fixture D (Patched): Genuine Read-Only | `VERIFIED` | 0 findings (Remediated Read-Only) |
| `rug_pull` | Fixture E: Controlled Catalog Rug-Pull | `ROGUE` / `TRUST_GAP` | `PIN-RUGPULL-001` upon version mutation |

---

## 2. API Endpoints Specification

### 2.1 System Readiness & Subsystem Diagnostics
- **Endpoint:** `GET /api/health` (also `GET /health`)
- **Response:**
  ```json
  {
    "status": "OK",
    "database": "auditforge.db",
    "ollama_host": "http://127.0.0.1:11434",
    "docker_image": "auditforge-probe:latest"
  }
  ```

### 2.2 Global Statistics
- **Endpoint:** `GET /api/stats` (also `GET /stats`)
- **Response:**
  ```json
  {
    "total_scans": 12,
    "total_baselines": 4,
    "findings_by_severity": {
      "CRITICAL": 5,
      "HIGH": 3,
      "MEDIUM": 2,
      "LOW": 0
    }
  }
  ```

### 2.3 Fixtures & Target Catalog
- **Endpoint:** `GET /api/fixtures` (also `GET /fixtures`)
- **Response:** Array of target metadata objects with `id`, `name`, `role`, `expected`, `tags`, and `path`.

### 2.4 Trigger Security Audit Scan
- **Endpoint:** `POST /api/scan` (also `POST /scan`)
- **Request Body:**
  ```json
  {
    "target_id": "clean_reader",      // Preferred: allowlisted ID
    "server_path": "clean_reader",    // Backward-compatible alias
    "server_name": "clean_reader",    // Optional friendly label
    "use_llm": false                  // Toggle local Qwen2.5-Coder analysis
  }
  ```
- **Response (ScanResult capsule):**
  ```json
  {
    "id": "scan-e4b2a8d10f3c",
    "scan_id": "scan-e4b2a8d10f3c",
    "server_name": "clean_reader",
    "target": "fixtures/clean_reader",
    "trust_state": "VERIFIED",
    "scan_mode": "LIVE_SCAN",
    "stage_coverage": {
      "catalog_discovery": "PASS",
      "static_ast": "PASS",
      "description_intelligence": "PASS",
      "dynamic_probing": "PASS",
      "baseline_pinning": "NOT_PINNED"
    },
    "findings": [],
    "evidence": [],
    "probe_outcomes": [],
    "started_at": "2026-10-16T12:00:00Z",
    "completed_at": "2026-10-16T12:00:03Z",
    "summary": "Audit completed with trust state VERIFIED."
  }
  ```

### 2.5 Scans History & Details
- **Endpoint:** `GET /api/scans?limit=50` (List recent scans)
- **Endpoint:** `GET /api/scans/{scan_id}` (Retrieve full scan result and evidence capsule)
- **Endpoint:** `GET /api/scans/{scan_id}/report?format=json|markdown`
  - Returns `application/json` or `text/markdown` for report exports directly from SQLite.

### 2.6 Baselines & Pin-and-Diff
- **Endpoint:** `GET /api/baselines` (List all pinned server baselines)
- **Endpoint:** `GET /api/baselines/{server_id}` (Retrieve pinned baseline snapshot)
- **Endpoint:** `POST /api/baselines/{server_id}/approve` (Explicitly approve current catalog as baseline)
- **Endpoint:** `POST /api/pin` (Pin catalog from safe path)
- **Endpoint:** `POST /api/diff` (Compare catalog against pinned baseline)

### 2.7 Live Stdio Rug-Pull Demonstration
- **Endpoint:** `POST /api/demo/rug-pull`
- **Behavior:**
  - Queries `fixtures/rug_pull/server.py --version 1` live over stdio JSON-RPC handshake.
  - Queries `fixtures/rug_pull/server.py --version 2` live over stdio JSON-RPC handshake.
  - Generates canonical SHA-256 fingerprint diff and detects field-level parameter/description mutations.
- **Response:**
  ```json
  {
    "status": "RUG_PULL_DETECTED",
    "server_id": "rug_pull",
    "baseline_version": "1",
    "baseline_fingerprint": "562f464e0e9c...",
    "mutated_version": "2",
    "mutated_fingerprint": "6c6e146d5b01...",
    "is_identical": false,
    "added_tools": [],
    "removed_tools": [],
    "modified_tools": {
      "word_count": {
        "description": "Count words in text in-memory. -> Count words after optional lowercase normalization.",
        "input_schema": "..."
      }
    }
  }
  ```
