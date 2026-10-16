# AuditForge API Contract & Integration Specification

**Specification Version**: `1.1.0`  
**Governing Branch**: `Shlok`  
**Compliance Target**: PS02 MCP Security Auditor Judging Playbook  

---

## 1. Overview & Architectural Boundary

AuditForge exposes a high-assurance REST API designed for pair-programming and multi-agent coordination. All audit findings originate from real rule engines (AST static analysis, regex & Qwen 2.5 Coder heuristic models, Docker container telemetry, and canonical SHA-256 catalog diffs).

---

## 2. Coordinated API Endpoints

### 2.1 Trigger Security Audit Scan
- **Route**: `POST /api/scan` (alias: `POST /scan`)
- **Description**: Triggers an isolated multi-stage audit on an MCP server target. Rejects arbitrary unrecognized targets when using `target_id`.

#### Request Schema
```json
{
  "target_id": "clean_reader",           // Registered MCP identifier (e.g. clean_reader, rogue_server, poisoned_description, lying_annotations, rug_pull)
  "server_path": "fixtures/clean_reader",// Optional direct filesystem path or GitHub URL
  "server_name": "clean_reader",         // Optional human-readable server name
  "use_llm": false                       // Enable local Qwen 2.5 Coder heuristic intelligence
}
```

#### Response Schema (`ScanResult`)
```json
{
  "scan_id": "scan-a34fce96cdb2",
  "id": "scan-a34fce96cdb2",
  "server_name": "clean_reader",
  "target": "fixtures/clean_reader",
  "trust_state": "VERIFIED",
  "scan_mode": "LIVE_SCAN",
  "stage_coverage": {
    "catalog_discovery": "PASS",
    "static_ast": "PASS",
    "description_intelligence": "PASS",
    "dynamic_probing": "SKIPPED",
    "baseline_pinning": "NOT_PINNED"
  },
  "findings": [],
  "evidence": [
    {
      "evidence_id": "ev-ast-3fa85f64e042",
      "source": "static_ast",
      "tool_name": "read_file",
      "observed_at": "2026-10-16T06:00:00Z",
      "summary": "AST validation passed for read_file handler",
      "raw_data": {}
    }
  ],
  "probe_outcomes": [],
  "started_at": "2026-10-16T06:00:00Z",
  "completed_at": "2026-10-16T06:00:02Z",
  "summary": "Audit completed with trust state VERIFIED. 0 finding(s) backed by 1 evidence capsule(s)."
}
```

#### Allowed `stage_coverage` Values
| Stage | Valid Values | Description |
| :--- | :--- | :--- |
| `catalog_discovery` | `PASS`, `ERROR` | Validates MCP `tools/list` schema integrity |
| `static_ast` | `PASS`, `FAIL`, `SKIPPED` | AST analysis of tool handlers (`readOnlyHint` violations, `os.system`) |
| `description_intelligence` | `PASS`, `FAIL` | Regex and Qwen 2.5 Coder prompt injection heuristic analysis |
| `dynamic_probing` | `PASS`, `FAIL`, `SKIPPED` | Isolated container execution outcomes |
| `baseline_pinning` | `PASS`, `FAIL`, `NOT_PINNED` | Cryptographic SHA-256 catalog drift comparison |

#### Allowed `trust_state` Values
- `VERIFIED` / `APPROVED`: All stages passed, zero high/critical vulnerabilities.
- `ROGUE` / `REVOKED`: Proven dangerous operations (shell execution, credential theft, rug pull).
- `TRUST_GAP`: Contract annotation promises `readOnlyHint: true` but handler mutates state or spawns subprocesses.
- `SUSPICIOUS` / `REVIEW`: Heuristic or unverified anomalous behavior detected.

---

### 2.2 Pin Baseline Snapshot
- **Route**: `POST /api/pin` (alias: `POST /pin`)
- **Description**: Cryptographically anchors the tool catalog as an approved baseline with canonical SHA-256 hashing.

#### Request Schema
```json
{
  "server_id": "clean_reader",
  "catalog_path": "fixtures/clean_reader"  // Supports directory or JSON file
}
```

#### Response Schema
```json
{
  "status": "PINNED",
  "server_id": "clean_reader",
  "catalog_fingerprint": "a3589b2c...",
  "tools_count": 2
}
```

---

### 2.3 Check Catalog Drift & Rug Pull
- **Route**: `POST /api/diff` (alias: `POST /diff`)
- **Description**: Computes field-level differential between the current server catalog and the pinned baseline.

#### Request Schema
```json
{
  "server_id": "clean_reader",
  "catalog_path": "fixtures/rug_pull/catalog_v2.json"
}
```

#### Response Schema
```json
{
  "server_id": "clean_reader",
  "baseline_fingerprint": "a3589b2c...",
  "current_fingerprint": "f892a01d...",
  "is_identical": false,
  "added_tools": ["prompt_injection"],
  "removed_tools": [],
  "modified_tools": {
    "read_file": {
      "annotations": {"readOnlyHint": {"old": true, "new": false}}
    }
  }
}
```

---

### 2.5 Live Stdio Rug-Pull Comparison Demo
- **Route**: `POST /api/demo/rug-pull`
- **Description**: Spawns authentic stdio server processes comparing v1 baseline against v2 mutated server over real MCP protocol and returns field-level diff with cryptographic fingerprints.

---

### 2.6 Sponsor KOALA Model Assurance Sidecar
- **Route**: `GET /api/assurance/model`
- **Route**: `POST /api/assurance/audit`
- **Description**: Audits local AI model (`Qwen2.5-Coder-7B`) against **NIST AI RMF 1.0** and **EU AI Act** using KOALA v0.2.0 by DomAiyn Labs (Apache 2.0).

---

## 3. Registered Evaluation Targets

| Target ID | Path | Threat Vector Audited | Expected Trust State |
| :--- | :--- | :--- | :--- |
| `clean_reader` | `fixtures/clean_reader` | Baseline Safe Read-Only Tool | `VERIFIED` |
| `rogue_server` | `fixtures/rogue_server` | Shell Injection (`os.system`) | `ROGUE` |
| `rogue_server_patched` | `fixtures/rogue_server_patched` | Remediated In-Memory Diagnostic | `VERIFIED` |
| `poisoned_description`| `fixtures/poisoned_description` | Adversarial LLM Prompt Injection | `ROGUE` |
| `poisoned_description_patched` | `fixtures/poisoned_description_patched` | Remediated Parameter Math | `VERIFIED` |
| `lying_annotations` | `fixtures/lying_annotations` | Contract-to-Behavior Trust Gap | `TRUST_GAP` |
| `lying_annotations_patched` | `fixtures/lying_annotations_patched` | Remediated Genuine Read-Only | `VERIFIED` |
| `rug_pull` | `fixtures/rug_pull` | Supply Chain Catalog Mutation | `ROGUE` |
