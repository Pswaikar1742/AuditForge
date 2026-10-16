# AUDITFORGE FROZEN SHARED CONTRACTS & SCHEMA SPECIFICATION

**Status:** FROZEN — Any modifications require Lead Integration Architect review.  
**Implementation Source:** [`src/auditforge/core/contracts.py`](file:///run/media/psw/6066FD4C66FD2406/Projects/Auditforge/Forger/src/auditforge/core/contracts.py)

---

## 1. Core Enumerations

### Severity
- `CRITICAL`: Imminent compromise, remote code execution, active credential theft, or unauthorized root subprocess.
- `HIGH`: Unrestricted file system write, covert external network egress, or blatant prompt injection override.
- `MEDIUM`: Lying metadata annotations (e.g. `readOnly=True` with benign state modification), excessive parameters.
- `LOW`: Poor schema constraints, missing property types, undocumented return structures.
- `INFO`: Normal baseline variance, documentation style mismatch, or non-security observations.

### TrustState
- `VERIFIED`: Declared contracts match observed static AST and dynamic container behaviors without anomalies.
- `TRUST_GAP`: Discrepancy between declared metadata (e.g. `readOnly=True`) and observed actions (e.g. file mutations or network egress).
- `SUSPICIOUS`: Unverified findings or ambiguous prompt injection indicators requiring human review.
- `ROGUE`: Malicious behavior detected (reverse shell, credential harvesting, unauthorized exfiltration).
- `UNKNOWN`: Insufficient evidence or unexecuted probes. *Missing evidence must NEVER be interpreted as proof of safety.*

### ProbeStatus
- `OK`: Probe executed successfully and returned a schema-valid response without policy violations.
- `TOOL_ERROR`: Target tool threw an internal runtime exception during execution.
- `TIMEOUT`: Probe exceeded maximum allocated runtime (default 10s).
- `SKIPPED`: Probe could not run (e.g. missing Docker environment, invalid input schema).
- `UNKNOWN`: Probe executed but outcome state could not be conclusively determined.

---

## 2. Shared Data Models

### `ToolRecord`
Normalized representation of an individual MCP tool.
```python
class ToolRecord(BaseModel):
    name: str                           # Unique tool name (e.g. "search_docs")
    title: Optional[str] = None         # Display title
    description: str = ""               # Tool docstring / description
    input_schema: Dict[str, Any] = {}   # JSON Schema for arguments
    output_schema: Optional[Dict] = None# Optional JSON Schema for response
    annotations: Optional[Dict] = None  # MCP annotations (readOnly, destructive, etc.)
    fingerprint: str                    # SHA-256 hash of canonical normalized tool
```

### `ServerSnapshot`
Point-in-time catalog snapshot of an MCP server.
```python
class ServerSnapshot(BaseModel):
    server_id: str                      # Server identifier / command
    timestamp: str                      # UTC ISO 8601 timestamp
    tools: Dict[str, ToolRecord]        # Mapping of tool names to ToolRecords
    catalog_fingerprint: str            # Combined SHA-256 fingerprint of all tools
```

### `EvidenceRecord`
Verifiable factual capsule documenting an observation.
```python
class EvidenceRecord(BaseModel):
    evidence_id: str                    # Unique ID e.g. "ev-ast-7f8a9b1c"
    source: str                         # "static_ast", "bandit", "description_llm", "docker_telemetry", "catalog_diff"
    tool_name: Optional[str] = None     # Target tool name if applicable
    observed_at: str                    # UTC ISO 8601 timestamp
    summary: str                        # Concise factual description
    raw_data: Dict[str, Any]            # Verbatim line quotes, AST node dump, or network log
```

### `Finding`
Security or trust gap finding linked to evidence.
```python
class Finding(BaseModel):
    id: str                             # Unique finding ID e.g. "fnd-AST-001-tool-ab12cd34"
    rule_id: str                        # Rule identifier (e.g. "AST-SHELL-001", "LLM-INJECT-002")
    severity: Severity                  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    tool_name: Optional[str] = None     # Affected tool
    evidence_ids: List[str]             # List of linked EvidenceRecord IDs
    reason: str                         # Detailed explanation of risk
    confidence: float                   # 0.0 to 1.0 confidence score
    remediation: str                    # Clear recommendation for developer
```

### `ProbeCase` & `ProbeOutcome`
Dynamic test case specification and recorded result.
```python
class ProbeCase(BaseModel):
    case_id: str                        # Unique case ID
    tool_name: str                      # Target tool
    input_arguments: Dict[str, Any]     # Schema-valid test arguments
    expected_behavior: str = ""         # Expected behavior specification
    timeout_seconds: float = 10.0       # Timeout budget

class ProbeOutcome(BaseModel):
    case_id: str                        # Linked ProbeCase ID
    tool_name: str                      # Probed tool name
    status: ProbeStatus                 # OK, TOOL_ERROR, TIMEOUT, SKIPPED, UNKNOWN
    return_value: Optional[Any] = None  # Tool return value
    error_message: Optional[str] = None # Error if failed
    duration_ms: float = 0.0            # Execution duration
    telemetry_events: List[Dict] = []   # Guest telemetry events
    evidence_id: Optional[str] = None   # Linked evidence capsule ID
```

### `CatalogDiff`
Field-level comparison between baseline and current catalogs.
```python
class CatalogDiff(BaseModel):
    server_id: str                      # Server ID
    baseline_fingerprint: str           # Approved catalog fingerprint
    current_fingerprint: str            # Current catalog fingerprint
    is_identical: bool                  # True if byte-for-byte identical
    added_tools: List[str] = []         # Newly added tools
    removed_tools: List[str] = []       # Removed tools
    modified_tools: Dict[str, Dict] = {}# Field diffs (description, schema, annotations)
```

### `ScanResult`
Comprehensive, self-contained audit output capsule.
```python
class ScanResult(BaseModel):
    scan_id: str                        # Scan run ID e.g. "scan-4a8b1c2d3e4f"
    target: str                         # Target command or path
    started_at: str                     # UTC ISO 8601 start
    completed_at: Optional[str] = None  # UTC ISO 8601 completion
    trust_state: TrustState             # Final TrustState
    snapshot: Optional[ServerSnapshot]  # Discovered catalog
    diff: Optional[CatalogDiff] = None  # Diff against baseline
    findings: List[Finding] = []        # All findings
    evidence: List[EvidenceRecord] = [] # All evidence capsules
    probe_outcomes: List[ProbeOutcome]=[]# Probe results
    summary: str = ""                   # Executive summary
```

---

## 3. Cryptographic Fingerprinting Rules

1. **Canonical JSON Serialization:**
   - Keys must be sorted alphabetically at all nesting levels.
   - Whitespace delimiters must be strictly `(",", ":")` without extra spaces.
   - Non-ASCII characters must be ASCII-escaped (`ensure_ascii=True`).
2. **Tool Fingerprint (`compute_tool_fingerprint`):**
   - Computed over normalized dictionary containing exactly:
     `{"annotations": ..., "description": ..., "input_schema": ..., "name": ..., "output_schema": ..., "title": ...}`
   - Formatted as standard 64-character lowercase hexadecimal SHA-256.
3. **Catalog Fingerprint (`compute_catalog_fingerprint`):**
   - Sort tool names alphabetically.
   - Extract each tool's 64-character SHA-256 fingerprint in sorted order.
   - Serialize the ordered list to canonical JSON and compute its SHA-256.
