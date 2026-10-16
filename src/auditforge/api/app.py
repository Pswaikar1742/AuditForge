"""AuditForge FastAPI Application.

REST API for MCP Security Auditing, Evidence Capsules, and Catalog Pinning.
"""

import asyncio
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from auditforge.assurance.koala import KoalaAssuranceRunner, KoalaReport
from auditforge.config import config
from auditforge.core.contracts import CatalogDiff, ScanResult, ServerSnapshot, TrustState
from auditforge.catalog.client import MCPCatalogClient
from auditforge.catalog.pinning import diff_catalogs
from auditforge.orchestrator import ScanOrchestrator
from auditforge.reports.markdown import generate_markdown_report
from auditforge.storage.database import Database

app = FastAPI(
    title="AuditForge Security Auditor API",
    version="0.1.0",
    description="REST API for MCP Security Auditing, Evidence Capsules, and Catalog Pinning",
)

# Restrict CORS strictly to local development origins
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

_db_instance: Optional[Database] = None
_orchestrator_instance: Optional[ScanOrchestrator] = None


def get_db() -> Database:
    global _db_instance
    if _db_instance is None:
        _db_instance = Database(config.DB_PATH)
    return _db_instance


def set_db(new_db: Database) -> None:
    global _db_instance
    _db_instance = new_db


def get_orchestrator() -> ScanOrchestrator:
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = ScanOrchestrator(db=get_db())
    return _orchestrator_instance


def set_orchestrator(new_orch: ScanOrchestrator) -> None:
    global _orchestrator_instance
    _orchestrator_instance = new_orch


FIXTURES_META = [
    {
        "id": "clean_reader",
        "name": "Fixture A: Clean Reader",
        "role": "Negative Control",
        "category": "COMPETITION LIVE MCP",
        "execution_mode": "LIVE_SCAN",
        "expected": "0 Vulnerabilities (TrustState: VERIFIED)",
        "tags": ["Read-Only", "No Execution", "Safe Baseline"],
        "path": "fixtures/clean_reader",
    },
    {
        "id": "rogue_server",
        "name": "Fixture B: Rogue Server (Vulnerable)",
        "role": "Positive Control",
        "category": "COMPETITION LIVE MCP",
        "execution_mode": "LIVE_SCAN",
        "expected": "AST-SHELL-001 Shell Execution & AST-SUBPROCESS-001 (TrustState: ROGUE)",
        "tags": ["Command Injection", "os.system", "Subprocess"],
        "path": "fixtures/rogue_server",
    },
    {
        "id": "rogue_server_patched",
        "name": "Fixture B (Patched): Safe Diagnostic",
        "role": "Remediated Control",
        "category": "PATCHED MCP",
        "execution_mode": "LIVE_SCAN",
        "expected": "0 Vulnerabilities (TrustState: VERIFIED, No Subprocess/Shell)",
        "tags": ["Remediated", "In-Memory Diagnostic", "Safe"],
        "path": "fixtures/rogue_server_patched",
    },
    {
        "id": "poisoned_description",
        "name": "Fixture C: Poisoned Description (Vulnerable)",
        "role": "Prompt Injection Control",
        "category": "COMPETITION LIVE MCP",
        "execution_mode": "LIVE_SCAN",
        "expected": "DESC-INJECT-001 Directive & DESC-EXFIL-001 Credential Theft (TrustState: ROGUE)",
        "tags": ["Prompt Injection", "Secret Exfiltration", "Adversarial NLP"],
        "path": "fixtures/poisoned_description",
    },
    {
        "id": "poisoned_description_patched",
        "name": "Fixture C (Patched): Clean Metadata",
        "role": "Remediated Control",
        "category": "PATCHED MCP",
        "execution_mode": "LIVE_SCAN",
        "expected": "0 Vulnerabilities (TrustState: VERIFIED, No Injection)",
        "tags": ["Remediated", "Clean Description", "Safe"],
        "path": "fixtures/poisoned_description_patched",
    },
    {
        "id": "lying_annotations",
        "name": "Fixture D: Lying Annotations (Vulnerable)",
        "role": "Trust Gap Demonstration",
        "category": "COMPETITION LIVE MCP",
        "execution_mode": "LIVE_SCAN",
        "expected": "TRUST-GAP-001 Contract-to-Behavior Trust Gap Violation (TrustState: TRUST_GAP)",
        "tags": ["Trust Gap USP", "readOnlyHint Violation", "Static & Dynamic"],
        "path": "fixtures/lying_annotations",
    },
    {
        "id": "lying_annotations_patched",
        "name": "Fixture D (Patched): Genuine Read-Only",
        "role": "Remediated Control",
        "category": "PATCHED MCP",
        "execution_mode": "LIVE_SCAN",
        "expected": "0 Vulnerabilities (TrustState: VERIFIED, No Deletion)",
        "tags": ["Remediated", "Genuine Read-Only", "Safe"],
        "path": "fixtures/lying_annotations_patched",
    },
    {
        "id": "rug_pull",
        "name": "Fixture E: Rug Pull (Catalog Drift)",
        "role": "Cryptographic Pin-and-Diff",
        "category": "COMPETITION LIVE MCP",
        "execution_mode": "LIVE_SCAN",
        "expected": "PIN-RUGPULL-001 Baseline Hash Mismatch",
        "tags": ["Rug Pull Defense", "SHA-256 Pinning", "Drift Detection"],
        "path": "fixtures/rug_pull",
    },
    # Source-Only Reference Benchmarks (Public Corpus)
    {
        "id": "official-mcp-time",
        "name": "Official MCP Time",
        "role": "Public Reference Benchmark",
        "category": "SOURCE-ONLY REFERENCE BENCHMARK",
        "execution_mode": "SNAPSHOT_ANALYSIS",
        "expected": "0 Static Findings (Clean Time Tools)",
        "tags": ["Source-Only", "Official Reference", "Deterministic"],
        "path": "benchmarks/targets/official-mcp-time",
    },
    {
        "id": "official-mcp-fetch",
        "name": "Official MCP Fetch",
        "role": "Public Reference Benchmark",
        "category": "SOURCE-ONLY REFERENCE BENCHMARK",
        "execution_mode": "SNAPSHOT_ANALYSIS",
        "expected": "BANDIT-B310 URL Open (Source Indicator)",
        "tags": ["Source-Only", "Official Reference", "Network"],
        "path": "benchmarks/targets/official-mcp-fetch",
    },
    {
        "id": "official-mcp-git",
        "name": "Official MCP Git",
        "role": "Public Reference Benchmark",
        "category": "SOURCE-ONLY REFERENCE BENCHMARK",
        "execution_mode": "SNAPSHOT_ANALYSIS",
        "expected": "AST-SUBPROCESS-001/002 Git Process Execution",
        "tags": ["Source-Only", "Official Reference", "Subprocess"],
        "path": "benchmarks/targets/official-mcp-git",
    },
    {
        "id": "official-mcp-filesystem",
        "name": "Official MCP Filesystem",
        "role": "Public Reference Benchmark",
        "category": "SOURCE-ONLY REFERENCE BENCHMARK",
        "execution_mode": "SNAPSHOT_ANALYSIS",
        "expected": "AST-FILE-001 Filesystem Access",
        "tags": ["Source-Only", "Official Reference", "Filesystem"],
        "path": "benchmarks/targets/official-mcp-filesystem",
    },
    {
        "id": "appsecco-secrets-pii",
        "name": "Appsecco Secrets & PII",
        "role": "Public Reference Benchmark",
        "category": "SOURCE-ONLY REFERENCE BENCHMARK",
        "execution_mode": "SNAPSHOT_ANALYSIS",
        "expected": "Deterministic Baseline (No Shell)",
        "tags": ["Source-Only", "Appsecco", "Secrets"],
        "path": "benchmarks/targets/appsecco-secrets-pii",
    },
    {
        "id": "appsecco-filesystem-workspace-actions",
        "name": "Appsecco Workspace Actions",
        "role": "Public Reference Benchmark",
        "category": "SOURCE-ONLY REFERENCE BENCHMARK",
        "execution_mode": "SNAPSHOT_ANALYSIS",
        "expected": "AST-SHELL-001 & BANDIT-B605 Shell Commands",
        "tags": ["Source-Only", "Appsecco", "Shell Command"],
        "path": "benchmarks/targets/appsecco-filesystem-workspace-actions",
    },
    {
        "id": "appsecco-indirect-prompt-injection",
        "name": "Appsecco Indirect Prompt Injection",
        "role": "Public Reference Benchmark",
        "category": "SOURCE-ONLY REFERENCE BENCHMARK",
        "execution_mode": "SNAPSHOT_ANALYSIS",
        "expected": "DESC-INJECT-001/002 & DESC-EXFIL-001",
        "tags": ["Source-Only", "Appsecco", "Prompt Injection"],
        "path": "benchmarks/targets/appsecco-indirect-prompt-injection",
    },
    {
        "id": "appsecco-malicious-tools",
        "name": "Appsecco Malicious Tools",
        "role": "Public Reference Benchmark",
        "category": "SOURCE-ONLY REFERENCE BENCHMARK",
        "execution_mode": "SNAPSHOT_ANALYSIS",
        "expected": "BANDIT-B307 Insecure Eval",
        "tags": ["Source-Only", "Appsecco", "Eval Execution"],
        "path": "benchmarks/targets/appsecco-malicious-tools",
    },
]

REGISTERED_FIXTURE_IDS = {f["id"]: f["path"] for f in FIXTURES_META}

COMPARISON_PAIRS_META = [
    {
        "id": "pair_rogue_server",
        "title": "Command Injection vs. Safe In-Memory Diagnostic",
        "description": "Demonstrates detection of unauthorized subprocess and os.system shell calls in positive control server, and their complete elimination in the safe diagnostic version.",
        "vulnerable_target_id": "rogue_server",
        "patched_target_id": "rogue_server_patched",
        "key_vulnerability": "AST-SHELL-001 (os.system) & AST-SUBPROCESS-001 (subprocess.Popen)",
        "remediation_summary": "Replaced external shell execution with deterministic internal in-memory diagnostic logic.",
    },
    {
        "id": "pair_poisoned_description",
        "title": "Adversarial Prompt Injection vs. Clean Tool Metadata",
        "description": "Demonstrates detection of prompt injection directives and credential exfiltration instructions hidden in tool descriptions, and clean verified metadata in the patched version.",
        "vulnerable_target_id": "poisoned_description",
        "patched_target_id": "poisoned_description_patched",
        "key_vulnerability": "DESC-INJECT-001 (Directive Override) & DESC-EXFIL-001 (Secret Exfiltration)",
        "remediation_summary": "Sanitized tool description to state only legitimate currency conversion parameters.",
    },
    {
        "id": "pair_lying_annotations",
        "title": "Lying readOnly Annotations vs. Genuine Read-Only",
        "description": "Demonstrates AuditForge's USP: Trust Gap reconciler catching tools declaring readOnly=True in annotations while executing destructive file removals in implementation.",
        "vulnerable_target_id": "lying_annotations",
        "patched_target_id": "lying_annotations_patched",
        "key_vulnerability": "TRUST-GAP-001 (Contract-to-behavior discrepancy) & AST-FILE-002 (os.remove)",
        "remediation_summary": "Eliminated destructive file removal and enforced strict read-only file viewing.",
    },
    {
        "id": "pair_rug_pull",
        "title": "Supply Chain Baseline Pinning vs. Rug-Pull Mutated Catalog",
        "description": "Demonstrates cryptographic SHA-256 baseline pinning catching unauthorized post-approval capabilities and backdoor tools.",
        "vulnerable_target_id": "rug_pull",
        "patched_target_id": "clean_reader",
        "key_vulnerability": "PIN-RUGPULL-001 (Post-approval capability drift / added backdoor_eval)",
        "remediation_summary": "Strict catalog hash verification rejects server until re-evaluated and approved.",
    },
]


class HealthResponse(BaseModel):
    status: str
    database: str
    ollama_host: str
    docker_image: str


class ScanRequest(BaseModel):
    target_id: Optional[str] = None
    server_path: Optional[str] = None
    server_name: Optional[str] = None
    use_llm: bool = False


def _format_scan_dict(res: ScanResult) -> Dict[str, Any]:
    """Format ScanResult dict ensuring id/scan_id, server_name, catalog_hash, status, and scan_mode are populated for UI."""
    data = res.model_dump()
    data["id"] = res.scan_id
    server_name = res.snapshot.server_id if res.snapshot else Path(res.target).name
    data["server_name"] = server_name
    data["catalog_hash"] = res.snapshot.catalog_fingerprint if res.snapshot else None
    data["status"] = "COMPLETED" if res.completed_at else "IN_PROGRESS"
    data["scan_mode"] = res.scan_mode
    return data


def _validate_safe_target(server_path: Optional[str], target_id: Optional[str] = None) -> Tuple[str, str]:
    """Validate target ID or path to enforce strict allowlisting against arbitrary execution."""
    raw = (target_id or server_path or "").strip()
    if not raw:
        raise HTTPException(
            status_code=400,
            detail="Missing required target identifier ('target_id' or 'server_path').",
        )

    # 1. Exact match against registered target ID
    if raw in REGISTERED_FIXTURE_IDS:
        return REGISTERED_FIXTURE_IDS[raw], raw

    # 2. Path provided: verify it strictly matches an authorized fixture relative path
    cleaned = raw.rstrip("/")
    for fid, fpath in REGISTERED_FIXTURE_IDS.items():
        if cleaned == fpath or cleaned == str(Path(fpath).resolve()):
            return fpath, fid

    # Reject unauthorized targets, absolute paths, and path traversal
    raise HTTPException(
        status_code=400,
        detail=(
            f"Unauthorized target '{raw}'. Only registered target IDs are permitted. "
            f"Authorized targets: {sorted(list(REGISTERED_FIXTURE_IDS.keys()))}"
        ),
    )


# ── Health & Diagnostics ──────────────────────────────────────────
@app.get("/health", response_model=HealthResponse)
@app.get("/api/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Return system readiness and service configuration."""
    return HealthResponse(
        status="OK",
        database=get_db().db_path,
        ollama_host=config.OLLAMA_HOST,
        docker_image=config.DOCKER_IMAGE,
    )


# ── Statistics ───────────────────────────────────────────────────
@app.get("/stats")
@app.get("/api/stats")
def get_stats() -> Dict[str, Any]:
    """Return aggregated security statistics."""
    return get_db().get_stats()


# ── Fixtures Catalog ──────────────────────────────────────────────
@app.get("/fixtures")
@app.get("/api/fixtures")
def get_fixtures() -> List[Dict[str, Any]]:
    """Return pre-configured synthetic competition fixtures."""
    return FIXTURES_META


# ── Scans API ─────────────────────────────────────────────────────
@app.get("/scans")
@app.get("/api/scans")
def list_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """List recent scan runs."""
    return get_db().list_scans(limit=limit)


@app.get("/scans/{scan_id}")
@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> Dict[str, Any]:
    """Retrieve full audit scan result and evidence capsule by scan_id."""
    res = get_db().get_scan_result(scan_id)
    if not res:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found")
    return _format_scan_dict(res)


@app.get("/scans/{scan_id}/report")
@app.get("/api/scans/{scan_id}/report")
def export_scan_report(scan_id: str, format: str = "json") -> Response:
    """Export the verified scan report as structured JSON or human-readable Markdown."""
    res = get_db().get_scan_result(scan_id)
    if not res:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found")

    fmt = format.lower().strip()
    if fmt == "json":
        return Response(content=res.model_dump_json(indent=2), media_type="application/json")
    elif fmt in {"markdown", "md"}:
        md_text = generate_markdown_report(res)
        return Response(content=md_text, media_type="text/markdown")
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format '{format}'. Use 'json' or 'markdown'.")


KNOWN_VULNERABLE_SERVERS = {"rogue_server", "poisoned_description", "lying_annotations"}


class ApproveRequest(BaseModel):
    reapprove: bool = False
    force: bool = False


@app.post("/scan")
@app.post("/api/scan")
def trigger_scan(req: ScanRequest) -> Dict[str, Any]:
    """Trigger a security audit scan on an authorized registered target ID."""
    safe_path, verified_target_id = _validate_safe_target(req.server_path, req.target_id)
    orch = get_orchestrator()

    try:
        # Ignore client-controlled server_name to derive trusted server identity strictly from allowlisted target ID
        res = orch.run_scan(target=safe_path, server_id=verified_target_id, use_llm=req.use_llm)
        return _format_scan_dict(res)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit scan failed: {str(e)}")


# ── Baselines API ─────────────────────────────────────────────────
@app.get("/baselines")
@app.get("/api/baselines")
def list_baselines() -> List[Dict[str, Any]]:
    """List all pinned server baselines."""
    return get_db().list_baselines()


@app.get("/baselines/{server_id}")
@app.get("/api/baselines/{server_id}")
def get_baseline(server_id: str) -> Dict[str, Any]:
    """Retrieve pinned baseline snapshot for a server."""
    snapshot = get_db().get_baseline(server_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail=f"Baseline for server '{server_id}' not found")
    return snapshot.model_dump()


@app.post("/baselines/{server_id}/approve")
@app.post("/api/baselines/{server_id}/approve")
def approve_baseline(server_id: str, req: Optional[ApproveRequest] = None) -> Dict[str, Any]:
    """Approve and pin the current catalog of a server as its verified baseline."""
    req_body = req or ApproveRequest()
    if server_id in KNOWN_VULNERABLE_SERVERS and not req_body.force:
        raise HTTPException(
            status_code=400,
            detail=f"Safety Guard: Cannot approve known vulnerable server '{server_id}' without explicit force=true override.",
        )

    candidate_paths = [
        Path("fixtures") / server_id / "catalog.json",
        Path("fixtures") / server_id / "catalog_v1.json",
        Path("benchmarks/targets") / server_id / "catalog.json",
        Path(server_id) / "catalog.json",
    ]
    catalog_path = None
    for p in candidate_paths:
        if p.exists():
            catalog_path = p
            break

    if not catalog_path:
        raise HTTPException(
            status_code=404,
            detail=f"Cannot locate catalog.json to pin for server '{server_id}'",
        )

    snapshot = MCPCatalogClient.load_from_file(str(catalog_path), server_id=server_id)
    existing = get_db().get_baseline(server_id)
    if existing and not req_body.reapprove:
        return {
            "status": "PRESERVED_EXISTING",
            "message": f"Baseline for '{server_id}' already exists and was preserved. Set reapprove=true to overwrite.",
            "server_id": server_id,
            "catalog_fingerprint": existing.catalog_fingerprint,
            "preserved": True,
        }

    get_db().save_baseline(snapshot, overwrite=req_body.reapprove)
    return {
        "status": "APPROVED",
        "server_id": server_id,
        "catalog_fingerprint": snapshot.catalog_fingerprint,
        "tools_count": len(snapshot.tools),
        "overwritten": req_body.reapprove and existing is not None,
    }


class PinRequest(BaseModel):
    server_id: str
    catalog_path: str
    reapprove: bool = False
    force: bool = False


@app.post("/pin")
@app.post("/api/pin")
def pin_catalog_endpoint(req: PinRequest) -> Dict[str, Any]:
    """Pin a catalog snapshot as an approved baseline."""
    safe_path, verified_id = _validate_safe_target(req.catalog_path, req.server_id)
    target_id = req.server_id or verified_id

    if target_id in KNOWN_VULNERABLE_SERVERS and not req.force:
        raise HTTPException(
            status_code=400,
            detail=f"Safety Guard: Cannot pin known vulnerable server '{target_id}' without explicit force=true override.",
        )

    cat_file = Path(safe_path)
    if cat_file.is_dir():
        cat_file = cat_file / "catalog.json"
    snapshot = MCPCatalogClient.load_from_file(str(cat_file), server_id=target_id)
    existing = get_db().get_baseline(target_id)
    if existing and not req.reapprove:
        return {
            "status": "PRESERVED_EXISTING",
            "message": f"Existing baseline for '{target_id}' was preserved. Set reapprove=true to overwrite.",
            "server_id": target_id,
            "catalog_fingerprint": existing.catalog_fingerprint,
            "preserved": True,
        }

    get_db().save_baseline(snapshot, overwrite=req.reapprove)
    return {
        "status": "PINNED",
        "server_id": target_id,
        "catalog_fingerprint": snapshot.catalog_fingerprint,
        "tools_count": len(snapshot.tools),
        "overwritten": req.reapprove and existing is not None,
    }


class DiffRequest(BaseModel):
    server_id: str
    catalog_path: str


@app.post("/diff")
@app.post("/api/diff")
def diff_catalogs_endpoint(req: DiffRequest) -> Dict[str, Any]:
    """Compare a current catalog against its pinned baseline to detect drift/rug pull."""
    baseline = get_db().get_baseline(req.server_id)
    if not baseline:
        raise HTTPException(status_code=404, detail=f"No baseline pinned for '{req.server_id}'")
    safe_path, _ = _validate_safe_target(req.catalog_path, req.server_id)
    cat_file = Path(safe_path)
    if cat_file.is_dir():
        cat_file = cat_file / "catalog.json"
    current = MCPCatalogClient.load_from_file(str(cat_file), server_id=req.server_id)
    diff_res = diff_catalogs(baseline, current)
    return diff_res.model_dump()


# ── Live Rug-Pull Demo Endpoint ───────────────────────────────────
@app.post("/demo/rug-pull")
@app.post("/api/demo/rug-pull")
def live_rug_pull_demo() -> Dict[str, Any]:
    """Execute authentic live stdio rug-pull comparison between version 1 and version 2."""
    server_py = Path("fixtures/rug_pull/server.py").resolve()
    if not server_py.exists():
        raise HTTPException(status_code=404, detail="fixtures/rug_pull/server.py not found")

    cmd1 = [sys.executable, str(server_py), "--version", "1"]
    cmd2 = [sys.executable, str(server_py), "--version", "2"]

    client1 = MCPCatalogClient(cmd1, server_id="rug_pull")
    baseline = asyncio.run(client1.discover_live())

    client2 = MCPCatalogClient(cmd2, server_id="rug_pull")
    mutated = asyncio.run(client2.discover_live())

    diff_res = diff_catalogs(baseline, mutated)

    return {
        "status": "RUG_PULL_DETECTED" if not diff_res.is_identical else "IDENTICAL",
        "server_id": "rug_pull",
        "target": "rug_pull",
        "baseline_version": "1",
        "baseline_fingerprint": baseline.catalog_fingerprint,
        "v1_baseline_hash": baseline.catalog_fingerprint,
        "mutated_version": "2",
        "mutated_fingerprint": mutated.catalog_fingerprint,
        "v2_mutated_hash": mutated.catalog_fingerprint,
        "is_identical": diff_res.is_identical,
        "added_tools": diff_res.added_tools,
        "removed_tools": diff_res.removed_tools,
        "modified_tools": diff_res.modified_tools,
        "diff": diff_res.model_dump(),
        "explanation": "Live stdio discovery captured capability modification between server versions without static file shortcuts.",
    }


# ── Vulnerable-to-Patched Comparison Endpoints ────────────────────
@app.get("/api/pairs")
def list_comparison_pairs() -> List[Dict[str, Any]]:
    """Return all configured vulnerable vs. remediated/patched demonstration pairs."""
    return COMPARISON_PAIRS_META


COMPARISON_RESULTS_CACHE: Dict[str, Dict[str, Any]] = {}


@app.get("/api/compare/{pair_id}")
def get_pair_comparison(pair_id: str) -> Dict[str, Any]:
    """Retrieve previously executed side-by-side comparison result.

    Adheres to REST semantics: GET retrieves existing results without triggering heavy scans.
    Use POST /api/compare/{pair_id} to trigger or re-run the comparison scans.
    """
    pair = next((p for p in COMPARISON_PAIRS_META if p["id"] == pair_id), None)
    if not pair:
        raise HTTPException(status_code=404, detail=f"Comparison pair '{pair_id}' not found")

    cached = COMPARISON_RESULTS_CACHE.get(pair_id)
    if not cached:
        raise HTTPException(
            status_code=404,
            detail=f"Comparison for pair '{pair_id}' has not been executed yet. Run POST /api/compare/{pair_id} to perform the scan.",
        )
    return cached


@app.post("/api/compare/{pair_id}")
def compare_pair(pair_id: str) -> Dict[str, Any]:
    """Execute side-by-side verification on a vulnerable target and its remediated counterpart."""
    pair = next((p for p in COMPARISON_PAIRS_META if p["id"] == pair_id), None)
    if not pair:
        raise HTTPException(status_code=404, detail=f"Comparison pair '{pair_id}' not found")

    orch = get_orchestrator()

    if pair_id == "pair_rug_pull":
        server_py = Path("fixtures/rug_pull/server.py").resolve()
        if not server_py.exists():
            raise HTTPException(status_code=404, detail="fixtures/rug_pull/server.py not found")

        cmd1 = [sys.executable, str(server_py), "--version", "1"]
        cmd2 = [sys.executable, str(server_py), "--version", "2"]

        # 1. Discover baseline v1 and mutated v2 via authentic live stdio
        client1 = MCPCatalogClient(cmd1, server_id="rug_pull")
        baseline = asyncio.run(client1.discover_live())

        client2 = MCPCatalogClient(cmd2, server_id="rug_pull")
        mutated = asyncio.run(client2.discover_live())

        diff_res = diff_catalogs(baseline, mutated)

        # 2. Pin approved baseline in DB
        orch.db.save_baseline(baseline, overwrite=True)

        # 3. Execute genuine scan on the approved baseline (v1)
        patched_scan = orch.run_scan(
            target=str(server_py),
            server_command=cmd1,
            server_id="rug_pull",
            use_llm=False,
            use_docker=False,
        )

        # 4. Execute genuine scan on the mutated server (v2) which diffs against baseline
        vuln_scan = orch.run_scan(
            target=str(server_py),
            server_command=cmd2,
            server_id="rug_pull",
            use_llm=False,
            use_docker=False,
        )

        vuln_rules = {f.rule_id for f in vuln_scan.findings}
        patched_rules = {f.rule_id for f in patched_scan.findings}
        eliminated_rules = sorted(list(vuln_rules - patched_rules))

        result = {
            "pair_id": pair["id"],
            "title": pair["title"],
            "description": pair["description"],
            "key_vulnerability": pair["key_vulnerability"],
            "remediation_summary": pair["remediation_summary"],
            "vulnerable": {
                "target_id": "rug_pull_v2",
                "server_name": "rug_pull (v2 Mutated)",
                "trust_state": vuln_scan.trust_state.value if hasattr(vuln_scan.trust_state, "value") else str(vuln_scan.trust_state),
                "findings_count": len(vuln_scan.findings),
                "findings": [f.model_dump() for f in vuln_scan.findings],
                "stage_coverage": vuln_scan.stage_coverage,
                "evidence_manifest_hash": vuln_scan.evidence_manifest_hash,
                "fingerprint": vuln_scan.snapshot.catalog_fingerprint if vuln_scan.snapshot else mutated.catalog_fingerprint,
            },
            "patched": {
                "target_id": "rug_pull_v1",
                "server_name": "rug_pull (v1 Approved Baseline)",
                "trust_state": patched_scan.trust_state.value if hasattr(patched_scan.trust_state, "value") else str(patched_scan.trust_state),
                "findings_count": len(patched_scan.findings),
                "findings": [f.model_dump() for f in patched_scan.findings],
                "stage_coverage": patched_scan.stage_coverage,
                "evidence_manifest_hash": patched_scan.evidence_manifest_hash,
                "fingerprint": patched_scan.snapshot.catalog_fingerprint if patched_scan.snapshot else baseline.catalog_fingerprint,
            },
            "comparison_delta": {
                "eliminated_findings_count": len(eliminated_rules),
                "eliminated_rule_ids": eliminated_rules,
                "is_fully_remediated": (
                    (patched_scan.trust_state == TrustState.VERIFIED or str(patched_scan.trust_state) == "VERIFIED")
                    and len(patched_scan.findings) == 0
                ),
                "diff": diff_res.model_dump(),
            },
        }
        COMPARISON_RESULTS_CACHE[pair_id] = result
        return result

    vuln_path = REGISTERED_FIXTURE_IDS.get(pair["vulnerable_target_id"])
    patched_path = REGISTERED_FIXTURE_IDS.get(pair["patched_target_id"])

    if not vuln_path or not patched_path:
        raise HTTPException(status_code=400, detail="Pair target fixtures not registered")

    vuln_scan = orch.run_scan(
        target=str(Path(vuln_path).resolve()),
        server_id=pair["vulnerable_target_id"],
        use_llm=False,
        use_docker=False,
    )
    patched_scan = orch.run_scan(
        target=str(Path(patched_path).resolve()),
        server_id=pair["patched_target_id"],
        use_llm=False,
        use_docker=False,
    )

    vuln_rules = {f.rule_id for f in vuln_scan.findings}
    patched_rules = {f.rule_id for f in patched_scan.findings}
    eliminated_rules = sorted(list(vuln_rules - patched_rules))

    result = {
        "pair_id": pair["id"],
        "title": pair["title"],
        "description": pair["description"],
        "key_vulnerability": pair["key_vulnerability"],
        "remediation_summary": pair["remediation_summary"],
        "vulnerable": {
            "target_id": pair["vulnerable_target_id"],
            "server_name": vuln_scan.server_name,
            "trust_state": vuln_scan.trust_state.value if hasattr(vuln_scan.trust_state, "value") else str(vuln_scan.trust_state),
            "findings_count": len(vuln_scan.findings),
            "findings": [f.model_dump() for f in vuln_scan.findings],
            "stage_coverage": vuln_scan.stage_coverage,
            "evidence_manifest_hash": vuln_scan.evidence_manifest_hash,
        },
        "patched": {
            "target_id": pair["patched_target_id"],
            "server_name": patched_scan.server_name,
            "trust_state": patched_scan.trust_state.value if hasattr(patched_scan.trust_state, "value") else str(patched_scan.trust_state),
            "findings_count": len(patched_scan.findings),
            "findings": [f.model_dump() for f in patched_scan.findings],
            "stage_coverage": patched_scan.stage_coverage,
            "evidence_manifest_hash": patched_scan.evidence_manifest_hash,
        },
        "comparison_delta": {
            "eliminated_findings_count": max(0, len(vuln_scan.findings) - len(patched_scan.findings)),
            "eliminated_rule_ids": eliminated_rules,
            "is_fully_remediated": (
                (patched_scan.trust_state == TrustState.VERIFIED or str(patched_scan.trust_state) == "VERIFIED")
                and len(patched_scan.findings) == 0
            ),
        },
    }
    COMPARISON_RESULTS_CACHE[pair_id] = result
    return result


# ── Sponsor KOALA Model Assurance Endpoints ───────────────────────
class KoalaAuditRequest(BaseModel):
    frameworks: Optional[List[str]] = None
    target_runtime: Optional[str] = None


@app.get("/api/assurance/model")
def get_model_assurance() -> Dict[str, Any]:
    """Retrieve model governance assurance report powered by KOALA (DomAiyn Labs).
    
    Returns the most recent completed audit report or a NOT_ASSESSED state.
    Does NOT trigger an expensive on-demand evaluation.
    """
    report = KoalaAssuranceRunner.get_latest_report()
    if report:
        return report.model_dump()

    return {
        "status": "NOT_ASSESSED",
        "audit_mode": "NOT_ASSESSED",
        "audit_id": "none",
        "tool_version": "0.2.0",
        "generated_at": "",
        "execution_timestamp": "",
        "evidence_provenance": "NONE",
        "model_id": "Qwen2.5-Coder-7B-Instruct",
        "frameworks": [],
        "summary": {
            "controls_total": 0,
            "machine_verified": 0,
            "self_attested": 0,
            "not_assessed": 0,
            "failed": 0,
            "machine_verification_percent": 0.0,
            "assessment_coverage_percent": 0.0,
        },
        "results": [],
        "attribution": "Audited via KOALA (version 0.2.0) by DomAiyn Labs (Apache 2.0)",
        "message": "No model governance audit has been executed yet. Trigger a fresh audit via POST /api/assurance/audit.",
    }


@app.post("/api/assurance/audit")
def trigger_model_assurance(req: KoalaAuditRequest) -> Dict[str, Any]:
    """Execute on-demand KOALA model assurance audit for local AI models."""
    runner = KoalaAssuranceRunner()
    if not runner.is_available():
        raise HTTPException(
            status_code=503,
            detail="KOALA CLI v0.2.0 is not installed or available on this system.",
        )

    try:
        report = runner.run_audit(
            frameworks=req.frameworks,
            target_runtime=req.target_runtime,
        )
        return report.model_dump()
    except TimeoutError:
        raise HTTPException(status_code=504, detail="KOALA model assurance audit timed out.")
    except Exception as exc:
        clean_msg = str(exc)
        if "/home/" in clean_msg or "/run/media/" in clean_msg:
            clean_msg = clean_msg.split(":")[-1].strip()
        raise HTTPException(status_code=500, detail=f"KOALA assurance audit failed: {clean_msg}")
