"""AuditForge FastAPI Application.

REST API for MCP Security Auditing, Evidence Capsules, Catalog Pinning,
and Interactive Dashboard Integration.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from auditforge.config import config
from auditforge.core.contracts import CatalogDiff, ScanResult, ServerSnapshot, TrustState
from auditforge.orchestrator import ScanOrchestrator
from auditforge.storage.database import Database
from auditforge.catalog.client import MCPCatalogClient

app = FastAPI(
    title="AuditForge Security Auditor API",
    version="0.1.0",
    description="REST API for MCP Security Auditing, Evidence Capsules, and Catalog Pinning",
)

# Enable CORS for local Vite dashboard (port 3000 / 5173 / any origin)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db = Database(config.DB_PATH)
orchestrator = ScanOrchestrator(db_path=config.DB_PATH)

FIXTURES_META = [
    {
        "id": "clean_reader",
        "name": "Fixture A: Clean Reader",
        "role": "Negative Control",
        "expected": "0 Vulnerabilities (TrustState: VERIFIED)",
        "tags": ["Read-Only", "No Execution", "Safe Baseline"],
        "path": "fixtures/clean_reader",
    },
    {
        "id": "rogue_server",
        "name": "Fixture B: Rogue Server",
        "role": "Positive Control",
        "expected": "SAST-001 Shell Execution (TrustState: ROGUE)",
        "tags": ["Command Injection", "os.system", "Subprocess"],
        "path": "fixtures/rogue_server",
    },
    {
        "id": "poisoned_description",
        "name": "Fixture C: Poisoned Description",
        "role": "Prompt Injection Control",
        "expected": "DESC-003 Directive & DESC-004 Credential Theft",
        "tags": ["Prompt Injection", "Secret Exfiltration", "Adversarial NLP"],
        "path": "fixtures/poisoned_description",
    },
    {
        "id": "lying_annotations",
        "name": "Fixture D: Lying Annotations (Core USP)",
        "role": "Trust Gap Demonstration",
        "expected": "ANN-001 Contract-to-Behavior Trust Gap Violation",
        "tags": ["Trust Gap USP", "readOnlyHint Violation", "Static & Dynamic"],
        "path": "fixtures/lying_annotations",
    },
    {
        "id": "rug_pull",
        "name": "Fixture E: Rug Pull (Catalog Drift)",
        "role": "Cryptographic Pin-and-Diff",
        "expected": "PIN-RUGPULL-001 Baseline Hash Mismatch",
        "tags": ["Rug Pull Defense", "SHA-256 Pinning", "Drift Detection"],
        "path": "fixtures/rug_pull",
    },
]


class HealthResponse(BaseModel):
    status: str
    database: str
    ollama_host: str
    docker_image: str


class ScanRequest(BaseModel):
    server_path: str
    server_name: Optional[str] = None
    use_llm: bool = False


def _format_scan_dict(res: ScanResult) -> Dict[str, Any]:
    """Format ScanResult dict ensuring both id/scan_id and server_name are populated for UI."""
    data = res.model_dump()
    data["id"] = res.scan_id
    server_name = res.snapshot.server_id if res.snapshot else Path(res.target).name
    data["server_name"] = server_name
    return data


# ── Health & Diagnostics ──────────────────────────────────────────
@app.get("/health", response_model=HealthResponse)
@app.get("/api/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Return system readiness and service configuration."""
    return HealthResponse(
        status="OK",
        database=config.DB_PATH,
        ollama_host=config.OLLAMA_HOST,
        docker_image=config.DOCKER_IMAGE,
    )


# ── Statistics ───────────────────────────────────────────────────
@app.get("/stats")
@app.get("/api/stats")
def get_stats() -> Dict[str, Any]:
    """Return aggregated security statistics."""
    return db.get_stats()


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
    return db.list_scans(limit=limit)


@app.get("/scans/{scan_id}")
@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> Dict[str, Any]:
    """Retrieve full audit scan result and evidence capsule by scan_id."""
    res = db.get_scan_result(scan_id)
    if not res:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found")
    return _format_scan_dict(res)


@app.post("/scan")
@app.post("/api/scan")
def trigger_scan(req: ScanRequest) -> Dict[str, Any]:
    """Trigger a security audit scan on a target directory, file, or fixture."""
    try:
        res = orchestrator.run_scan(target=req.server_path, use_llm=req.use_llm)
        return _format_scan_dict(res)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit scan failed: {str(e)}")


# ── Baselines API ─────────────────────────────────────────────────
@app.get("/baselines")
@app.get("/api/baselines")
def list_baselines() -> List[Dict[str, Any]]:
    """List all pinned server baselines."""
    return db.list_baselines()


@app.get("/baselines/{server_id}")
@app.get("/api/baselines/{server_id}")
def get_baseline(server_id: str) -> Dict[str, Any]:
    """Retrieve pinned baseline snapshot for a server."""
    snapshot = db.get_baseline(server_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail=f"Baseline for server '{server_id}' not found")
    return snapshot.model_dump()


@app.post("/baselines/{server_id}/approve")
@app.post("/api/baselines/{server_id}/approve")
def approve_baseline(server_id: str) -> Dict[str, Any]:
    """Approve and pin the current catalog of a server as its verified baseline."""
    # Look for catalog file in fixtures or target directory
    candidate_paths = [
        Path("fixtures") / server_id / "catalog.json",
        Path("fixtures") / server_id / "catalog_v1.json",
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
    db.save_baseline(snapshot)
    return {
        "status": "APPROVED",
        "server_id": server_id,
        "catalog_fingerprint": snapshot.catalog_fingerprint,
        "tools_count": len(snapshot.tools),
    }
