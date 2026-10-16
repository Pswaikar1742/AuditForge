"""AuditForge FastAPI Application."""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from auditforge.storage.database import Database
from auditforge.config import config
from auditforge.core.contracts import ScanResult, ServerSnapshot

app = FastAPI(
    title="AuditForge Security Auditor API",
    version="0.1.0",
    description="REST API for MCP Security Auditing, Evidence Capsules, and Catalog Pinning",
)

# Enable CORS for local Vite dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db = Database(config.DB_PATH)


class HealthResponse(BaseModel):
    status: str
    database: str
    ollama_host: str
    docker_image: str


@app.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Return system readiness and service configuration."""
    return HealthResponse(
        status="OK",
        database=config.DB_PATH,
        ollama_host=config.OLLAMA_HOST,
        docker_image=config.DOCKER_IMAGE,
    )


@app.get("/scans/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str) -> ScanResult:
    """Retrieve full audit scan result and evidence capsule by scan_id."""
    res = db.get_scan_result(scan_id)
    if not res:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found")
    return res


@app.get("/baselines/{server_id}", response_model=ServerSnapshot)
def get_baseline(server_id: str) -> ServerSnapshot:
    """Retrieve pinned baseline snapshot for a server."""
    snapshot = db.get_baseline(server_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail=f"Baseline for server '{server_id}' not found")
    return snapshot
