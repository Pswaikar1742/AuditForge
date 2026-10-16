"""AuditForge Sponsor Integration: KOALA Model Assurance Sidecar.

Audits local AI/LLM models (e.g., Qwen2.5-Coder-7B) against governance frameworks
(NIST AI RMF, EU AI Act) using KOALA v0.2.0 by DomAiyn Labs (Apache 2.0).

NOTE: Model assurance is maintained strictly orthogonal to MCP server security findings.
An AI model's governance score NEVER alters an MCP server's vulnerability verdict.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class KoalaControlResult(BaseModel):
    """Result of an individual governance control check."""
    model_config = ConfigDict(extra="ignore")

    control_id: str
    framework: str
    clause: str
    title: str
    status: str = Field(description="pass, fail, or not_assessed")
    evidence_state: str = Field(default="machine_verified")
    severity: str = Field(default="medium")
    evidence: str = Field(default="")
    remediation: Optional[Dict[str, Any]] = None


class KoalaAuditSummary(BaseModel):
    """Aggregate summary statistics of the KOALA audit."""
    model_config = ConfigDict(extra="ignore")

    controls_total: int = 0
    machine_verified: int = 0
    self_attested: int = 0
    not_assessed: int = 0
    failed: int = 0
    machine_verification_percent: float = 0.0
    assessment_coverage_percent: float = 0.0


class KoalaReport(BaseModel):
    """Full structured KOALA model assurance report."""
    model_config = ConfigDict(extra="ignore")

    audit_id: str
    tool_version: str = "0.2.0"
    generated_at: str
    disclaimer: str = (
        "Koala produces evidence and gap analysis, not legal certification. "
        "A passing result is not a compliance guarantee or a legal defense."
    )
    target: Dict[str, Any] = Field(default_factory=dict)
    frameworks: List[str] = Field(default_factory=list)
    summary: KoalaAuditSummary = Field(default_factory=KoalaAuditSummary)
    results: List[KoalaControlResult] = Field(default_factory=list)
    attribution: str = "Audited via KOALA (version 0.2.0) by DomAiyn Labs (Apache 2.0)"
    model_id: str = "Qwen2.5-Coder-7B-Instruct"


class KoalaAssuranceRunner:
    """Executes and ingests KOALA compliance audits for local AI models."""

    DEFAULT_KOALA_DIR = Path("/home/psw/KOALA/KOALA")
    DEFAULT_MODEL_DIR = Path("/run/media/psw/6066FD4C66FD2406/Projects/Auditforge/Forger/models/qwen2.5-coder-7b")

    def __init__(self, koala_repo_path: Optional[Path] = None):
        self.koala_repo_path = koala_repo_path or self.DEFAULT_KOALA_DIR
        self.python_bin = self._resolve_python_bin()

    def _resolve_python_bin(self) -> str:
        """Resolve python interpreter with koala installed."""
        venv_py = self.koala_repo_path / ".venv" / "bin" / "python"
        if venv_py.exists():
            return str(venv_py)
        sys_py = shutil.which("python3")
        return sys_py or "python3"

    def is_available(self) -> bool:
        """Check if KOALA CLI is available for execution."""
        try:
            res = subprocess.run(
                [self.python_bin, "-m", "koala.cli", "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return res.returncode == 0
        except Exception:
            return False

    def run_audit(
        self,
        model_dir: Optional[str] = None,
        frameworks: Optional[List[str]] = None,
        output_file: Optional[str] = None,
        target_runtime: Optional[str] = None,
    ) -> KoalaReport:
        """Execute a KOALA audit against the specified model directory.
        
        Args:
            model_dir: Directory containing model card and artifacts.
            frameworks: List of frameworks (e.g. ['nist_ai_rmf', 'eu_ai_act']).
            output_file: Path to write the JSON report.
            target_runtime: Runtime target like 'ollama:qwen2.5-coder:7b'.
        """
        target_dir = Path(model_dir) if model_dir else self.DEFAULT_MODEL_DIR
        fws_list = sorted(frameworks) if frameworks else ["eu_ai_act", "nist_ai_rmf"]
        fws_tag = "_".join(fws_list)
        out_path = Path(output_file) if output_file else Path(f"/tmp/koala_report_{fws_tag}.json")
        fws = ",".join(fws_list)

        cmd = [
            self.python_bin,
            "-m",
            "koala.cli",
            "audit",
            str(target_dir),
            "--frameworks",
            fws,
            "-o",
            str(out_path),
        ]
        if target_runtime:
            cmd.extend(["-t", target_runtime])

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode != 0 and not out_path.exists():
                raise RuntimeError(f"KOALA audit failed: {res.stderr}")
        except Exception as exc:
            # If dynamic or live execution fails, attempt loading existing or fallback report
            if not out_path.exists():
                raise RuntimeError(f"KOALA execution error: {exc}") from exc

        return self.load_report(str(out_path))

    @classmethod
    def load_report(cls, report_path: str) -> KoalaReport:
        """Load and parse an existing KOALA JSON report."""
        path = Path(report_path)
        if not path.exists():
            raise FileNotFoundError(f"Report file not found: {report_path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return KoalaReport.model_validate(data)
