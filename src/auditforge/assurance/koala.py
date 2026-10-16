"""AuditForge Sponsor Integration: KOALA Model Assurance Sidecar.

Audits local AI/LLM models (e.g., Qwen2.5-Coder-7B) against governance frameworks
(NIST AI RMF, EU AI Act) using KOALA v0.2.0 by DomAiyn Labs (Apache 2.0).

NOTE: Model assurance is maintained strictly orthogonal to MCP server security findings.
An AI model's governance score NEVER alters an MCP server's vulnerability verdict.
"""

from __future__ import annotations

from enum import Enum
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict

from auditforge.core.evidence import current_iso_timestamp


class KoalaAuditMode(str, Enum):
    STATIC_GOVERNANCE_AUDIT = "STATIC_GOVERNANCE_AUDIT"
    OLLAMA_RUNTIME_PROBES = "OLLAMA_RUNTIME_PROBES"
    FAILED = "FAILED"
    NOT_ASSESSED = "NOT_ASSESSED"


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
    execution_timestamp: Optional[str] = None
    audit_mode: str = KoalaAuditMode.STATIC_GOVERNANCE_AUDIT.value
    status: str = "COMPLETED"
    evidence_provenance: str = "KOALA v0.2.0 Engine"
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
    target_runtime: Optional[str] = None


class KoalaAssuranceRunner:
    """Executes and ingests KOALA compliance audits for local AI models."""

    DEFAULT_KOALA_DIR = Path("/home/psw/KOALA/KOALA")
    CACHE_DIR = Path("/tmp/auditforge_koala_cache")
    LATEST_REPORT_FILE = CACHE_DIR / "latest_report.json"
    HISTORICAL_DIR = CACHE_DIR / "history"

    def __init__(self, koala_repo_path: Optional[Path] = None):
        self.koala_repo_path = koala_repo_path or self.DEFAULT_KOALA_DIR
        self.python_bin = self._resolve_python_bin()

    def _resolve_default_model_dir(self) -> Path:
        """Resolve model card directory."""
        candidates = [
            Path("/run/media/psw/6066FD4C66FD2406/Projects/Auditforge/Forger/models/qwen2.5-coder-7b"),
            Path.cwd() / "models" / "qwen2.5-coder-7b",
            Path(__file__).resolve().parents[3] / "models" / "qwen2.5-coder-7b",
        ]
        for p in candidates:
            if p.exists():
                return p
        return candidates[0]

    def _resolve_python_bin(self) -> str:
        """Resolve python interpreter with koala installed."""
        venv_py = self.koala_repo_path / ".venv" / "bin" / "python"
        if venv_py.exists():
            return str(venv_py)
        sys_py = shutil.which("python3")
        return sys_py or sys.executable

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

    @classmethod
    def get_latest_report(cls) -> Optional[KoalaReport]:
        """Retrieve the most recently saved report from cache without triggering an audit."""
        if cls.LATEST_REPORT_FILE.exists():
            try:
                return cls.load_report(str(cls.LATEST_REPORT_FILE))
            except Exception:
                return None
        return None

    def run_audit(
        self,
        model_dir: Optional[str] = None,
        frameworks: Optional[List[str]] = None,
        output_file: Optional[str] = None,
        target_runtime: Optional[str] = None,
        timeout_seconds: float = 60.0,
    ) -> KoalaReport:
        """Execute a KOALA audit against the specified model directory in an isolated temporary location.
        
        Args:
            model_dir: Directory containing model card and artifacts.
            frameworks: List of frameworks (e.g. ['nist_ai_rmf', 'eu_ai_act']).
            output_file: Optional path to copy the generated JSON report.
            target_runtime: Runtime target like 'ollama:qwen2.5-coder:7b' (enables runtime probes).
            timeout_seconds: Subprocess execution timeout in seconds.
            
        Raises:
            RuntimeError: If KOALA is unavailable or the audit process exits with non-zero code.
            TimeoutError: If evaluation times out.
            FileNotFoundError: If the process did not produce an output report.
            ValueError: If the generated output is malformed JSON.
        """
        if not self.is_available():
            raise RuntimeError("KOALA CLI v0.2.0 is not installed or available on this system.")

        target_dir = Path(model_dir) if model_dir else self._resolve_default_model_dir()
        if not target_dir.exists():
            raise FileNotFoundError(f"Model directory not found: {target_dir}")

        fws_list = sorted(frameworks) if frameworks else ["eu_ai_act", "nist_ai_rmf"]
        fws = ",".join(fws_list)
        audit_mode = (
            KoalaAuditMode.OLLAMA_RUNTIME_PROBES.value
            if target_runtime
            else KoalaAuditMode.STATIC_GOVERNANCE_AUDIT.value
        )

        with tempfile.TemporaryDirectory(prefix="koala_audit_") as tmp_dir:
            tmp_out = Path(tmp_dir) / "report.json"
            cmd = [
                self.python_bin,
                "-m",
                "koala.cli",
                "audit",
                str(target_dir),
                "--frameworks",
                fws,
                "-o",
                str(tmp_out),
            ]
            if target_runtime:
                cmd.extend(["-t", target_runtime])

            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                raise TimeoutError(f"KOALA assurance audit timed out after {timeout_seconds}s") from exc

            if res.returncode != 0:
                err_detail = (res.stderr or "").strip().split("\n")[-1] or f"Exit code {res.returncode}"
                raise RuntimeError(f"KOALA CLI audit failed: {err_detail}")

            if not tmp_out.exists():
                raise FileNotFoundError("KOALA audit completed without generating a report file.")

            try:
                with open(tmp_out, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
            except Exception as exc:
                raise ValueError(f"KOALA audit produced malformed JSON report: {exc}") from exc

            report = KoalaReport.model_validate(raw_data)
            report.audit_mode = audit_mode
            report.status = "COMPLETED"
            report.target_runtime = target_runtime
            report.execution_timestamp = current_iso_timestamp()
            report.evidence_provenance = f"KOALA CLI v0.2.0 ({audit_mode})"

            # Persist to local cache for GET /api/assurance/model
            try:
                self.CACHE_DIR.mkdir(parents=True, exist_ok=True)
                self.HISTORICAL_DIR.mkdir(parents=True, exist_ok=True)
                serialized = report.model_dump_json(indent=2)
                self.LATEST_REPORT_FILE.write_text(serialized, encoding="utf-8")
                (self.HISTORICAL_DIR / f"{report.audit_id}.json").write_text(serialized, encoding="utf-8")
            except OSError:
                pass

            if output_file:
                Path(output_file).parent.mkdir(parents=True, exist_ok=True)
                Path(output_file).write_text(report.model_dump_json(indent=2), encoding="utf-8")

            return report

    @classmethod
    def load_report(cls, report_path: str) -> KoalaReport:
        """Load and parse an existing KOALA JSON report."""
        path = Path(report_path)
        if not path.exists():
            raise FileNotFoundError(f"Report file not found: {report_path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return KoalaReport.model_validate(data)
