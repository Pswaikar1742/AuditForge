"""AuditForge Scan Orchestrator.

Coordinates Catalog Discovery, Static Analysis, Description Analysis,
Dynamic Sandboxed Probing, Pinning Diffs, and Trust Gap Reconciliation.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

from auditforge.analyzers.description import DescriptionAnalyzer
from auditforge.analyzers.static import StaticAnalyzer
from auditforge.analyzers.trust_gap import TrustGapAnalyzer
from auditforge.catalog.client import MCPCatalogClient
from auditforge.catalog.pinning import diff_catalogs
from auditforge.config import config
from auditforge.core.contracts import (
    CatalogDiff,
    EvidenceRecord,
    Finding,
    ProbeOutcome,
    ScanResult,
    ServerSnapshot,
    Severity,
    TrustState,
)
from auditforge.core.evidence import current_iso_timestamp, generate_evidence_id, generate_finding_id
from auditforge.sandbox.probe_cases import generate_probe_cases
from auditforge.sandbox.runner import DockerSandboxRunner
from auditforge.storage.database import Database


class ScanOrchestrator:
    """Orchestrates end-to-end security audits across analysis layers."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        use_docker: bool = False,
        use_llm: bool = True,
    ):
        self.db = Database(db_path or config.DB_PATH)
        self.use_docker = use_docker
        self.use_llm = use_llm
        self.static_analyzer: Optional[StaticAnalyzer] = None
        self.desc_analyzer = DescriptionAnalyzer(use_llm=use_llm, model_name=config.OLLAMA_MODEL)
        self.trust_gap_analyzer = TrustGapAnalyzer()
        self.runner = DockerSandboxRunner()

    def run_scan(
        self,
        target: str,
        server_command: Optional[List[str]] = None,
        source_path: Optional[str] = None,
        catalog_path: Optional[str] = None,
    ) -> ScanResult:
        """Execute full audit pipeline on target server."""
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        started_at = current_iso_timestamp()

        all_findings: List[Finding] = []
        all_evidence: List[EvidenceRecord] = []
        all_probe_outcomes: List[ProbeOutcome] = []

        target_path = Path(target).resolve() if target else Path(".")
        src_dir = Path(source_path).resolve() if source_path else target_path

        # ── 1. Catalog Discovery / Loading ────────────────────────
        snapshot: Optional[ServerSnapshot] = None
        cat_file: Optional[Path] = None

        if catalog_path and Path(catalog_path).exists():
            cat_file = Path(catalog_path)
        elif (target_path / "catalog.json").exists():
            cat_file = target_path / "catalog.json"
        elif target_path.is_file() and target_path.suffix == ".json":
            cat_file = target_path

        if cat_file:
            snapshot = MCPCatalogClient.load_from_file(str(cat_file), server_id=target_path.name)
        else:
            snapshot = ServerSnapshot(server_id=target_path.name, tools={})

        # ── 2. Static AST & Secret Analysis ───────────────────────
        if src_dir.exists():
            self.static_analyzer = StaticAnalyzer(str(src_dir))
            static_findings, static_ev = self.static_analyzer.analyze()
            all_findings.extend(static_findings)
            all_evidence.extend(static_ev)

        # ── 3. Description & Schema Analysis ──────────────────────
        if snapshot and snapshot.tools:
            for tool in snapshot.tools.values():
                desc_findings, desc_ev = self.desc_analyzer.analyze_tool(tool)
                all_findings.extend(desc_findings)
                all_evidence.extend(desc_ev)

        # ── 4. Dynamic Sandbox Probing ────────────────────────────
        executors: Dict[str, Any] = {}
        target = Path(target_path)
        server_py = None
        if target.is_file() and target.suffix == ".py":
            server_py = target
        elif target.is_dir():
            cand = target / "server.py"
            if cand.exists():
                server_py = cand
            else:
                py_files = list(target.glob("*.py"))
                if py_files:
                    server_py = py_files[0]

        if server_py and server_py.exists():
            import importlib.util
            try:
                spec = importlib.util.spec_from_file_location("scanned_server", str(server_py))
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    if snapshot and snapshot.tools:
                        for t_name in snapshot.tools.keys():
                            if hasattr(mod, t_name):
                                executors[t_name] = getattr(mod, t_name)
            except Exception:
                pass

        if snapshot and snapshot.tools:
            for tool in snapshot.tools.values():
                cases = generate_probe_cases(tool)
                for case in cases:
                    executor = executors.get(tool.name)
                    outcome = self.runner.run_probe(case, executor=executor)
                    all_probe_outcomes.append(outcome)

        # ── 5. Pin-and-Diff Baseline Check ────────────────────────
        diff: Optional[CatalogDiff] = None
        baseline = self.db.get_baseline(snapshot.server_id)
        if baseline:
            diff = diff_catalogs(baseline, snapshot)
            if not diff.is_identical:
                raw_data = {
                    "added_tools": diff.added_tools,
                    "removed_tools": diff.removed_tools,
                    "modified_tools": diff.modified_tools,
                }
                ev_id = generate_evidence_id("catalog_diff", raw_data)
                all_evidence.append(
                    EvidenceRecord(
                        evidence_id=ev_id,
                        source="catalog_diff",
                        summary=f"Catalog drift detected against approved baseline for '{snapshot.server_id}'.",
                        raw_data=raw_data,
                    )
                )
                all_findings.append(
                    Finding(
                        id=generate_finding_id("DIFF"),
                        rule_id="PIN-RUGPULL-001",
                        severity=Severity.CRITICAL,
                        evidence_ids=[ev_id],
                        reason=(
                            f"RUG PULL DETECTED: Tool catalog hash changed from approved baseline "
                            f"({diff.baseline_fingerprint[:12]}... -> {diff.current_fingerprint[:12]}...). "
                            f"Modified: {list(diff.modified_tools.keys())}, Added: {diff.added_tools}"
                        ),
                        confidence=1.0,
                        remediation="Verify all modified and added tool signatures before re-approving baseline.",
                    )
                )

        # ── 6. Trust Gap Correlation & State Decision ─────────────
        trust_state = self.trust_gap_analyzer.evaluate(
            snapshot=snapshot,
            findings=all_findings,
            evidence=all_evidence,
            probe_outcomes=all_probe_outcomes,
            diff=diff,
        )

        completed_at = current_iso_timestamp()
        summary = (
            f"Audit completed with trust state {trust_state.value}. "
            f"{len(all_findings)} finding(s) backed by {len(all_evidence)} evidence capsule(s)."
        )

        scan_result = ScanResult(
            scan_id=scan_id,
            target=str(target_path),
            started_at=started_at,
            completed_at=completed_at,
            trust_state=trust_state,
            snapshot=snapshot,
            diff=diff,
            findings=all_findings,
            evidence=all_evidence,
            probe_outcomes=all_probe_outcomes,
            summary=summary,
        )

        # ── 7. Save to Database ───────────────────────────────────
        self.db.save_scan(scan_result)

        return scan_result
