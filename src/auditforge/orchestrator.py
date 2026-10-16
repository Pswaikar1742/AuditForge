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
        use_llm: bool = False,
    ):
        self.db_path = db_path or config.DB_PATH
        self.db = Database(self.db_path)
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
        use_llm: Optional[bool] = None,
    ) -> ScanResult:
        """Execute full audit pipeline on target server."""
        if use_llm is not None:
            self.desc_analyzer.use_llm = use_llm

        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        started_at = current_iso_timestamp()

        all_findings: List[Finding] = []
        all_evidence: List[EvidenceRecord] = []
        all_probe_outcomes: List[ProbeOutcome] = []

        target_str = str(target).strip()
        is_git_target = target_str.startswith(("https://github.com", "http://github.com", "git@", "https://gitlab.com")) or target_str.endswith(".git")
        temp_git_dir = None

        if is_git_target:
            import tempfile
            import subprocess
            temp_git_dir = tempfile.mkdtemp(prefix="auditforge_repo_")
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", target_str, temp_git_dir],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=45,
                    check=True,
                )
                target_path = Path(temp_git_dir)
                src_dir = target_path
                server_name = target_str.rstrip("/").split("/")[-1].replace(".git", "")
            except Exception as e:
                target_path = Path(temp_git_dir)
                src_dir = target_path
                server_name = target_str
        else:
            target_path = Path(target).resolve() if target else Path(".")
            src_dir = Path(source_path).resolve() if source_path else target_path
            server_name = target_path.name

        # ── 1. Catalog Discovery / Loading ────────────────────────
        snapshot: Optional[ServerSnapshot] = None
        cat_file: Optional[Path] = None

        if catalog_path and Path(catalog_path).exists():
            cat_file = Path(catalog_path)
        elif (target_path / "catalog.json").exists():
            cat_file = target_path / "catalog.json"
        elif (target_path / "mcp.json").exists():
            cat_file = target_path / "mcp.json"
        elif target_path.is_file() and target_path.suffix == ".json":
            cat_file = target_path
        else:
            cand_cats = list(target_path.glob("**/catalog.json"))
            if cand_cats:
                cat_file = cand_cats[0]

        if cat_file:
            snapshot = MCPCatalogClient.load_from_file(str(cat_file), server_id=server_name)
        else:
            snapshot = ServerSnapshot(server_id=server_name, tools={})

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
        target_dir = Path(target_path)
        server_py = None
        if target_dir.is_file() and target_dir.suffix == ".py":
            server_py = target_dir
        elif target_dir.is_dir():
            cand = target_dir / "server.py"
            if cand.exists():
                server_py = cand
            else:
                py_files = list(target_dir.glob("*.py"))
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

        # Stage Coverage calculation per PS02 API Contract
        cat_status = "PASS" if (snapshot and snapshot.tools) else "ERROR"
        ast_status = "FAIL" if any(f.rule_id.startswith("SAST") or f.rule_id.startswith("ANN") for f in all_findings) else ("PASS" if self.static_analyzer else "SKIPPED")
        desc_status = "FAIL" if any(f.rule_id.startswith("DESC") for f in all_findings) else "PASS"
        if all_probe_outcomes:
            probe_status = "FAIL" if any(po.status.value != "OK" for po in all_probe_outcomes) else "PASS"
        else:
            probe_status = "SKIPPED"
        if baseline:
            pin_status = "FAIL" if (diff and not diff.is_identical) else "PASS"
        else:
            pin_status = "NOT_PINNED"

        stage_coverage = {
            "catalog_discovery": cat_status,
            "static_ast": ast_status,
            "description_intelligence": desc_status,
            "dynamic_probing": probe_status,
            "baseline_pinning": pin_status,
        }

        scan_mode = "LIVE_SCAN" if (server_command or self.use_docker or all_probe_outcomes) else "SNAPSHOT_ANALYSIS"

        scan_result = ScanResult(
            scan_id=scan_id,
            id=scan_id,
            server_name=snapshot.server_id if snapshot else Path(str(target)).name,
            target=str(target),
            started_at=started_at,
            completed_at=completed_at,
            trust_state=trust_state,
            scan_mode=scan_mode,
            stage_coverage=stage_coverage,
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
