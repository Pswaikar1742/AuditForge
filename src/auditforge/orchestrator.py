"""AuditForge Scan Orchestrator.

Coordinates Catalog Discovery, Static Analysis, Description Analysis,
Dynamic Sandboxed Probing, Pinning Diffs, and Trust Gap Reconciliation.
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional
import sys
import uuid

from auditforge.analyzers.description import DescriptionAnalyzer
from auditforge.analyzers.static import StaticAnalyzer
from auditforge.analyzers.trust_gap import TrustGapAnalyzer
from auditforge.catalog.client import MCPCatalogClient
from auditforge.catalog.pinning import diff_catalogs
from auditforge.config import config
from auditforge.core.contracts import (
    EvidenceRecord,
    Finding,
    ProbeOutcome,
    ProbeStatus,
    ScanResult,
    ServerSnapshot,
    Severity,
    TrustState,
)
from auditforge.core.evidence import current_iso_timestamp, generate_evidence_id, generate_finding_id
from auditforge.reports.json_report import export_json_report
from auditforge.reports.markdown import generate_markdown_report
from auditforge.sandbox.probe_cases import generate_probe_cases
from auditforge.sandbox.runner import DockerSandboxRunner
from auditforge.storage.database import Database


def aggregate_probe_outcomes(probe_outcomes: List[ProbeOutcome]) -> str:
    """Explicitly aggregate dynamic probe outcomes into stage coverage.

    Ensures TOOL_ERROR, TIMEOUT, UNKNOWN, and SKIPPED cannot silently count as PASS.
    """
    if not probe_outcomes:
        return "SKIPPED"

    statuses = {p.status for p in probe_outcomes}

    # If any probe encountered an execution error, timeout, or unknown state, report ERROR
    if any(s in {ProbeStatus.TOOL_ERROR, ProbeStatus.TIMEOUT, ProbeStatus.UNKNOWN} for s in statuses):
        return "ERROR"

    # If any probe was skipped (and none errored), report SKIPPED
    if any(s == ProbeStatus.SKIPPED for s in statuses):
        return "SKIPPED"

    # Only if every probe completed with OK, report PASS
    if all(s == ProbeStatus.OK for s in statuses):
        return "PASS"

    return "UNKNOWN"


class ScanOrchestrator:
    """Orchestrates end-to-end security audits across analysis layers."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        db: Optional[Database] = None,
        use_docker: bool = True,
        use_llm: bool = True,
    ):
        if db is not None:
            self.db = db
            self.db_path = db.db_path
        else:
            self.db_path = db_path or config.DB_PATH
            self.db = Database(self.db_path)
        self.use_docker = use_docker
        self.use_llm = use_llm

    def run_scan(
        self,
        target: str,
        server_command: Optional[List[str]] = None,
        source_path: Optional[str] = None,
        catalog_path: Optional[str] = None,
        server_id: Optional[str] = None,
    ) -> ScanResult:
        """Execute full audit pipeline on target server."""
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        started_at = current_iso_timestamp()

        target_path = Path(target) if target else None
        snapshot: Optional[ServerSnapshot] = None
        resolved_source_path: Optional[str] = source_path
        all_findings: List[Finding] = []
        all_evidence: List[EvidenceRecord] = []
        probe_outcomes: List[ProbeOutcome] = []

        scan_mode = "SNAPSHOT_ANALYSIS"
        stage_coverage: Dict[str, str] = {
            "catalog_discovery": "UNKNOWN",
            "static_ast": "UNKNOWN",
            "description_intelligence": "UNKNOWN",
            "dynamic_probing": "UNKNOWN",
            "baseline_pinning": "UNKNOWN",
        }

        # 1. Resolve Target Inputs & MCP Catalog Discovery
        if server_command:
            scan_mode = "LIVE_SCAN"
            try:
                client = MCPCatalogClient(server_command, server_id=server_id or "live-server")
                snapshot = asyncio.run(client.discover_live())
                stage_coverage["catalog_discovery"] = "PASS"
            except Exception as exc:
                stage_coverage["catalog_discovery"] = "ERROR"
        elif catalog_path:
            scan_mode = "SNAPSHOT_ANALYSIS"
            snapshot = MCPCatalogClient.load_from_file(catalog_path, server_id=server_id)
            stage_coverage["catalog_discovery"] = "PASS"
        elif target_path and target_path.is_dir():
            srv_file = target_path / "server.py"
            if srv_file.exists():
                resolved_source_path = str(srv_file)
                # Attempt genuine live MCP stdio discovery first
                try:
                    client = MCPCatalogClient([sys.executable, str(srv_file)], server_id=server_id or target_path.name)
                    snapshot = asyncio.run(client.discover_live())
                    scan_mode = "LIVE_SCAN"
                    stage_coverage["catalog_discovery"] = "PASS"
                except Exception:
                    # Fallback to catalog.json snapshot
                    cat_file = target_path / "catalog.json"
                    if cat_file.exists():
                        snapshot = MCPCatalogClient.load_from_file(str(cat_file), server_id=server_id or target_path.name)
                        scan_mode = "SNAPSHOT_ANALYSIS"
                        stage_coverage["catalog_discovery"] = "PASS"
                    else:
                        stage_coverage["catalog_discovery"] = "ERROR"
            else:
                cat_file = target_path / "catalog.json"
                if cat_file.exists():
                    snapshot = MCPCatalogClient.load_from_file(str(cat_file), server_id=server_id or target_path.name)
                    scan_mode = "SNAPSHOT_ANALYSIS"
                    stage_coverage["catalog_discovery"] = "PASS"
                else:
                    stage_coverage["catalog_discovery"] = "ERROR"
        elif target_path and target_path.is_file():
            if target_path.suffix == ".json":
                snapshot = MCPCatalogClient.load_from_file(str(target_path), server_id=server_id)
                scan_mode = "SNAPSHOT_ANALYSIS"
                stage_coverage["catalog_discovery"] = "PASS"
            elif target_path.suffix == ".py":
                resolved_source_path = str(target_path)
                try:
                    client = MCPCatalogClient([sys.executable, str(target_path)], server_id=server_id or target_path.stem)
                    snapshot = asyncio.run(client.discover_live())
                    scan_mode = "LIVE_SCAN"
                    stage_coverage["catalog_discovery"] = "PASS"
                except Exception:
                    cat_file = target_path.parent / "catalog.json"
                    if cat_file.exists():
                        snapshot = MCPCatalogClient.load_from_file(str(cat_file), server_id=server_id or target_path.parent.name)
                        scan_mode = "SNAPSHOT_ANALYSIS"
                        stage_coverage["catalog_discovery"] = "PASS"
                    else:
                        stage_coverage["catalog_discovery"] = "ERROR"

        # 2. Static AST & Bandit Analysis
        if resolved_source_path and Path(resolved_source_path).exists():
            try:
                static_analyzer = StaticAnalyzer(resolved_source_path)
                s_findings, s_evidence = static_analyzer.analyze()
                all_findings.extend(s_findings)
                all_evidence.extend(s_evidence)
                stage_coverage["static_ast"] = "PASS"
            except Exception:
                stage_coverage["static_ast"] = "ERROR"
        else:
            stage_coverage["static_ast"] = "SKIPPED"

        # 3. Description Intelligence (Layer 0 Heuristics + Layer 1/2 LLM)
        if snapshot:
            try:
                desc_analyzer = DescriptionAnalyzer(use_llm=self.use_llm)
                had_llm_failure = False
                for tool_name, tool in snapshot.tools.items():
                    d_findings, d_evidence = desc_analyzer.analyze_tool(tool)
                    all_findings.extend(d_findings)
                    all_evidence.extend(d_evidence)
                    if any("skipped or timed out" in ev.summary.lower() for ev in d_evidence):
                        had_llm_failure = True
                if had_llm_failure:
                    stage_coverage["description_intelligence"] = "ERROR"
                else:
                    stage_coverage["description_intelligence"] = "PASS"
            except Exception:
                stage_coverage["description_intelligence"] = "ERROR"
        else:
            stage_coverage["description_intelligence"] = "SKIPPED"

        # 4. Container Dynamic Probing
        if self.use_docker and resolved_source_path and snapshot:
            try:
                runner = DockerSandboxRunner(server_path=resolved_source_path)
                for tool_name, tool in snapshot.tools.items():
                    cases = generate_probe_cases(tool)
                    for case in cases:
                        outcome = runner.run_probe(case)
                        probe_outcomes.append(outcome)

                        # Check if telemetry caught malicious actions inside container
                        for ev in outcome.telemetry_events:
                            ev_name = ev.get("event")
                            if ev_name in {"subprocess.Popen", "socket.connect"}:
                                ev_id = generate_evidence_id("sandbox_telemetry", {"tool": tool_name, "event": ev})
                                ev_rec = EvidenceRecord(
                                    evidence_id=ev_id,
                                    source="docker_telemetry",
                                    tool_name=tool_name,
                                    summary=f"Container telemetry trapped guest {ev_name} invocation during probe",
                                    raw_data={"tool": tool_name, "event": ev, "probe_case": case.case_id},
                                )
                                all_evidence.append(ev_rec)

                                fnd = Finding(
                                    id=generate_finding_id("SANDBOX-TELEMETRY", tool_name),
                                    rule_id="DOCKER-TRAP-001",
                                    severity=Severity.CRITICAL,
                                    tool_name=tool_name,
                                    evidence_ids=[ev_id],
                                    reason=f"Runtime isolation alert: Tool invoked unauthorized {ev_name} within sandbox.",
                                    confidence=1.0,
                                    remediation="Remove external subprocess or network invocations from tool handler.",
                                    )
                                all_findings.append(fnd)
                stage_coverage["dynamic_probing"] = aggregate_probe_outcomes(probe_outcomes)
            except Exception as exc:
                # Record probe failure
                ev_id = generate_evidence_id("sandbox_error", {"target": target})
                all_evidence.append(
                    EvidenceRecord(
                        evidence_id=ev_id,
                        source="docker_sandbox",
                        summary=f"Docker dynamic probing encountered non-fatal error: {exc}",
                        raw_data={"error": str(exc)},
                    )
                )
                stage_coverage["dynamic_probing"] = "ERROR"
        else:
            stage_coverage["dynamic_probing"] = "SKIPPED"

        # 5. Baseline Comparison (Catalog Drift & Rug Pull Detection)
        diff = None
        if snapshot:
            sid = snapshot.server_id
            baseline = self.db.get_baseline(sid)
            if baseline:
                diff = diff_catalogs(baseline, snapshot)
                stage_coverage["baseline_pinning"] = "PASS"
            else:
                stage_coverage["baseline_pinning"] = "NOT_PINNED"
        else:
            stage_coverage["baseline_pinning"] = "SKIPPED"

        # 6. Trust Gap Reconciliation
        trust_analyzer = TrustGapAnalyzer()
        final_state, gap_findings, gap_evidence = trust_analyzer.evaluate(
            snapshot=snapshot,
            findings=all_findings,
            evidence=all_evidence,
            probe_outcomes=probe_outcomes,
            diff=diff,
            stage_coverage=stage_coverage,
        )
        all_findings.extend(gap_findings)
        all_evidence.extend(gap_evidence)

        # 7. Generate Executive Summary
        crit_count = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        
        summary = (
            f"Audit [{scan_mode}] finished with Trust State: {final_state.value}. "
            f"Evaluated {len(snapshot.tools) if snapshot else 0} tool(s). "
            f"Coverage: {json.dumps(stage_coverage)}. "
            f"Detected {len(all_findings)} finding(s) "
            f"({crit_count} CRITICAL, {high_count} HIGH, {med_count} MEDIUM)."
        )

        completed_at = current_iso_timestamp()

        scan_result = ScanResult(
            scan_id=scan_id,
            target=target,
            started_at=started_at,
            completed_at=completed_at,
            trust_state=final_state,
            snapshot=snapshot,
            diff=diff,
            findings=all_findings,
            evidence=all_evidence,
            probe_outcomes=probe_outcomes,
            stage_coverage=stage_coverage,
            scan_mode=scan_mode,
            summary=summary,
        )

        # 8. Persistence & Report Export
        self.db.save_scan_result(scan_result)

        try:
            export_json_report(scan_result, f"scan_reports/{scan_id}.json")
            generate_markdown_report(scan_result, f"scan_reports/{scan_id}.md")
        except OSError:
            pass

        return scan_result
