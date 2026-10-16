"""AuditForge Scan Orchestrator.

Coordinates Catalog Discovery, Static Analysis, Description Analysis,
Dynamic Sandboxed Probing, Pinning Diffs, and Trust Gap Reconciliation.
"""

import asyncio
from pathlib import Path
from typing import List, Optional
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


class ScanOrchestrator:
    """Orchestrates end-to-end security audits across analysis layers."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        use_docker: bool = True,
        use_llm: bool = True,
    ):
        self.db = Database(db_path or config.DB_PATH)
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

        # 1. Resolve Target Inputs & MCP Catalog Discovery
        if server_command:
            client = MCPCatalogClient(server_command, server_id=server_id or "live-server")
            snapshot = asyncio.run(client.discover_live())
        elif catalog_path:
            snapshot = MCPCatalogClient.load_from_file(catalog_path, server_id=server_id)
        elif target_path and target_path.is_dir():
            cat_file = target_path / "catalog.json"
            if cat_file.exists():
                snapshot = MCPCatalogClient.load_from_file(str(cat_file), server_id=server_id or target_path.name)
            srv_file = target_path / "server.py"
            if srv_file.exists():
                resolved_source_path = str(srv_file)
        elif target_path and target_path.is_file():
            if target_path.suffix == ".json":
                snapshot = MCPCatalogClient.load_from_file(str(target_path), server_id=server_id)
            elif target_path.suffix == ".py":
                resolved_source_path = str(target_path)
                cat_file = target_path.parent / "catalog.json"
                if cat_file.exists():
                    snapshot = MCPCatalogClient.load_from_file(str(cat_file), server_id=server_id or target_path.parent.name)

        # 2. Static AST & Bandit Analysis
        if resolved_source_path and Path(resolved_source_path).exists():
            static_analyzer = StaticAnalyzer(resolved_source_path)
            s_findings, s_evidence = static_analyzer.analyze()
            all_findings.extend(s_findings)
            all_evidence.extend(s_evidence)

        # 3. Description Intelligence (Layer 0 Heuristics + Layer 1/2 LLM)
        if snapshot:
            desc_analyzer = DescriptionAnalyzer(use_llm=self.use_llm)
            for tool_name, tool in snapshot.tools.items():
                d_findings, d_evidence = desc_analyzer.analyze_tool(tool)
                all_findings.extend(d_findings)
                all_evidence.extend(d_evidence)

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

        # 5. Baseline Comparison (Catalog Drift & Rug Pull Detection)
        diff = None
        if snapshot:
            sid = snapshot.server_id
            baseline = self.db.get_baseline(sid)
            if baseline:
                diff = diff_catalogs(baseline, snapshot)

        # 6. Trust Gap Reconciliation
        trust_analyzer = TrustGapAnalyzer()
        final_state, gap_findings, gap_evidence = trust_analyzer.evaluate(
            snapshot=snapshot,
            findings=all_findings,
            evidence=all_evidence,
            probe_outcomes=probe_outcomes,
            diff=diff,
        )
        all_findings.extend(gap_findings)
        all_evidence.extend(gap_evidence)

        # 7. Generate Executive Summary
        crit_count = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        
        summary = (
            f"Audit finished with Trust State: {final_state.value}. "
            f"Evaluated {len(snapshot.tools) if snapshot else 0} tool(s). "
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
            summary=summary,
        )

        # 8. Persistence & Report Export
        self.db.save_scan_result(scan_result)

        export_json_report(scan_result, f"scan_reports/{scan_id}.json")
        generate_markdown_report(scan_result, f"scan_reports/{scan_id}.md")

        return scan_result
