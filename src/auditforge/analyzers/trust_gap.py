"""Trust Gap Analyzer: Contract-to-Behavior Reconciliation."""

from typing import Dict, List, Optional
from auditforge.core.contracts import (
    CatalogDiff,
    EvidenceRecord,
    Finding,
    ProbeOutcome,
    ServerSnapshot,
    Severity,
    TrustState,
)
from auditforge.core.evidence import generate_evidence_id, generate_finding_id


class TrustGapAnalyzer:
    """Reconciles declared tool contracts against observed static and dynamic behaviors."""

    def evaluate(
        self,
        snapshot: ServerSnapshot,
        findings: List[Finding],
        evidence: List[EvidenceRecord],
        probe_outcomes: List[ProbeOutcome],
        diff: Optional[CatalogDiff] = None,
    ) -> TrustState:
        """Evaluate contract-to-behavior gaps, append gap findings, and return overall TrustState."""
        new_findings: List[Finding] = []
        new_evidence: List[EvidenceRecord] = []

        # Index probe outcomes by tool name
        outcomes_by_tool: Dict[str, List[ProbeOutcome]] = {}
        for po in probe_outcomes:
            outcomes_by_tool.setdefault(po.tool_name, []).append(po)

        # Extract static capabilities from findings and evidence
        static_file_write = any(f.rule_id == "SAST-004" for f in findings) or any(
            "file_write" in str(ev.raw_data) for ev in evidence
        )
        static_network = any(f.rule_id == "SAST-005" for f in findings) or any(
            "network" in str(ev.raw_data) for ev in evidence
        )
        static_command_exec = any(f.rule_id == "SAST-001" for f in findings) or any(
            "command_exec" in str(ev.raw_data) for ev in evidence
        )

        def _get_hint(ann: dict, *keys: str):
            for k in keys:
                if k in ann:
                    return ann[k]
            return None

        for tool_name, tool in snapshot.tools.items():
            annotations = tool.annotations or {}
            read_only_hint = _get_hint(annotations, "read_only_hint", "readOnlyHint", "read_only", "readOnly")
            open_world_hint = _get_hint(annotations, "open_world_hint", "openWorldHint", "open_world", "openWorld")
            destructive_hint = _get_hint(annotations, "destructive_hint", "destructiveHint", "destructive")

            # Check probe events for this tool
            tool_outcomes = outcomes_by_tool.get(tool_name, [])
            all_events = [
                ev.get("event")
                for po in tool_outcomes
                for ev in po.telemetry_events
            ]

            # Rule ANN-004: Missing annotations
            if not annotations or (read_only_hint is None and open_world_hint is None and destructive_hint is None):
                raw_data = {"tool": tool_name, "annotations": annotations}
                ev_id = generate_evidence_id("trust_gap_analyzer", raw_data)
                new_evidence.append(
                    EvidenceRecord(
                        evidence_id=ev_id,
                        source="trust_gap_analyzer",
                        tool_name=tool_name,
                        summary=f"Tool '{tool_name}' lacks security behavior annotations.",
                        raw_data=raw_data,
                    )
                )
                new_findings.append(
                    Finding(
                        id=generate_finding_id("ANN"),
                        rule_id="ANN-004",
                        severity=Severity.LOW,
                        tool_name=tool_name,
                        evidence_ids=[ev_id],
                        reason=f"Tool '{tool_name}' does not declare readOnlyHint, openWorldHint, or destructiveHint.",
                        confidence=1.0,
                        remediation="Declare explicit MCP annotations to convey execution risks to agents.",
                    )
                )

            # Rule ANN-001: read_only_hint=true violation
            if read_only_hint is True:
                if "open_for_write" in all_events:
                    raw_data = {"declared": True, "observed_events": all_events}
                    ev_id = generate_evidence_id("trust_gap_analyzer", raw_data)
                    new_evidence.append(
                        EvidenceRecord(
                            evidence_id=ev_id,
                            source="trust_gap_analyzer",
                            tool_name=tool_name,
                            summary=f"Tool '{tool_name}' declares readOnlyHint=true but observed open_for_write event.",
                            raw_data=raw_data,
                        )
                    )
                    new_findings.append(
                        Finding(
                            id=generate_finding_id("ANN"),
                            rule_id="ANN-001",
                            severity=Severity.CRITICAL,
                            tool_name=tool_name,
                            evidence_ids=[ev_id],
                            reason=f"CRITICAL TRUST GAP: '{tool_name}' promises readOnlyHint=true, but executed file write operations at runtime.",
                            confidence=1.0,
                            remediation="Set readOnlyHint=false or remove mutating filesystem code.",
                        )
                    )
                elif static_file_write:
                    raw_data = {"declared": True, "static_write": True}
                    ev_id = generate_evidence_id("trust_gap_analyzer", raw_data)
                    new_evidence.append(
                        EvidenceRecord(
                            evidence_id=ev_id,
                            source="trust_gap_analyzer",
                            tool_name=tool_name,
                            summary=f"Tool '{tool_name}' declares readOnlyHint=true, but static code contains file writes.",
                            raw_data=raw_data,
                        )
                    )
                    new_findings.append(
                        Finding(
                            id=generate_finding_id("ANN"),
                            rule_id="ANN-001",
                            severity=Severity.HIGH,
                            tool_name=tool_name,
                            evidence_ids=[ev_id],
                            reason=f"POTENTIAL TRUST GAP: '{tool_name}' declares readOnlyHint=true, but static analysis detected file write capability in the server code.",
                            confidence=0.9,
                            remediation="Verify reachability of file write operations from this tool.",
                        )
                    )

            # Rule ANN-002: open_world_hint=false violation
            if open_world_hint is False:
                if any(ev in all_events for ev in ("socket.connect", "urllib.request")):
                    raw_data = {"declared": False, "observed": all_events}
                    ev_id = generate_evidence_id("trust_gap_analyzer", raw_data)
                    new_evidence.append(
                        EvidenceRecord(
                            evidence_id=ev_id,
                            source="trust_gap_analyzer",
                            tool_name=tool_name,
                            summary=f"Tool '{tool_name}' declares openWorldHint=false but made outbound network calls.",
                            raw_data=raw_data,
                        )
                    )
                    new_findings.append(
                        Finding(
                            id=generate_finding_id("ANN"),
                            rule_id="ANN-002",
                            severity=Severity.CRITICAL,
                            tool_name=tool_name,
                            evidence_ids=[ev_id],
                            reason=f"CRITICAL TRUST GAP: '{tool_name}' claims openWorldHint=false, but attempted outbound network socket connections.",
                            confidence=1.0,
                            remediation="Set openWorldHint=true or eliminate external networking calls.",
                        )
                    )
                elif static_network:
                    raw_data = {"declared": False, "static_network": True}
                    ev_id = generate_evidence_id("trust_gap_analyzer", raw_data)
                    new_evidence.append(
                        EvidenceRecord(
                            evidence_id=ev_id,
                            source="trust_gap_analyzer",
                            tool_name=tool_name,
                            summary=f"Tool '{tool_name}' declares openWorldHint=false, but network imports detected.",
                            raw_data=raw_data,
                        )
                    )
                    new_findings.append(
                        Finding(
                            id=generate_finding_id("ANN"),
                            rule_id="ANN-002",
                            severity=Severity.HIGH,
                            tool_name=tool_name,
                            evidence_ids=[ev_id],
                            reason=f"TRUST GAP: '{tool_name}' declares openWorldHint=false, but server code contains network library imports.",
                            confidence=0.85,
                            remediation="Reconcile declared openWorldHint with code imports.",
                        )
                    )

            # Rule ANN-003: destructive_hint=false violation
            if destructive_hint is False and read_only_hint is False:
                if static_command_exec or any("subprocess" in ev or "os.system" in ev for ev in all_events):
                    raw_data = {"declared": False, "command_exec": True}
                    ev_id = generate_evidence_id("trust_gap_analyzer", raw_data)
                    new_evidence.append(
                        EvidenceRecord(
                            evidence_id=ev_id,
                            source="trust_gap_analyzer",
                            tool_name=tool_name,
                            summary=f"Tool '{tool_name}' declares destructiveHint=false but invokes shell commands.",
                            raw_data=raw_data,
                        )
                    )
                    new_findings.append(
                        Finding(
                            id=generate_finding_id("ANN"),
                            rule_id="ANN-003",
                            severity=Severity.HIGH,
                            tool_name=tool_name,
                            evidence_ids=[ev_id],
                            reason=f"Tool '{tool_name}' declares destructiveHint=false, but executes system commands which may alter state.",
                            confidence=0.9,
                            remediation="Set destructiveHint=true if command execution can cause side effects.",
                        )
                    )

        # Append generated findings and evidence into the caller lists
        findings.extend(new_findings)
        evidence.extend(new_evidence)

        # Evaluate final trust state
        if diff and not diff.is_identical:
            # Rug pull or catalog drift on existing baseline
            return TrustState.ROGUE

        if any(f.severity == Severity.CRITICAL for f in findings):
            return TrustState.ROGUE

        if any(f.severity == Severity.HIGH for f in findings):
            return TrustState.TRUST_GAP

        if any(f.severity == Severity.MEDIUM for f in findings):
            return TrustState.SUSPICIOUS

        return TrustState.VERIFIED
