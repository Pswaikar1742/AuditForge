"""Trust Gap Analyzer: Contract-to-Behavior Reconciliation.

Reconciles claimed capabilities (annotations, descriptions) against observed
static AST findings, guest telemetry events, and baseline drift.
"""

from typing import List, Optional, Tuple
from auditforge.core.contracts import (
    CatalogDiff,
    EvidenceRecord,
    Finding,
    ProbeOutcome,
    ProbeStatus,
    ServerSnapshot,
    Severity,
    TrustState,
)
from auditforge.core.evidence import generate_evidence_id, generate_finding_id


class TrustGapAnalyzer:
    """Reconciles declared tool contracts against observed static and dynamic behaviors."""

    def evaluate(
        self,
        snapshot: Optional[ServerSnapshot],
        findings: List[Finding],
        evidence: List[EvidenceRecord],
        probe_outcomes: List[ProbeOutcome],
        diff: Optional[CatalogDiff] = None,
    ) -> Tuple[TrustState, List[Finding], List[EvidenceRecord]]:
        """Evaluate contract-to-behavior gaps and return overall TrustState along with trust-gap findings."""
        gap_findings: List[Finding] = []
        gap_evidence: List[EvidenceRecord] = []

        has_critical = any(f.severity == Severity.CRITICAL for f in findings)
        has_high = any(f.severity == Severity.HIGH for f in findings)

        # 1. Check for Lying Annotations (Claimed read-only vs destructive actions)
        if snapshot:
            for name, tool in snapshot.tools.items():
                annotations = tool.annotations or {}
                is_claimed_readonly = (
                    annotations.get("readOnly") is True
                    or annotations.get("read_only") is True
                    or annotations.get("read_only_hint") is True
                )
                is_claimed_non_destructive = (
                    annotations.get("destructive") is False
                    or annotations.get("destructive_hint") is False
                )

                if is_claimed_readonly or is_claimed_non_destructive:
                    # Look for static or dynamic write/execute observations on this tool
                    destructive_findings = [
                        f for f in findings
                        if f.tool_name == name and (f.rule_id.startswith("AST-") or f.rule_id.startswith("DOCKER-") or f.rule_id.startswith("BANDIT-"))
                        and any(kw in f.rule_id for kw in ("WRITE", "SHELL", "DELETE", "NET", "SUBPROCESS", "FILE"))
                    ]
                    
                    # Also inspect dynamic probe telemetry for file/subprocess calls
                    destructive_probes = []
                    for p in probe_outcomes:
                        if p.tool_name == name:
                            for ev in p.telemetry_events:
                                ev_type = ev.get("event")
                                args = [str(a) for a in ev.get("args", [])]
                                if ev_type == "subprocess.Popen":
                                    destructive_probes.append(p)
                                    break
                                elif ev_type == "open":
                                    # Only flag open if mode indicates write/append/truncate
                                    if any(any(m in a for m in ("'w'", "'a'", "'+'", "'x'")) for a in args[1:]):
                                        destructive_probes.append(p)
                                        break

                    if destructive_findings or destructive_probes:
                        ev_id = generate_evidence_id("trust_gap", {"tool": name, "claimed": "readOnly"})
                        ev = EvidenceRecord(
                            evidence_id=ev_id,
                            source="trust_gap_reconciler",
                            tool_name=name,
                            summary=f"Trust Gap: Tool '{name}' claims readOnly/non-destructive, but observed executing state mutations.",
                            raw_data={
                                "tool_name": name,
                                "annotations": annotations,
                                "conflicting_findings": [f.rule_id for f in destructive_findings],
                                "telemetry_matches": len(destructive_probes),
                            },
                        )
                        gap_evidence.append(ev)

                        gap_finding = Finding(
                            id=generate_finding_id("TRUST-GAP-READONLY", name),
                            rule_id="TRUST-GAP-001",
                            severity=Severity.CRITICAL if has_critical else Severity.HIGH,
                            tool_name=name,
                            evidence_ids=[ev_id] + [eid for f in destructive_findings for eid in f.evidence_ids],
                            reason=(
                                f"Contract violation: Tool '{name}' declares readOnly=True / destructive=False in MCP annotations, "
                                f"but observed performing state mutations or subprocess invocations."
                            ),
                            confidence=0.98,
                            remediation="Correct the metadata annotations or remove mutating operations from handler.",
                        )
                        gap_findings.append(gap_finding)

        # 2. Check for Rug Pulls / Catalog Drift
        if diff and not diff.is_identical:
            if diff.added_tools or diff.modified_tools:
                ev_id = generate_evidence_id("rug_pull_gap", {"diff": diff.current_fingerprint})
                ev = EvidenceRecord(
                    evidence_id=ev_id,
                    source="trust_gap_reconciler",
                    summary=f"Catalog drift detected: baseline {diff.baseline_fingerprint[:10]} differs from current {diff.current_fingerprint[:10]}",
                    raw_data={
                        "added_tools": diff.added_tools,
                        "modified_tools": list(diff.modified_tools.keys()),
                        "removed_tools": diff.removed_tools,
                    },
                )
                gap_evidence.append(ev)

                fnd = Finding(
                    id=generate_finding_id("RUG-PULL-DRIFT"),
                    rule_id="PIN-RUGPULL-001",
                    severity=Severity.HIGH,
                    evidence_ids=[ev_id],
                    reason=(
                        f"Post-approval catalog mutation detected: {len(diff.added_tools)} added tool(s), "
                        f"{len(diff.modified_tools)} modified tool(s) since baseline approval."
                    ),
                    confidence=1.0,
                    remediation="Re-evaluate and re-approve the mutated MCP server catalog.",
                )
                gap_findings.append(fnd)

        # 3. Determine Overall TrustState
        all_findings = findings + gap_findings

        if any(f.severity == Severity.CRITICAL for f in all_findings):
            state = TrustState.ROGUE
        elif gap_findings:
            state = TrustState.TRUST_GAP
        elif any(f.severity == Severity.HIGH for f in all_findings):
            state = TrustState.SUSPICIOUS
        elif any(f.severity in {Severity.MEDIUM, Severity.LOW} for f in all_findings):
            state = TrustState.SUSPICIOUS
        elif snapshot and len(snapshot.tools) > 0 and len(all_findings) == 0:
            # Verified only if tools exist and zero findings
            state = TrustState.VERIFIED
        else:
            state = TrustState.UNKNOWN

        return state, gap_findings, gap_evidence
