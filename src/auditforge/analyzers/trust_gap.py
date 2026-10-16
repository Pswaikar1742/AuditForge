"""Trust Gap Analyzer: Contract-to-Behavior Reconciliation.

Reconciles claimed capabilities (annotations, descriptions) against observed
static AST findings, guest telemetry events, and baseline drift.
"""

from typing import Dict, List, Optional, Tuple
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
        stage_coverage: Optional[Dict[str, str]] = None,
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
                    or annotations.get("readOnlyHint") is True
                )
                is_claimed_non_destructive = (
                    annotations.get("destructive") is False
                    or annotations.get("destructive_hint") is False
                    or annotations.get("destructiveHint") is False
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

                    if destructive_probes:
                        # Runtime telemetry actually trapped mutating actions inside container
                        ev_id = generate_evidence_id("trust_gap_runtime", {"tool": name, "claimed": "readOnly"})
                        ev = EvidenceRecord(
                            evidence_id=ev_id,
                            source="trust_gap_reconciler",
                            tool_name=name,
                            summary=f"Trust Gap (OBSERVED_ATTEMPT): Tool '{name}' claims readOnly/non-destructive, but runtime telemetry trapped unauthorized state mutations.",
                            raw_data={
                                "tool_name": name,
                                "provenance": "OBSERVED_ATTEMPT",
                                "annotations": annotations,
                                "telemetry_matches": len(destructive_probes),
                            },
                        )
                        gap_evidence.append(ev)

                        probe_ev_ids = [p.evidence_id for p in destructive_probes if p.evidence_id]
                        gap_finding = Finding(
                            id=generate_finding_id("TRUST-GAP-RUNTIME", name),
                            rule_id="TRUST-GAP-001",
                            severity=Severity.CRITICAL if any(f.severity == Severity.CRITICAL for f in destructive_findings) else Severity.HIGH,
                            tool_name=name,
                            evidence_ids=[ev_id] + probe_ev_ids,
                            reason=(
                                f"Contract violation (OBSERVED_ATTEMPT): Tool '{name}' declares readOnly=True / destructive=False in MCP annotations, "
                                f"but dynamic sandbox telemetry OBSERVED execution of mutating operations during probing."
                            ),
                            confidence=1.0,
                            remediation="Correct the metadata annotations or remove mutating operations from tool handler.",
                        )
                        gap_findings.append(gap_finding)

                    elif destructive_findings:
                        # Static AST only: LIKELY / SOURCE_INDICATOR (no runtime execution observed)
                        ev_id = generate_evidence_id("trust_gap_static", {"tool": name, "claimed": "readOnly"})
                        conflicting = [f.rule_id for f in destructive_findings]
                        ev = EvidenceRecord(
                            evidence_id=ev_id,
                            source="trust_gap_reconciler",
                            tool_name=name,
                            summary=f"Trust Gap (SOURCE_INDICATOR / LIKELY): Tool '{name}' claims readOnly/non-destructive, but static AST analysis detected state-mutating capability in source.",
                            raw_data={
                                "tool_name": name,
                                "provenance": "SOURCE_INDICATOR",
                                "annotations": annotations,
                                "conflicting_findings": conflicting,
                            },
                        )
                        gap_evidence.append(ev)

                        gap_finding = Finding(
                            id=generate_finding_id("TRUST-GAP-STATIC", name),
                            rule_id="TRUST-GAP-001",
                            severity=Severity.HIGH,
                            tool_name=name,
                            evidence_ids=[ev_id] + [eid for f in destructive_findings for eid in f.evidence_ids],
                            reason=(
                                f"Contract discrepancy (SOURCE_INDICATOR / LIKELY): Tool '{name}' declares readOnly=True / destructive=False in MCP annotations, "
                                f"but static source inspection detected state mutation or process execution capabilities ({', '.join(conflicting)}). No runtime execution confirmed."
                            ),
                            confidence=0.85,
                            remediation="Review tool source code to remove mutating operations or update MCP annotations.",
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
            # Verified ONLY if tools exist, zero findings, and required detectors passed
            if stage_coverage:
                has_error = any(v == "ERROR" for v in stage_coverage.values())
                mandatory_failed = any(
                    stage_coverage.get(st) in {"ERROR", "SKIPPED", "UNKNOWN"}
                    for st in ("catalog_discovery", "static_ast", "description_intelligence")
                )
                if has_error or mandatory_failed:
                    # Incomplete detector coverage cannot be claimed as safety proof
                    state = TrustState.UNKNOWN
                else:
                    state = TrustState.VERIFIED
            else:
                state = TrustState.VERIFIED
        else:
            state = TrustState.UNKNOWN

        return state, gap_findings, gap_evidence
