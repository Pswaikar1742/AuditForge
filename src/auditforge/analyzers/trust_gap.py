"""Trust Gap Analyzer: Contract-to-Behavior Reconciliation."""

from typing import List, Optional
from auditforge.core.contracts import (
    CatalogDiff,
    EvidenceRecord,
    Finding,
    ProbeOutcome,
    ServerSnapshot,
    TrustState,
)
from auditforge.core.errors import NotImplementedAuditError


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
        """Evaluate contract-to-behavior gaps and return overall TrustState.
        
        Implementation assigned to workstream: feat/static-description-llm & integration.
        """
        raise NotImplementedAuditError(
            "Trust gap evaluation is not yet implemented. "
            "Assigned to workstream: feat/static-description-llm & integration."
        )
