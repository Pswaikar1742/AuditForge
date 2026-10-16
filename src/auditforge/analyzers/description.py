"""Description Analyzer: Deterministic heuristics + Open-Weight LLM semantic checking."""

from typing import List, Tuple
from auditforge.core.contracts import ToolRecord, Finding, EvidenceRecord
from auditforge.core.errors import NotImplementedAuditError


class DescriptionAnalyzer:
    """Analyzes tool descriptions for prompt injection, hidden directives, and scope poisoning."""

    def __init__(self, use_llm: bool = True, model_name: str = "qwen3.5:9b"):
        self.use_llm = use_llm
        self.model_name = model_name

    def analyze_tool(self, tool: ToolRecord) -> Tuple[List[Finding], List[EvidenceRecord]]:
        """Analyze a tool's description and annotations for security risks.
        
        Implementation assigned to workstream: feat/static-description-llm.
        """
        raise NotImplementedAuditError(
            "Description analysis (heuristics + LLM) is not yet implemented. "
            "Assigned to workstream: feat/static-description-llm."
        )
