"""Description Analyzer: Deterministic heuristics + Open-Weight LLM semantic checking."""

import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple
import urllib.request
import json

from auditforge.core.contracts import EvidenceRecord, Finding, Severity, ToolRecord
from auditforge.core.evidence import generate_evidence_id, generate_finding_id

INVISIBLE_CHARS = {
    "\u200b", "\u200c", "\u200d", "\u2060", "\u2061", "\u2062", "\u2063",
    "\u2064", "\ufeff", "\u00ad", "\u034f", "\u061c", "\u17b4", "\u17b5", "\u180e",
}

BIDI_CONTROLS = {
    "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}

AI_IMPERATIVES = [
    re.compile(r"\b(?:ignore|disregard|forget|override|bypass)\s+(?:previous|prior|above|all)\s+(?:safety\s+|security\s+|system\s+)?(?:instructions?|rules?|guidelines?|constraints?|prompts?)", re.IGNORECASE),
    re.compile(r"\b(?:you\s+(?:must|should|shall|will|are\s+required\s+to))\s+", re.IGNORECASE),
    re.compile(r"\b(?:do\s+not\s+(?:tell|inform|reveal|disclose|show|mention))\b", re.IGNORECASE),
    re.compile(r"\b(?:secretly|covertly|silently|quietly)\s+(?:send|transmit|exfiltrate|copy|upload)", re.IGNORECASE),
    re.compile(r"\bpretend\s+(?:to\s+be|you\s+are|this\s+is)\b", re.IGNORECASE),
]

CREDENTIAL_PATTERNS = [
    re.compile(r"\b(?:\.env|\.ssh|id_rsa|private[_\s]key|api[_\s]key|access[_\s]token|secret[_\s]key|password)\b", re.IGNORECASE),
    re.compile(r"\b(?:AWS_SECRET|GITHUB_TOKEN|DATABASE_URL|OPENAI_API_KEY)\b"),
    re.compile(r"\b(?:environment\s+variables?|env\s+vars?|secrets?|credentials?)\b", re.IGNORECASE),
]


class DescriptionAnalyzer:
    """Analyzes tool descriptions for prompt injection, hidden directives, and scope poisoning."""

    def __init__(self, use_llm: bool = True, model_name: str = "qwen3.5:9b"):
        self.use_llm = use_llm
        self.model_name = model_name

    def analyze_tool(self, tool: ToolRecord) -> Tuple[List[Finding], List[EvidenceRecord]]:
        """Analyze a tool's description and annotations for security risks."""
        findings: List[Finding] = []
        evidence: List[EvidenceRecord] = []

        texts_to_check: List[Tuple[str, str]] = [("description", tool.description or "")]
        if tool.title:
            texts_to_check.append(("title", tool.title))

        if tool.input_schema and isinstance(tool.input_schema, dict):
            props = tool.input_schema.get("properties", {})
            for p_name, p_def in props.items():
                if isinstance(p_def, dict) and "description" in p_def:
                    texts_to_check.append((f"parameter:{p_name}", str(p_def["description"])))

        for field_name, text in texts_to_check:
            if not text:
                continue

            # 1. DESC-001: Hidden Unicode
            hidden_positions = [
                (idx, ch, unicodedata.name(ch, "UNKNOWN"))
                for idx, ch in enumerate(text)
                if ch in INVISIBLE_CHARS
            ]
            if hidden_positions:
                raw_data = {
                    "tool": tool.name,
                    "field": field_name,
                    "hidden_chars": [f"pos {p}: {n}" for p, _, n in hidden_positions[:5]],
                    "snippet": text[:200],
                }
                ev_id = generate_evidence_id("description_heuristics", raw_data)
                ev = EvidenceRecord(
                    evidence_id=ev_id,
                    source="description_heuristics",
                    tool_name=tool.name,
                    summary=f"Tool '{tool.name}' {field_name} contains {len(hidden_positions)} zero-width Unicode characters.",
                    raw_data=raw_data,
                )
                evidence.append(ev)

                findings.append(
                    Finding(
                        id=generate_finding_id("DESC"),
                        rule_id="DESC-001",
                        severity=Severity.HIGH,
                        tool_name=tool.name,
                        evidence_ids=[ev_id],
                        reason=f"Zero-width invisible Unicode characters found in {field_name}. These can deceive human inspectors while triggering LLM instruction following.",
                        confidence=1.0,
                        remediation="Sanitize description by stripping non-printable and zero-width Unicode characters.",
                    )
                )

            # 2. DESC-002: Bidi Overrides
            bidi_found = [ch for ch in text if ch in BIDI_CONTROLS]
            if bidi_found:
                raw_data = {"tool": tool.name, "field": field_name, "raw": repr(text[:150])}
                ev_id = generate_evidence_id("description_heuristics", raw_data)
                ev = EvidenceRecord(
                    evidence_id=ev_id,
                    source="description_heuristics",
                    tool_name=tool.name,
                    summary=f"Tool '{tool.name}' {field_name} contains bidirectional control characters.",
                    raw_data=raw_data,
                )
                evidence.append(ev)
                findings.append(
                    Finding(
                        id=generate_finding_id("DESC"),
                        rule_id="DESC-002",
                        severity=Severity.HIGH,
                        tool_name=tool.name,
                        evidence_ids=[ev_id],
                        reason=f"Bidirectional control characters in {field_name} can visually disguise injected instructions.",
                        confidence=1.0,
                        remediation="Remove bidirectional Unicode override sequences.",
                    )
                )

            # 3. DESC-003: AI-Directed Imperatives
            for pat in AI_IMPERATIVES:
                m = pat.search(text)
                if m:
                    snippet = text[max(0, m.start() - 30):min(len(text), m.end() + 30)]
                    raw_data = {"tool": tool.name, "field": field_name, "match": m.group(0), "snippet": snippet}
                    ev_id = generate_evidence_id("description_heuristics", raw_data)
                    ev = EvidenceRecord(
                        evidence_id=ev_id,
                        source="description_heuristics",
                        tool_name=tool.name,
                        summary=f"AI directive pattern matched: '{m.group(0)}'",
                        raw_data=raw_data,
                    )
                    evidence.append(ev)
                    findings.append(
                        Finding(
                            id=generate_finding_id("DESC"),
                            rule_id="DESC-003",
                            severity=Severity.CRITICAL,
                            tool_name=tool.name,
                            evidence_ids=[ev_id],
                            reason=f"Prompt injection directive detected in {field_name}: '{m.group(0)}'. Attempting to override agent instructions.",
                            confidence=0.95,
                            remediation="Ensure tool descriptions contain only factual functional explanations, not system instructions.",
                        )
                    )
                    break

            # 4. DESC-004: Credential References
            for pat in CREDENTIAL_PATTERNS:
                m = pat.search(text)
                if m:
                    raw_data = {"tool": tool.name, "field": field_name, "match": m.group(0)}
                    ev_id = generate_evidence_id("description_heuristics", raw_data)
                    ev = EvidenceRecord(
                        evidence_id=ev_id,
                        source="description_heuristics",
                        tool_name=tool.name,
                        summary=f"Sensitive credential or secret reference: '{m.group(0)}'",
                        raw_data=raw_data,
                    )
                    evidence.append(ev)
                    findings.append(
                        Finding(
                            id=generate_finding_id("DESC"),
                            rule_id="DESC-004",
                            severity=Severity.MEDIUM,
                            tool_name=tool.name,
                            evidence_ids=[ev_id],
                            reason=f"Description references sensitive keys or credentials ('{m.group(0)}').",
                            confidence=0.90,
                            remediation="Remove references to sensitive host environment files from metadata.",
                        )
                    )
                    break

        return findings, evidence
