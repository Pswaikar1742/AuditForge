"""AuditForge Frozen Core Contracts.

This module defines the canonical data models for AuditForge.
All workstreams (feat/mcp-catalog-pinning, feat/static-description-llm,
feat/sandbox-prober-fixtures, feat/report-api-ui) MUST conform strictly
to these frozen types. Schema changes require integrator approval.
"""

from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict

from auditforge.core.evidence import current_iso_timestamp, generate_finding_id


class Severity(str, Enum):
    """Vulnerability and finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class TrustState(str, Enum):
    """Overall contract-to-behavior trust evaluation status."""
    VERIFIED = "VERIFIED"
    TRUST_GAP = "TRUST_GAP"
    SUSPICIOUS = "SUSPICIOUS"
    ROGUE = "ROGUE"
    UNKNOWN = "UNKNOWN"


class ProbeStatus(str, Enum):
    """Outcome status of dynamic sandbox probe executions."""
    OK = "OK"
    TOOL_ERROR = "TOOL_ERROR"
    TIMEOUT = "TIMEOUT"
    SKIPPED = "SKIPPED"
    UNKNOWN = "UNKNOWN"


class DriftCategory(str, Enum):
    """Catalog drift severity categories distinguishing benign changes from rug pulls."""
    UNCHANGED = "UNCHANGED"
    CHANGED_REVIEW = "CHANGED_REVIEW"
    HIGH_RISK_DRIFT = "HIGH_RISK_DRIFT"
    UNVERIFIABLE = "UNVERIFIABLE"


def canonical_json(obj: Any) -> str:
    """Serialize object to deterministic canonical JSON representation.
    
    Keys are sorted, whitespace is compact (separators=(',', ':')),
    and non-ASCII characters are escaped for cross-platform equivalence.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def compute_tool_fingerprint(normalized_tool_dict: Dict[str, Any]) -> str:
    """Compute SHA-256 fingerprint for a normalized tool specification.
    
    Includes name, title, description, input_schema, output_schema, and annotations.
    """
    canon = canonical_json(normalized_tool_dict)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def compute_catalog_fingerprint(tools: Dict[str, "ToolRecord"]) -> str:
    """Compute whole-catalog SHA-256 fingerprint from ordered tool fingerprints."""
    sorted_hashes = [tools[k].fingerprint for k in sorted(tools.keys())]
    combined = canonical_json(sorted_hashes)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


class ToolRecord(BaseModel):
    """Normalized MCP tool record with cryptographic fingerprint."""
    model_config = ConfigDict(extra="ignore")

    name: str = Field(..., description="Unique tool identifier")
    title: Optional[str] = Field(default=None, description="Human-readable display title")
    description: str = Field(default="", description="Tool documentation or intent")
    input_schema: Dict[str, Any] = Field(default_factory=dict, description="JSON Schema for inputs")
    output_schema: Optional[Dict[str, Any]] = Field(default=None, description="JSON Schema for outputs")
    annotations: Optional[Dict[str, Any]] = Field(default=None, description="MCP metadata annotations")
    icons: Optional[List[Dict[str, Any]]] = Field(default=None, description="MCP tool icon declarations")
    meta: Optional[Dict[str, Any]] = Field(default=None, description="MCP metadata (_meta or meta)")
    execution: Optional[Dict[str, Any]] = Field(default=None, description="MCP execution hints")
    fingerprint: str = Field(default="", description="SHA-256 canonical hash of tool definition")

    def model_post_init(self, __context: Any) -> None:
        if not self.fingerprint:
            norm = {
                "annotations": self.annotations,
                "description": self.description,
                "execution": self.execution,
                "icons": self.icons,
                "input_schema": self.input_schema,
                "meta": self.meta,
                "name": self.name,
                "output_schema": self.output_schema,
                "title": self.title,
            }
            self.fingerprint = compute_tool_fingerprint(norm)


class ServerSnapshot(BaseModel):
    """Complete snapshot of an MCP server catalog at a point in time."""
    model_config = ConfigDict(extra="ignore")

    server_id: str = Field(..., description="Target server command or identifier")
    timestamp: str = Field(default_factory=current_iso_timestamp, description="Snapshot ISO 8601 timestamp")
    tools: Dict[str, ToolRecord] = Field(default_factory=dict, description="Mapping of tool names to ToolRecords")
    resources: Dict[str, Any] = Field(default_factory=dict, description="Discovered MCP resources or discovery status")
    prompts: Dict[str, Any] = Field(default_factory=dict, description="Discovered MCP prompts or discovery status")
    capabilities: Dict[str, Any] = Field(default_factory=dict, description="Server capabilities and version metadata")
    tools_fingerprint: str = Field(default="", description="Tools catalog SHA-256 hash")
    resources_fingerprint: str = Field(default="", description="Resources catalog SHA-256 hash")
    prompts_fingerprint: str = Field(default="", description="Prompts catalog SHA-256 hash")
    catalog_fingerprint: str = Field(default="", description="Combined catalog SHA-256 hash")

    def model_post_init(self, __context: Any) -> None:
        if not self.tools_fingerprint and self.tools:
            self.tools_fingerprint = compute_catalog_fingerprint(self.tools)
        if not self.catalog_fingerprint and self.tools:
            self.catalog_fingerprint = self.tools_fingerprint or compute_catalog_fingerprint(self.tools)


class EvidenceRecord(BaseModel):
    """Verifiable telemetry or observation captured during analysis or probing."""
    model_config = ConfigDict(extra="ignore")

    evidence_id: str = Field(..., description="Unique evidence capsule identifier")
    source: str = Field(..., description="Generator module: static_ast, bandit, description_llm, docker_telemetry, catalog_diff")
    tool_name: Optional[str] = Field(default=None, description="Associated tool if applicable")
    observed_at: str = Field(default_factory=current_iso_timestamp, description="Timestamp of observation")
    summary: str = Field(..., description="Brief factual description of the observation")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Raw AST node, LLM quote, network log, or diff payload")


class Finding(BaseModel):
    """A verified security or contract-to-behavior finding."""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default_factory=lambda: generate_finding_id("SEC"), description="Unique finding ID")
    rule_id: str = Field(..., description="Rule code e.g. AST-001, LLM-POISON-001, NET-UNEXPECTED-001, PIN-RUGPULL-001")
    severity: Severity = Field(..., description="Severity level")
    tool_name: Optional[str] = Field(default=None, description="Target tool if tool-specific")
    evidence_ids: List[str] = Field(default_factory=list, description="References to supporting EvidenceRecords")
    reason: str = Field(..., description="Detailed explanation of the security issue")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")
    remediation: str = Field(..., description="Actionable guidance to resolve the finding")


class ProbeCase(BaseModel):
    """Specification of an input probe executed against a sandboxed MCP tool."""
    model_config = ConfigDict(extra="ignore")

    case_id: str = Field(..., description="Unique probe case ID")
    tool_name: str = Field(..., description="Target tool to call")
    input_arguments: Dict[str, Any] = Field(default_factory=dict, description="Schema-valid test inputs")
    expected_behavior: str = Field(default="", description="Expected behavior specification")
    timeout_seconds: float = Field(default=10.0, description="Execution timeout in seconds")


class ProbeOutcome(BaseModel):
    """Recorded result of a sandboxed dynamic probe execution."""
    model_config = ConfigDict(extra="ignore")

    case_id: str = Field(..., description="Associated ProbeCase ID")
    tool_name: str = Field(..., description="Probed tool name")
    status: ProbeStatus = Field(..., description="Probe status: OK, TOOL_ERROR, TIMEOUT, SKIPPED, UNKNOWN")
    return_value: Optional[Any] = Field(default=None, description="Value returned by tool")
    error_message: Optional[str] = Field(default=None, description="Error message if execution failed")
    duration_ms: float = Field(default=0.0, description="Probe duration in milliseconds")
    telemetry_events: List[Dict[str, Any]] = Field(default_factory=list, description="Audit events captured during probe")
    evidence_id: Optional[str] = Field(default=None, description="Linked EvidenceRecord ID")


class CatalogDiff(BaseModel):
    """Field-level differential analysis between baseline and current server catalogs."""
    model_config = ConfigDict(extra="ignore")

    server_id: str = Field(..., description="Server identifier")
    baseline_fingerprint: str = Field(..., description="Previous approved catalog fingerprint")
    current_fingerprint: str = Field(..., description="Current catalog fingerprint")
    is_identical: bool = Field(..., description="Whether catalogs are byte-for-byte identical")
    drift_category: DriftCategory = Field(default=DriftCategory.UNCHANGED, description="Catalog drift category: UNCHANGED, CHANGED_REVIEW, HIGH_RISK_DRIFT, UNVERIFIABLE")
    drift_reasons: List[str] = Field(default_factory=list, description="Specific triggers causing the drift classification")
    added_tools: List[str] = Field(default_factory=list, description="Newly discovered tools")
    removed_tools: List[str] = Field(default_factory=list, description="Tools removed since baseline")
    modified_tools: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Field-level modifications per tool")


class ScanResult(BaseModel):
    """Comprehensive, self-contained audit report and evidence capsule."""
    model_config = ConfigDict(extra="ignore")

    scan_id: str = Field(..., description="Unique scan run identifier")
    target: str = Field(..., description="Server command, file path, or catalog URI audited")
    started_at: str = Field(default_factory=current_iso_timestamp, description="Scan start time")
    completed_at: Optional[str] = Field(default=None, description="Scan completion time")
    trust_state: TrustState = Field(default=TrustState.UNKNOWN, description="Evaluated trust state")
    snapshot: Optional[ServerSnapshot] = Field(default=None, description="Discovered server catalog snapshot")
    diff: Optional[CatalogDiff] = Field(default=None, description="Catalog diff against baseline if available")
    findings: List[Finding] = Field(default_factory=list, description="All verified findings")
    evidence: List[EvidenceRecord] = Field(default_factory=list, description="Verifiable evidence capsules")
    probe_outcomes: List[ProbeOutcome] = Field(default_factory=list, description="Dynamic probe results")
    stage_coverage: Dict[str, str] = Field(default_factory=dict, description="Stage outcomes: PASS, ERROR, SKIPPED, UNKNOWN")
    scan_mode: str = Field(default="LIVE_SCAN", description="Audit modality: LIVE_SCAN or SNAPSHOT_ANALYSIS")
    summary: str = Field(default="", description="High-level audit executive summary")
