"""SQLAlchemy Declarative Models for AuditForge Persistence.

Supports PostgreSQL and SQLite interchangeable backends while maintaining strict
alignment with frozen core contracts in auditforge.core.contracts.
"""

from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import (
    Column,
    String,
    Float,
    DateTime,
    Text,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def _utc_now_str() -> str:
    return datetime.now(timezone.utc).isoformat()


class BaselineModel(Base):
    """Catalog baseline approval record."""
    __tablename__ = "baselines"

    server_id = Column(String(255), primary_key=True)
    catalog_fingerprint = Column(String(64), nullable=False, index=True)
    snapshot_json = Column(Text, nullable=False)
    created_at = Column(String(64), nullable=False, default=_utc_now_str)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_id": self.server_id,
            "catalog_fingerprint": self.catalog_fingerprint,
            "snapshot_json": self.snapshot_json,
            "created_at": self.created_at,
        }


class ScanModel(Base):
    """Scan execution result record."""
    __tablename__ = "scans"

    scan_id = Column(String(64), primary_key=True)
    target = Column(String(512), nullable=False, index=True)
    started_at = Column(String(64), nullable=False)
    completed_at = Column(String(64), nullable=True)
    trust_state = Column(String(32), nullable=False, index=True)
    summary = Column(Text, nullable=True)
    result_json = Column(Text, nullable=False)

    findings = relationship("FindingModel", back_populates="scan", cascade="all, delete-orphan")
    evidence = relationship("EvidenceModel", back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "trust_state": self.trust_state,
            "summary": self.summary,
            "result_json": self.result_json,
        }


class FindingModel(Base):
    """Normalized security finding record."""
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True)
    scan_id = Column(String(64), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)
    tool_name = Column(String(255), nullable=True, index=True)
    confidence = Column(Float, nullable=False)
    reason = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)

    scan = relationship("ScanModel", back_populates="findings")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "tool_name": self.tool_name,
            "confidence": self.confidence,
            "reason": self.reason,
            "remediation": self.remediation,
        }


class EvidenceModel(Base):
    """Tamper-evident evidence record capsule."""
    __tablename__ = "evidence"

    evidence_id = Column(String(64), primary_key=True)
    scan_id = Column(String(64), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    source = Column(String(64), nullable=False, index=True)
    tool_name = Column(String(255), nullable=True)
    observed_at = Column(String(64), nullable=False)
    summary = Column(Text, nullable=False)
    raw_data_json = Column(Text, nullable=False)

    scan = relationship("ScanModel", back_populates="evidence")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "scan_id": self.scan_id,
            "source": self.source,
            "tool_name": self.tool_name,
            "observed_at": self.observed_at,
            "summary": self.summary,
            "raw_data_json": self.raw_data_json,
        }


class JobModel(Base):
    """Asynchronous scan job lifecycle tracking."""
    __tablename__ = "jobs"

    job_id = Column(String(64), primary_key=True)
    target = Column(String(512), nullable=False)
    scan_type = Column(String(64), nullable=False, default="LIVE_SCAN")
    status = Column(String(32), nullable=False, index=True, default="QUEUED")  # QUEUED, RUNNING, SUCCEEDED, FAILED, CANCELLED
    created_at = Column(String(64), nullable=False, default=_utc_now_str)
    started_at = Column(String(64), nullable=True)
    completed_at = Column(String(64), nullable=True)
    error = Column(Text, nullable=True)
    scan_id = Column(String(64), ForeignKey("scans.scan_id", ondelete="SET NULL"), nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "target": self.target,
            "scan_type": self.scan_type,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "scan_id": self.scan_id,
        }
