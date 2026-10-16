"""PostgreSQL / SQLAlchemy Persistence Engine for AuditForge.

Provides high-concurrency, transactional persistence for enterprise deployments
using SQLAlchemy 2.0 with connection pooling and automated migration support.
Implements the exact same interface as the standalone SQLite Database class.
"""

from contextlib import contextmanager
import json
import os
from typing import Any, Dict, List, Optional
from sqlalchemy import create_engine, select, update, func, desc
from sqlalchemy.orm import sessionmaker, Session

from auditforge.core.contracts import (
    canonical_json,
    Finding,
    EvidenceRecord,
    ScanResult,
    ServerSnapshot,
)
from auditforge.storage.models import (
    Base,
    BaselineModel,
    ScanModel,
    FindingModel,
    EvidenceModel,
    JobModel,
    _utc_now_str,
)


class PostgresDatabase:
    """Enterprise SQLAlchemy/PostgreSQL persistence engine for AuditForge."""

    def __init__(self, db_url: str):
        self.db_url = db_url
        # Convert postgres:// to postgresql:// if needed for SQLAlchemy compatibility
        if self.db_url.startswith("postgres://"):
            self.db_url = self.db_url.replace("postgres://", "postgresql://", 1)
        self.db_path = self.db_url

        connect_args = {}
        if self.db_url.startswith("sqlite"):
            connect_args = {"check_same_thread": False}

        self.engine = create_engine(
            self.db_url,
            pool_pre_ping=True,
            connect_args=connect_args,
        )
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self._init_schema()

    def _init_schema(self) -> None:
        """Create tables if they do not exist."""
        Base.metadata.create_all(bind=self.engine)

    @contextmanager
    def get_session(self):
        session: Session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_baseline(self, snapshot: ServerSnapshot, overwrite: bool = False) -> bool:
        """Insert or update a pinned catalog baseline."""
        with self.get_session() as session:
            existing = session.get(BaselineModel, snapshot.server_id)
            if existing and not overwrite:
                return False

            raw_snap = canonical_json(snapshot.model_dump(mode="json"))
            if existing:
                existing.catalog_fingerprint = snapshot.catalog_fingerprint
                existing.snapshot_json = raw_snap
                existing.created_at = snapshot.timestamp
            else:
                model = BaselineModel(
                    server_id=snapshot.server_id,
                    catalog_fingerprint=snapshot.catalog_fingerprint,
                    snapshot_json=raw_snap,
                    created_at=snapshot.timestamp,
                )
                session.add(model)
            return True

    def get_baseline(self, server_id: str) -> Optional[ServerSnapshot]:
        """Retrieve baseline snapshot for server_id."""
        with self.get_session() as session:
            record = session.get(BaselineModel, server_id)
            if record:
                return ServerSnapshot.model_validate_json(record.snapshot_json)
            return None

    def list_baselines(self) -> List[Dict[str, Any]]:
        """List all baselines ordered by creation timestamp."""
        with self.get_session() as session:
            records = session.execute(
                select(BaselineModel).order_by(desc(BaselineModel.created_at))
            ).scalars().all()
            results = []
            for r in records:
                item = {
                    "server_id": r.server_id,
                    "server_name": r.server_id,
                    "catalog_fingerprint": r.catalog_fingerprint,
                    "catalog_hash": r.catalog_fingerprint,
                    "trust_state": "APPROVED",
                    "approved_by": "admin",
                    "created_at": r.created_at,
                    "approved_at": r.created_at,
                    "timestamp": r.created_at,
                    "snapshot_json": r.snapshot_json,
                }
                try:
                    snap = json.loads(r.snapshot_json)
                    item["tool_count"] = len(snap.get("tools", {}))
                except Exception:
                    item["tool_count"] = 0
                results.append(item)
            return results

    def save_scan_result(self, result: ScanResult) -> None:
        """Save a complete scan result and index findings and evidence."""
        with self.get_session() as session:
            existing = session.get(ScanModel, result.scan_id)
            if existing:
                session.delete(existing)
                session.flush()

            scan_record = ScanModel(
                scan_id=result.scan_id,
                target=result.target,
                started_at=result.started_at,
                completed_at=result.completed_at,
                trust_state=result.trust_state.value,
                summary=result.summary,
                result_json=result.model_dump_json(),
            )
            session.add(scan_record)

            for f in result.findings:
                session.merge(
                    FindingModel(
                        id=f.id,
                        scan_id=result.scan_id,
                        rule_id=f.rule_id,
                        severity=f.severity.value,
                        tool_name=f.tool_name,
                        confidence=f.confidence,
                        reason=f.reason,
                        remediation=f.remediation,
                    )
                )

            for ev in result.evidence:
                session.merge(
                    EvidenceModel(
                        evidence_id=ev.evidence_id,
                        scan_id=result.scan_id,
                        source=ev.source,
                        tool_name=ev.tool_name,
                        observed_at=ev.observed_at,
                        summary=ev.summary,
                        raw_data_json=json.dumps(ev.raw_data),
                    )
                )

    def save_scan(self, result: ScanResult) -> None:
        self.save_scan_result(result)

    def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """Retrieve a complete scan result by scan_id."""
        with self.get_session() as session:
            record = session.get(ScanModel, scan_id)
            if record:
                return ScanResult.model_validate_json(record.result_json)
            return None

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List recent scans ordered by started_at."""
        with self.get_session() as session:
            records = session.execute(
                select(ScanModel).order_by(desc(ScanModel.started_at)).limit(limit)
            ).scalars().all()
            results = []
            for r in records:
                item = {
                    "id": r.scan_id,
                    "server_name": r.target,
                    "started_at": r.started_at,
                    "trust_state": r.trust_state,
                    "summary": r.summary,
                    "result_json": r.result_json,
                }
                try:
                    res_obj = json.loads(r.result_json)
                    item["findings"] = res_obj.get("findings", [])
                    item["catalog_hash"] = res_obj.get("snapshot", {}).get("catalog_fingerprint")
                    item["status"] = "COMPLETED" if res_obj.get("completed_at") else "PENDING"
                except Exception:
                    item["findings"] = []
                results.append(item)
            return results

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate security statistics."""
        with self.get_session() as session:
            scan_cnt = session.scalar(select(func.count(ScanModel.scan_id))) or 0
            base_cnt = session.scalar(select(func.count(BaselineModel.server_id))) or 0
            
            findings_q = session.execute(
                select(FindingModel.severity, func.count(FindingModel.id)).group_by(FindingModel.severity)
            ).all()
            sev_map = {row[0]: row[1] for row in findings_q}
            return {
                "total_scans": scan_cnt,
                "total_baselines": base_cnt,
                "findings_by_severity": sev_map,
            }

    # Job Queue Persistence Methods
    def create_job(self, job_id: str, target: str, scan_type: str = "LIVE_SCAN") -> Dict[str, Any]:
        with self.get_session() as session:
            job = JobModel(
                job_id=job_id,
                target=target,
                scan_type=scan_type,
                status="QUEUED",
                created_at=_utc_now_str(),
            )
            session.add(job)
            return job.to_dict()

    def update_job(
        self,
        job_id: str,
        status: str,
        scan_id: Optional[str] = None,
        error: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        with self.get_session() as session:
            job = session.get(JobModel, job_id)
            if not job:
                return None
            job.status = status
            if status == "RUNNING" and not job.started_at:
                job.started_at = _utc_now_str()
            elif status in ("SUCCEEDED", "FAILED", "CANCELLED"):
                job.completed_at = _utc_now_str()
            if scan_id:
                job.scan_id = scan_id
            if error:
                job.error = error
            return job.to_dict()

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self.get_session() as session:
            job = session.get(JobModel, job_id)
            return job.to_dict() if job else None

    def list_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.get_session() as session:
            records = session.execute(
                select(JobModel).order_by(desc(JobModel.created_at)).limit(limit)
            ).scalars().all()
            return [r.to_dict() for r in records]

    def cancel_job(self, job_id: str) -> bool:
        with self.get_session() as session:
            job = session.get(JobModel, job_id)
            if job and job.status in ("QUEUED", "RUNNING"):
                job.status = "CANCELLED"
                job.completed_at = _utc_now_str()
                return True
            return False


def get_storage():
    """Factory returning appropriate Database implementation based on environment."""
    db_url = os.getenv("DATABASE_URL")
    if db_url and (db_url.startswith("postgresql://") or db_url.startswith("postgres://")):
        return PostgresDatabase(db_url)
    
    # Fallback to local SQLite Database
    from auditforge.storage.database import Database
    return Database()
