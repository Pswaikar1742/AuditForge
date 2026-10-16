"""SQLite Storage for Scans, Baselines, Findings, and Evidence Capsules."""

import json
import sqlite3
from typing import Any, Dict, List, Optional
from auditforge.core.contracts import (
    canonical_json,
    Finding,
    EvidenceRecord,
    ScanResult,
    ServerSnapshot,
)


class Database:
    """SQLite persistence layer for AuditForge."""

    def __init__(self, db_path: str = "auditforge.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create database tables if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Baselines for catalog pinning
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    server_id TEXT PRIMARY KEY,
                    catalog_fingerprint TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

            # Scans history
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    trust_state TEXT NOT NULL,
                    summary TEXT,
                    result_json TEXT NOT NULL
                )
            """)

            # Findings index
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    tool_name TEXT,
                    confidence REAL NOT NULL,
                    reason TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
                )
            """)

            # Evidence capsules index
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    tool_name TEXT,
                    observed_at TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    raw_data_json TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
                )
            """)

            # Asynchronous jobs tracking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL DEFAULT 'LIVE_SCAN',
                    status TEXT NOT NULL DEFAULT 'QUEUED',
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    error TEXT,
                    scan_id TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
                )
            """)
            conn.commit()

    def save_baseline(self, snapshot: ServerSnapshot, overwrite: bool = False) -> bool:
        """Insert an explicitly approved baseline; preserve any existing approval unless overwrite is True.

        Returns True if a new baseline was inserted or overwritten,
        False if an existing baseline already existed and was preserved.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if overwrite:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO baselines (server_id, catalog_fingerprint, snapshot_json, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        snapshot.server_id,
                        snapshot.catalog_fingerprint,
                        canonical_json(snapshot.model_dump(mode="json")),
                        snapshot.timestamp,
                    ),
                )
                conn.commit()
                return True
            else:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO baselines (server_id, catalog_fingerprint, snapshot_json, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        snapshot.server_id,
                        snapshot.catalog_fingerprint,
                        canonical_json(snapshot.model_dump(mode="json")),
                        snapshot.timestamp,
                    ),
                )
                conn.commit()
                return cursor.rowcount > 0

    def get_baseline(self, server_id: str) -> Optional[ServerSnapshot]:
        """Retrieve baseline snapshot for server_id if it exists."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT snapshot_json FROM baselines WHERE server_id = ?",
                (server_id,),
            )
            row = cursor.fetchone()
            if row:
                return ServerSnapshot.model_validate_json(row["snapshot_json"])
            return None

    def save_scan_result(self, result: ScanResult) -> None:
        """Save a complete scan result and index its findings and evidence."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO scans (scan_id, target, started_at, completed_at, trust_state, summary, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    result.target,
                    result.started_at,
                    result.completed_at,
                    result.trust_state.value,
                    result.summary,
                    result.model_dump_json(),
                ),
            )

            for f in result.findings:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO findings (id, scan_id, rule_id, severity, tool_name, confidence, reason, remediation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.id,
                        result.scan_id,
                        f.rule_id,
                        f.severity.value,
                        f.tool_name,
                        f.confidence,
                        f.reason,
                        f.remediation,
                    ),
                )

            for ev in result.evidence:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO evidence (evidence_id, scan_id, source, tool_name, observed_at, summary, raw_data_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ev.evidence_id,
                        result.scan_id,
                        ev.source,
                        ev.tool_name,
                        ev.observed_at,
                        ev.summary,
                        json.dumps(ev.raw_data),
                    ),
                )
            conn.commit()

    def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """Retrieve a complete scan result by scan_id."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT result_json FROM scans WHERE scan_id = ?",
                (scan_id,),
            )
            row = cursor.fetchone()
            if row:
                return ScanResult.model_validate_json(row["result_json"])
            return None

    def save_scan(self, result: ScanResult) -> None:
        """Alias for save_scan_result."""
        self.save_scan_result(result)

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List recent scans."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT scan_id as id, target as server_name, started_at, trust_state, summary, result_json FROM scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    res_obj = json.loads(item.get("result_json", "{}"))
                    item["findings"] = res_obj.get("findings", [])
                    item["catalog_hash"] = res_obj.get("snapshot", {}).get("catalog_fingerprint")
                    item["status"] = "COMPLETED" if res_obj.get("completed_at") else "PENDING"
                except Exception:
                    item["findings"] = []
                results.append(item)
            return results

    def list_baselines(self) -> List[Dict[str, Any]]:
        """List all pinned baselines with complete field aliases."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT server_id, server_id as server_name, catalog_fingerprint, catalog_fingerprint as catalog_hash, 'APPROVED' as trust_state, 'admin' as approved_by, created_at, created_at as approved_at, created_at as timestamp, snapshot_json FROM baselines ORDER BY created_at DESC"
            )
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                if item.get("snapshot_json"):
                    try:
                        snap = json.loads(item["snapshot_json"])
                        item["tool_count"] = len(snap.get("tools", {}))
                    except Exception:
                        item["tool_count"] = 0
                else:
                    item["tool_count"] = 0
                results.append(item)
            return results

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate security statistics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            scan_cnt = cursor.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            base_cnt = cursor.execute("SELECT COUNT(*) FROM baselines").fetchone()[0]
            findings_rows = cursor.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity").fetchall()
            sev_map = {row[0]: row[1] for row in findings_rows}
            return {
                "total_scans": scan_cnt,
                "total_baselines": base_cnt,
                "findings_by_severity": sev_map,
            }

    # Asynchronous Job Tracking Methods
    def create_job(self, job_id: str, target: str, scan_type: str = "LIVE_SCAN") -> Dict[str, Any]:
        """Record a newly queued asynchronous scan job."""
        from datetime import datetime, timezone
        created_at = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO jobs (job_id, target, scan_type, status, created_at)
                VALUES (?, ?, ?, 'QUEUED', ?)
                """,
                (job_id, target, scan_type, created_at),
            )
            conn.commit()
            return {
                "job_id": job_id,
                "target": target,
                "scan_type": scan_type,
                "status": "QUEUED",
                "created_at": created_at,
                "started_at": None,
                "completed_at": None,
                "error": None,
                "scan_id": None,
            }

    def update_job(
        self,
        job_id: str,
        status: str,
        scan_id: Optional[str] = None,
        error: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Update the status, timing, and results of an existing job."""
        from datetime import datetime, timezone
        now_str = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if status == "RUNNING":
                cursor.execute(
                    "UPDATE jobs SET status = ?, started_at = COALESCE(started_at, ?) WHERE job_id = ?",
                    (status, now_str, job_id),
                )
            elif status in ("SUCCEEDED", "FAILED", "CANCELLED"):
                cursor.execute(
                    "UPDATE jobs SET status = ?, completed_at = ?, scan_id = COALESCE(?, scan_id), error = COALESCE(?, error) WHERE job_id = ?",
                    (status, now_str, scan_id, error, job_id),
                )
            else:
                cursor.execute("UPDATE jobs SET status = ? WHERE job_id = ?", (status, job_id))
            conn.commit()
            return self.get_job(job_id)

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve job record by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List recent jobs ordered by creation timestamp."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,))
            return [dict(r) for r in cursor.fetchall()]

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a queued or running job."""
        from datetime import datetime, timezone
        now_str = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE jobs SET status = 'CANCELLED', completed_at = ? WHERE job_id = ? AND status IN ('QUEUED', 'RUNNING')",
                (now_str, job_id),
            )
            conn.commit()
            return cursor.rowcount > 0

