"""SQLite Storage for Scans, Baselines, Findings, and Evidence Capsules."""

import json
import sqlite3
from pathlib import Path
from typing import List, Optional
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
            conn.commit()

    def save_baseline(self, snapshot: ServerSnapshot) -> None:
        """Insert an explicitly approved baseline; preserve any existing approval."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
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
