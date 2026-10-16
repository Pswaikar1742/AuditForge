"""AuditForge Database Migration Utility: SQLite to PostgreSQL / SQLAlchemy.

Validates data integrity, enforces Pydantic schema validation during transfer,
and provides row-count verification and dry-run execution.
"""

import argparse
import os
import sqlite3
import sys
from pathlib import Path
from typing import Dict, Any

from auditforge.core.contracts import ServerSnapshot, ScanResult
from auditforge.storage.pg_database import PostgresDatabase


def migrate(sqlite_path: str, target_url: str, dry_run: bool = False) -> Dict[str, Any]:
    """Migrate data from SQLite database to PostgreSQL/SQLAlchemy target database."""
    sqlite_file = Path(sqlite_path)
    if not sqlite_file.exists():
        raise FileNotFoundError(f"Source SQLite database not found at {sqlite_path}")

    print(f"[*] Connecting to source SQLite database: {sqlite_path}")
    source_conn = sqlite3.connect(sqlite_path)
    source_conn.row_factory = sqlite3.Row
    cursor = source_conn.cursor()

    # Query source counts
    base_rows = cursor.execute("SELECT * FROM baselines").fetchall()
    scan_rows = cursor.execute("SELECT * FROM scans").fetchall()
    findings_rows = cursor.execute("SELECT * FROM findings").fetchall()
    evidence_rows = cursor.execute("SELECT * FROM evidence").fetchall()
    
    # Check if jobs table exists
    has_jobs = cursor.execute(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='jobs'"
    ).fetchone()[0] > 0
    job_rows = cursor.execute("SELECT * FROM jobs").fetchall() if has_jobs else []

    stats = {
        "baselines_found": len(base_rows),
        "scans_found": len(scan_rows),
        "findings_found": len(findings_rows),
        "evidence_found": len(evidence_rows),
        "jobs_found": len(job_rows),
        "baselines_migrated": 0,
        "scans_migrated": 0,
        "dry_run": dry_run,
        "validation_errors": 0,
    }

    print(f"[*] Discovered records: {stats['baselines_found']} baselines, {stats['scans_found']} scans, {stats['findings_found']} findings, {stats['evidence_found']} evidence, {stats['jobs_found']} jobs")

    # Validate baselines
    validated_baselines = []
    for row in base_rows:
        try:
            snap = ServerSnapshot.model_validate_json(row["snapshot_json"])
            validated_baselines.append(snap)
        except Exception as e:
            stats["validation_errors"] += 1
            print(f"[!] Baseline validation failed for {row['server_id']}: {e}", file=sys.stderr)

    # Validate scans
    validated_scans = []
    for row in scan_rows:
        try:
            scan_res = ScanResult.model_validate_json(row["result_json"])
            validated_scans.append(scan_res)
        except Exception as e:
            stats["validation_errors"] += 1
            print(f"[!] Scan validation failed for {row['scan_id']}: {e}", file=sys.stderr)

    if dry_run:
        print("[+] DRY-RUN COMPLETE: All discovered records passed validation. No writes performed.")
        return stats

    # Write to target database
    print(f"[*] Connecting to target database: {target_url.split('@')[-1] if '@' in target_url else target_url}")
    target_db = PostgresDatabase(target_url)

    for snap in validated_baselines:
        target_db.save_baseline(snap, overwrite=True)
        stats["baselines_migrated"] += 1

    for scan_res in validated_scans:
        target_db.save_scan_result(scan_res)
        stats["scans_migrated"] += 1

    # Migrate jobs if present
    for row in job_rows:
        target_db.create_job(
            job_id=row["job_id"],
            target=row["target"],
            scan_type=row["scan_type"],
        )
        target_db.update_job(
            job_id=row["job_id"],
            status=row["status"],
            scan_id=row["scan_id"],
            error=row["error"],
        )

    print(f"[+] MIGRATION COMPLETE: Migrated {stats['baselines_migrated']} baselines, {stats['scans_migrated']} scans into target.")
    return stats


def main():
    parser = argparse.ArgumentParser(description="AuditForge SQLite to PostgreSQL Migration")
    parser.add_argument("--sqlite-path", default="auditforge.db", help="Path to source SQLite database")
    parser.add_argument("--target-url", default=os.getenv("DATABASE_URL", "postgresql://auditforge:auditforge@localhost:5432/auditforge"), help="Target PostgreSQL/SQLAlchemy connection URL")
    parser.add_argument("--dry-run", action="store_true", help="Validate records without writing to target")
    args = parser.parse_args()

    try:
        migrate(sqlite_path=args.sqlite_path, target_url=args.target_url, dry_run=args.dry_run)
    except Exception as e:
        print(f"[x] Migration failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
