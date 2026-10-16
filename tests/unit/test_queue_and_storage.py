"""Unit tests for AuditForge Scalable Queue, SQLAlchemy Storage, and Job Endpoints.

Verifies:
- PostgresDatabase / SQLAlchemy engine using in-memory SQLite URI
- Complete job lifecycle tracking (QUEUED -> RUNNING -> SUCCEEDED / FAILED / CANCELLED)
- ScanQueueManager and ScanWorker execution
- Migration validation and dry-run
- FastAPI Job endpoints
"""

import os
import time
import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

from auditforge.api.app import app
from auditforge.core.contracts import (
    Finding,
    EvidenceRecord,
    ScanResult,
    ServerSnapshot,
    Severity,
    TrustState,
)
from auditforge.storage.pg_database import PostgresDatabase
from auditforge.storage.migrate import migrate
from auditforge.queue.manager import ScanQueueManager
from auditforge.queue.worker import ScanWorker


@pytest.fixture
def test_client():
    return TestClient(app)


@pytest.fixture
def memory_pg_db():
    return PostgresDatabase("sqlite:///:memory:")


class TestSQLAlchemyStorage:
    def test_save_and_get_baseline(self, memory_pg_db):
        snapshot = ServerSnapshot(
            server_id="test_server",
            catalog_fingerprint="abc123def456",
            tools={},
        )
        saved = memory_pg_db.save_baseline(snapshot)
        assert saved is True

        retrieved = memory_pg_db.get_baseline("test_server")
        assert retrieved is not None
        assert retrieved.server_id == "test_server"
        assert retrieved.catalog_fingerprint == "abc123def456"

        # Overwrite=False preserves existing
        dup_snapshot = ServerSnapshot(
            server_id="test_server",
            catalog_fingerprint="new_fingerprint",
            tools={},
        )
        saved_again = memory_pg_db.save_baseline(dup_snapshot, overwrite=False)
        assert saved_again is False

        # Overwrite=True updates
        saved_overwrite = memory_pg_db.save_baseline(dup_snapshot, overwrite=True)
        assert saved_overwrite is True
        updated = memory_pg_db.get_baseline("test_server")
        assert updated.catalog_fingerprint == "new_fingerprint"

    def test_save_and_get_scan_result(self, memory_pg_db):
        scan = ScanResult(
            scan_id="scan-sql-001",
            target="fixtures/clean_reader",
            started_at="2026-10-16T12:00:00Z",
            completed_at="2026-10-16T12:00:02Z",
            trust_state=TrustState.VERIFIED,
            summary="Clean audit result",
            findings=[],
            evidence=[],
        )
        memory_pg_db.save_scan_result(scan)

        fetched = memory_pg_db.get_scan_result("scan-sql-001")
        assert fetched is not None
        assert fetched.scan_id == "scan-sql-001"
        assert fetched.trust_state == TrustState.VERIFIED

        scans_list = memory_pg_db.list_scans()
        assert len(scans_list) >= 1
        assert scans_list[0]["id"] == "scan-sql-001"

    def test_job_persistence_lifecycle(self, memory_pg_db):
        job = memory_pg_db.create_job("job-test-1", target="fixtures/clean_reader")
        assert job["job_id"] == "job-test-1"
        assert job["status"] == "QUEUED"

        running = memory_pg_db.update_job("job-test-1", status="RUNNING")
        assert running["status"] == "RUNNING"
        assert running["started_at"] is not None

        succeeded = memory_pg_db.update_job("job-test-1", status="SUCCEEDED", scan_id="scan-123")
        assert succeeded["status"] == "SUCCEEDED"
        assert succeeded["completed_at"] is not None
        assert succeeded["scan_id"] == "scan-123"

        # Cancel test
        job2 = memory_pg_db.create_job("job-test-2", target="fixtures/rogue_server")
        assert memory_pg_db.cancel_job("job-test-2") is True
        cancelled = memory_pg_db.get_job("job-test-2")
        assert cancelled["status"] == "CANCELLED"


class TestScanQueueAndWorker:
    def test_queue_enqueue_and_metrics(self):
        qm = ScanQueueManager(redis_url="redis://nonexistent:9999/0")
        assert qm.mode == "IN_MEMORY"
        metrics = qm.get_queue_metrics()
        assert metrics["queue_mode"] == "IN_MEMORY"

        job = qm.enqueue_scan(target="fixtures/clean_reader")
        assert job["job_id"].startswith("job-")
        assert job["status"] == "QUEUED"

    def test_worker_process_job_mocked(self, monkeypatch):
        db = PostgresDatabase("sqlite:///:memory:")
        worker = ScanWorker(db=db)

        job_meta = db.create_job("job-worker-test", target="fixtures/clean_reader")
        assert job_meta["status"] == "QUEUED"

        # Mock orchestrator run_scan
        mock_scan = ScanResult(
            scan_id="scan-mock-999",
            target="fixtures/clean_reader",
            started_at="2026-10-16T12:00:00Z",
            completed_at="2026-10-16T12:00:01Z",
            trust_state=TrustState.VERIFIED,
            summary="Mock clean audit",
            findings=[],
            evidence=[],
        )

        class MockOrchestrator:
            def __init__(self, db=None):
                pass
            def run_scan(self, target, scan_type="LIVE_SCAN"):
                return mock_scan

        monkeypatch.setattr("auditforge.queue.worker.ScanOrchestrator", MockOrchestrator)

        worker.process_job({"job_id": "job-worker-test", "target": "fixtures/clean_reader"})

        updated = db.get_job("job-worker-test")
        assert updated["status"] == "SUCCEEDED"
        assert updated["scan_id"] == "scan-mock-999"


class TestMigrationUtility:
    def test_migration_dry_run(self):
        # Dry-run on auditforge.db
        res = migrate("auditforge.db", "sqlite:///:memory:", dry_run=True)
        assert res["dry_run"] is True
        assert res["validation_errors"] == 0
        assert res["scans_found"] >= 0

    def test_migration_execution(self, tmp_path):
        target_db_path = tmp_path / "target_migrated.db"
        target_url = f"sqlite:///{target_db_path}"
        res = migrate("auditforge.db", target_url, dry_run=False)
        assert res["dry_run"] is False
        assert res["validation_errors"] == 0
        assert res["scans_migrated"] == res["scans_found"]


class TestJobEndpoints:
    def test_submit_async_scan(self, test_client):
        resp = test_client.post(
            "/api/jobs/scans",
            json={"target": "fixtures/clean_reader", "scan_type": "LIVE_SCAN", "use_llm": False},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert "job_id" in data
        assert data["job_id"].startswith("job-")
        assert data["target"] == "fixtures/clean_reader"

    def test_list_and_get_job(self, test_client):
        # Submit
        resp = test_client.post(
            "/api/jobs/scans",
            json={"target": "fixtures/clean_reader"},
        )
        job_id = resp.json()["job_id"]

        # List
        list_resp = test_client.get("/api/jobs")
        assert list_resp.status_code == 200
        data = list_resp.json()
        assert "jobs" in data
        assert "metrics" in data
        assert any(j["job_id"] == job_id for j in data["jobs"])

        # Get
        get_resp = test_client.get(f"/api/jobs/{job_id}")
        assert get_resp.status_code == 200
        job_detail = get_resp.json()
        assert job_detail["job"]["job_id"] == job_id

    def test_cancel_job(self, test_client):
        # Submit
        resp = test_client.post(
            "/api/jobs/scans",
            json={"target": "fixtures/long_scan"},
        )
        job_id = resp.json()["job_id"]

        # Cancel
        cancel_resp = test_client.post(f"/api/jobs/{job_id}/cancel")
        # Should be 200 or 400 if worker already completed it
        assert cancel_resp.status_code in (200, 400)
