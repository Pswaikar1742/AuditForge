"""AuditForge Asynchronous Scan Queue Manager.

Provides distributed job queueing backed by Redis for multi-worker production
deployments, with automatic fallback to an in-process worker thread for standalone
offline developer environments.
"""

import json
import logging
import os
import queue
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from auditforge.storage.pg_database import get_storage

logger = logging.getLogger("auditforge.queue")

QUEUE_KEY = "auditforge:jobs:queue"


class ScanQueueManager:
    """Manages asynchronous scan execution jobs."""

    def __init__(self, redis_url: Optional[str] = None, db: Optional[Any] = None):
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.db = db or get_storage()
        self.redis_client = None
        self.mode = "IN_MEMORY"
        self._in_memory_queue: queue.Queue = queue.Queue()
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self._init_backend()

    def _init_backend(self) -> None:
        """Attempt to connect to Redis; fall back to local queue if unavailable."""
        try:
            import redis
            client = redis.Redis.from_url(
                self.redis_url,
                socket_connect_timeout=1.0,
                socket_timeout=2.0,
                decode_responses=True,
            )
            client.ping()
            self.redis_client = client
            self.mode = "REDIS"
            logger.info("ScanQueueManager initialized in REDIS mode (%s)", self.redis_url)
        except Exception as e:
            self.mode = "IN_MEMORY"
            logger.info("Redis unavailable (%s); ScanQueueManager initialized in IN_MEMORY mode", e)
            self._start_in_memory_worker()

    def _start_in_memory_worker(self) -> None:
        """Start local background worker thread for standalone execution."""
        if self._worker_thread and self._worker_thread.is_alive():
            return
        from auditforge.queue.worker import ScanWorker
        self._worker = ScanWorker(queue_manager=self, db=self.db)
        self._worker_thread = threading.Thread(
            target=self._in_memory_worker_loop,
            daemon=True,
            name="AuditForge-LocalScanWorker",
        )
        self._worker_thread.start()

    def _in_memory_worker_loop(self) -> None:
        """Worker loop processing in-memory jobs."""
        while not self._stop_event.is_set():
            try:
                job_data = self._in_memory_queue.get(timeout=1.0)
                if job_data:
                    self._worker.process_job(job_data)
                    self._in_memory_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error("Error in local scan worker: %s", e)

    def enqueue_scan(
        self,
        target: str,
        scan_type: str = "LIVE_SCAN",
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Submit a target for asynchronous scanning."""
        job_id = f"job-{uuid.uuid4().hex[:12]}"
        job_meta = self.db.create_job(job_id=job_id, target=target, scan_type=scan_type)

        job_payload = {
            "job_id": job_id,
            "target": target,
            "scan_type": scan_type,
            "options": options or {},
        }

        if self.mode == "REDIS" and self.redis_client:
            try:
                self.redis_client.rpush(QUEUE_KEY, json.dumps(job_payload))
                logger.info("Enqueued job %s to Redis queue", job_id)
            except Exception as e:
                logger.warning("Failed to enqueue to Redis, falling back to local queue: %s", e)
                self._in_memory_queue.put(job_payload)
        else:
            self._in_memory_queue.put(job_payload)
            logger.info("Enqueued job %s to in-memory queue", job_id)

        return job_meta

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve job status and result from storage."""
        return self.db.get_job(job_id)

    def list_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List recent jobs."""
        return self.db.list_jobs(limit=limit)

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a queued or running job."""
        return self.db.cancel_job(job_id)

    def get_queue_metrics(self) -> Dict[str, Any]:
        """Return operational metrics of the job queue."""
        queued_count = 0
        if self.mode == "REDIS" and self.redis_client:
            try:
                queued_count = self.redis_client.llen(QUEUE_KEY)
            except Exception:
                queued_count = 0
        else:
            queued_count = self._in_memory_queue.qsize()

        return {
            "queue_mode": self.mode,
            "queued_jobs": queued_count,
            "redis_connected": self.mode == "REDIS",
        }


_GLOBAL_QUEUE_MANAGER: Optional[ScanQueueManager] = None


def get_queue_manager(db: Optional[Any] = None) -> ScanQueueManager:
    """Singleton getter for the scan queue manager."""
    global _GLOBAL_QUEUE_MANAGER
    if _GLOBAL_QUEUE_MANAGER is None:
        _GLOBAL_QUEUE_MANAGER = ScanQueueManager(db=db)
    elif db is not None:
        _GLOBAL_QUEUE_MANAGER.db = db
    return _GLOBAL_QUEUE_MANAGER
