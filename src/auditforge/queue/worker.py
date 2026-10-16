"""AuditForge Background Scan Worker.

Consumes scan tasks from Redis or local job queue, runs the complete AuditForge
pipeline (MCP discovery -> AST -> NLP heuristics -> Docker prober -> Trust Gap -> Evidence Sealing),
and commits verified evidence capsules and job outcomes to persistent storage.
"""

import json
import logging
import os
import sys
import time
from typing import Any, Dict, Optional

from auditforge.orchestrator import ScanOrchestrator
from auditforge.storage.pg_database import get_storage

logger = logging.getLogger("auditforge.worker")


class ScanWorker:
    """Worker processing background scan execution tasks."""

    def __init__(self, queue_manager: Optional[Any] = None, db: Optional[Any] = None):
        self.db = db or get_storage()
        self.queue_manager = queue_manager

    def process_job(self, job_payload: Dict[str, Any]) -> None:
        """Execute a single scan job and persist outcomes."""
        job_id = job_payload["job_id"]
        target = job_payload["target"]
        scan_type = job_payload.get("scan_type", "LIVE_SCAN")
        options = job_payload.get("options", {})

        # Check for pre-execution cancellation
        existing = self.db.get_job(job_id)
        if existing and existing.get("status") == "CANCELLED":
            logger.info("Skipping cancelled job %s", job_id)
            return

        # Mark RUNNING
        self.db.update_job(job_id, status="RUNNING")
        logger.info("Started processing job %s for target: %s", job_id, target)

        try:
            orch = ScanOrchestrator(db=self.db)
            use_llm = options.get("use_llm", False)
            if hasattr(orch, "use_llm"):
                orch.use_llm = use_llm

            scan_result = orch.run_scan(target=target, scan_type=scan_type)
            self.db.save_scan(scan_result)

            self.db.update_job(
                job_id=job_id,
                status="SUCCEEDED",
                scan_id=scan_result.scan_id,
            )
            logger.info(
                "Successfully completed job %s (scan_id: %s, verdict: %s)",
                job_id,
                scan_result.scan_id,
                scan_result.trust_state.value,
            )
        except Exception as e:
            logger.exception("Job %s execution failed: %s", job_id, e)
            self.db.update_job(
                job_id=job_id,
                status="FAILED",
                error=str(e),
            )

    def run_forever(self, poll_interval: float = 1.0) -> None:
        """Main loop for standalone distributed worker process."""
        import redis
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        queue_key = "auditforge:jobs:queue"

        logger.info("AuditForge worker starting up. Listening on Redis queue %s...", queue_key)
        try:
            r = redis.Redis.from_url(redis_url, decode_responses=True)
            r.ping()
        except Exception as e:
            logger.error("Could not connect to Redis at %s: %s", redis_url, e)
            sys.exit(1)

        while True:
            try:
                # BLPOP blocks until a job is available (timeout 2s)
                item = r.blpop(queue_key, timeout=2)
                if item:
                    _, payload_str = item
                    job_payload = json.loads(payload_str)
                    self.process_job(job_payload)
            except KeyboardInterrupt:
                logger.info("Worker shutting down gracefully...")
                break
            except Exception as e:
                logger.error("Unexpected worker loop exception: %s", e)
                time.sleep(poll_interval)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = ScanWorker()
    worker.run_forever()
