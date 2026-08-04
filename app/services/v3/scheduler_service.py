"""Scheduler Framework — NanoVault v3.0 Part 2. Background job tracking for rotation, cleanup, renewal."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Optional

_JOB_HISTORY: list[dict] = []  # in-memory job history (survives process lifetime)


class JobStatus(str, PyEnum):
    SUCCESS = "success"
    FAILED = "failed"
    RUNNING = "running"


def _now(): return datetime.now(timezone.utc)


class SchedulerService:
    """Lightweight scheduler job tracker. Real cron/APScheduler jobs call record_run()."""

    JOB_TYPES = [
        "secret_rotation", "lease_cleanup", "token_cleanup",
        "certificate_renewal", "key_rotation", "backup",
        "engine_health_check", "namespace_cleanup",
    ]

    @staticmethod
    def record_run(job_type: str, status: JobStatus, duration_ms: float, detail: Optional[dict] = None) -> dict:
        entry = {
            "id": str(uuid.uuid4()),
            "job_type": job_type,
            "status": status.value,
            "duration_ms": duration_ms,
            "detail": detail or {},
            "run_at": _now().isoformat(),
        }
        _JOB_HISTORY.append(entry)
        if len(_JOB_HISTORY) > 500:
            _JOB_HISTORY.pop(0)
        return entry

    @staticmethod
    async def run_lease_cleanup(db) -> dict:
        import time
        t0 = time.monotonic()
        from app.services.v2.lease_service import lease_service
        count = await lease_service.expire_stale(db)
        return SchedulerService.record_run("lease_cleanup", JobStatus.SUCCESS, (time.monotonic()-t0)*1000, {"expired_count": count})

    @staticmethod
    async def run_scheduled_rotations(db) -> dict:
        import time
        t0 = time.monotonic()
        from app.services.v2.rotation_service import rotation_service
        rotated = await rotation_service.run_scheduled_rotations(db)
        return SchedulerService.record_run("secret_rotation", JobStatus.SUCCESS, (time.monotonic()-t0)*1000, {"rotated_count": len(rotated)})

    @staticmethod
    def list_history(job_type: Optional[str] = None, limit: int = 50) -> list[dict]:
        items = _JOB_HISTORY
        if job_type:
            items = [j for j in items if j["job_type"] == job_type]
        return list(reversed(items))[:limit]

    @staticmethod
    def get_stats() -> dict:
        by_type: dict[str, dict] = {}
        for j in _JOB_HISTORY:
            t = j["job_type"]
            by_type.setdefault(t, {"total": 0, "success": 0, "failed": 0})
            by_type[t]["total"] += 1
            by_type[t]["success" if j["status"] == "success" else "failed"] += 1
        return {
            "job_types": SchedulerService.JOB_TYPES,
            "total_runs": len(_JOB_HISTORY),
            "by_type": by_type,
        }


scheduler_service = SchedulerService()
