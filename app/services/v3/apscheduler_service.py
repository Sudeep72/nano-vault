"""
Real APScheduler integration — NanoVault v3.0 Completion.
Replaces the manual-trigger-only scheduler stub with actual background jobs.
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone

logger = logging.getLogger("nano_vault.scheduler")

_scheduler = None


def _now(): return datetime.now(timezone.utc)


async def _job_lease_cleanup():
    from app.db.session import AsyncSessionLocal
    from app.services.v3.scheduler_service import scheduler_service, JobStatus
    import time
    t0 = time.monotonic()
    try:
        async with AsyncSessionLocal() as db:
            from app.services.v2.lease_service import lease_service
            count = await lease_service.expire_stale(db)
            await db.commit()
        scheduler_service.record_run("lease_cleanup", JobStatus.SUCCESS, (time.monotonic()-t0)*1000, {"expired": count})
        logger.info("Scheduled lease_cleanup: %d expired", count)
    except Exception as e:
        scheduler_service.record_run("lease_cleanup", JobStatus.FAILED, (time.monotonic()-t0)*1000, {"error": str(e)})
        logger.error("lease_cleanup failed: %s", e)


async def _job_secret_rotation():
    from app.db.session import AsyncSessionLocal
    from app.services.v3.scheduler_service import scheduler_service, JobStatus
    import time
    t0 = time.monotonic()
    try:
        async with AsyncSessionLocal() as db:
            from app.services.v2.rotation_service import rotation_service
            rotated = await rotation_service.run_scheduled_rotations(db)
            await db.commit()
        scheduler_service.record_run("secret_rotation", JobStatus.SUCCESS, (time.monotonic()-t0)*1000, {"rotated": len(rotated)})
    except Exception as e:
        scheduler_service.record_run("secret_rotation", JobStatus.FAILED, (time.monotonic()-t0)*1000, {"error": str(e)})
        logger.error("secret_rotation failed: %s", e)


async def _job_token_cleanup():
    from app.db.session import AsyncSessionLocal
    from app.services.v3.scheduler_service import scheduler_service, JobStatus
    from sqlalchemy import select, update
    from app.models.models import VaultToken, TokenStatus
    import time
    t0 = time.monotonic()
    try:
        async with AsyncSessionLocal() as db:
            expired = (await db.execute(
                select(VaultToken).where(VaultToken.status == TokenStatus.ACTIVE, VaultToken.expires_at < _now())
            )).scalars().all()
            for t in expired:
                t.status = TokenStatus.EXPIRED
            await db.commit()
        scheduler_service.record_run("token_cleanup", JobStatus.SUCCESS, (time.monotonic()-t0)*1000, {"expired": len(expired)})
    except Exception as e:
        scheduler_service.record_run("token_cleanup", JobStatus.FAILED, (time.monotonic()-t0)*1000, {"error": str(e)})


async def _job_engine_health():
    from app.db.session import AsyncSessionLocal
    from app.services.v3.scheduler_service import scheduler_service, JobStatus
    import time
    t0 = time.monotonic()
    try:
        async with AsyncSessionLocal() as db:
            from app.services.v2.engine_service import engine_service
            mounts = await engine_service.list_all(db)
        scheduler_service.record_run("engine_health_check", JobStatus.SUCCESS, (time.monotonic()-t0)*1000, {"engines_checked": len(mounts)})
    except Exception as e:
        scheduler_service.record_run("engine_health_check", JobStatus.FAILED, (time.monotonic()-t0)*1000, {"error": str(e)})


def start_scheduler():
    """Start APScheduler with real interval-based background jobs."""
    global _scheduler
    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
    except ImportError:
        logger.warning("APScheduler not installed — background jobs disabled")
        return None

    _scheduler = AsyncIOScheduler()
    _scheduler.add_job(_job_lease_cleanup, "interval", minutes=5, id="lease_cleanup")
    _scheduler.add_job(_job_secret_rotation, "interval", hours=1, id="secret_rotation")
    _scheduler.add_job(_job_token_cleanup, "interval", minutes=10, id="token_cleanup")
    _scheduler.add_job(_job_engine_health, "interval", minutes=15, id="engine_health_check")
    _scheduler.start()
    logger.info("APScheduler started with 4 background jobs")
    return _scheduler


def stop_scheduler():
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None


def get_scheduler_jobs() -> list[dict]:
    if not _scheduler:
        return []
    return [
        {"id": job.id, "next_run": str(job.next_run_time) if job.next_run_time else None,
         "trigger": str(job.trigger)}
        for job in _scheduler.get_jobs()
    ]
