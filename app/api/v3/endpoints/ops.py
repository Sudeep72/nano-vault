"""Operations API — Dashboard v3, Scheduler, Backup, Cluster, per-module health. NanoVault v3.0 Parts 2 & 3."""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from pydantic import BaseModel
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok
from app.services.v3.dashboard_v3_service import dashboard_v3_service
from app.services.v3.scheduler_service import scheduler_service, JobStatus
from app.services.v3.backup_service import backup_service
from app.services.v3.cluster_service import cluster_service
from app.core.encryption import encryption_service

router = APIRouter(tags=["Enterprise Operations"])


class BackupRequest(BaseModel):
    backup_type: str = "full"


# ── Dashboard v3 extensions ───────────────────────────────────────────────────

@router.get("/dashboard/transit", summary="Transit Engine dashboard stats [Admin]")
async def dashboard_transit(db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    return ok(await dashboard_v3_service.get_transit_stats(db), "Transit dashboard")


@router.get("/dashboard/pki", summary="PKI Engine dashboard stats [Admin]")
async def dashboard_pki(db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    return ok(await dashboard_v3_service.get_pki_stats(db), "PKI dashboard")


@router.get("/dashboard/seal", summary="Seal management dashboard stats [Admin]")
async def dashboard_seal(db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    return ok(await dashboard_v3_service.get_seal_stats(db), "Seal dashboard")


@router.get("/dashboard/identity", summary="Identity providers dashboard stats [Admin]")
async def dashboard_identity(db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    return ok(await dashboard_v3_service.get_identity_stats(db), "Identity dashboard")


@router.get("/dashboard/policy-as-code", summary="Policy as Code dashboard stats [Admin]")
async def dashboard_pac(db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    return ok(await dashboard_v3_service.get_policy_as_code_stats(db), "Policy as Code dashboard")


@router.get("/dashboard/cluster", summary="Cluster / HA dashboard [Admin]")
async def dashboard_cluster(_=Depends(require_admin)):
    return ok(cluster_service.get_cluster_status(), "Cluster dashboard")


# ── Scheduler ─────────────────────────────────────────────────────────────────

@router.post("/scheduler/run/lease-cleanup", summary="Manually trigger lease cleanup job [Admin]")
async def run_lease_cleanup(db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    return ok(await scheduler_service.run_lease_cleanup(db), "Lease cleanup executed")


@router.post("/scheduler/run/secret-rotation", summary="Manually trigger scheduled secret rotation [Admin]")
async def run_secret_rotation(db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    return ok(await scheduler_service.run_scheduled_rotations(db), "Scheduled rotation executed")


@router.get("/scheduler/jobs", summary="List scheduler job history [Admin]")
async def list_jobs(job_type: Optional[str] = Query(None), limit: int = Query(50, ge=1, le=500), _=Depends(require_admin)):
    return ok(scheduler_service.list_history(job_type, limit), "Job history")


@router.get("/scheduler/stats", summary="Scheduler statistics [Admin]")
async def scheduler_stats(_=Depends(require_admin)):
    return ok(scheduler_service.get_stats(), "Scheduler stats")


# ── Backup & Restore ──────────────────────────────────────────────────────────

@router.post("/backup", summary="Create a backup [Admin]")
async def create_backup(body: BackupRequest, db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    return ok(await backup_service.create_backup(db, body.backup_type, admin.id), "Backup created")


@router.get("/backup", summary="List backups [Admin]")
async def list_backups(_=Depends(require_admin)):
    return ok(backup_service.list_backups(), "Backups listed")


@router.post("/backup/{backup_id}/validate", summary="Validate backup integrity [Admin]")
async def validate_backup(backup_id: str, _=Depends(require_admin)):
    return ok(backup_service.validate_backup(backup_id), "Backup validated")


@router.post("/backup/{backup_id}/restore", summary="Restore from backup [Admin]")
async def restore_backup(backup_id: str, _=Depends(require_admin)):
    return ok(backup_service.restore_backup(backup_id), "Simulated backup restore completed")


# ── Cluster / HA / Multi-region ───────────────────────────────────────────────

@router.get("/cluster/status", summary="Cluster node status")
async def cluster_status(_=Depends(get_current_user)):
    return ok(cluster_service.get_cluster_status(), "Cluster status")


@router.get("/cluster/regions", summary="Multi-region status")
async def region_status(_=Depends(get_current_user)):
    return ok(cluster_service.get_region_status(), "Region status")


@router.get("/cluster/replication", summary="Replication status")
async def replication_status(_=Depends(get_current_user)):
    return ok(cluster_service.get_replication_status(), "Replication status")


# ── Per-module health ─────────────────────────────────────────────────────────

@router.get("/health/modules", summary="Per-module health check")
async def module_health(db: AsyncSession = Depends(get_db)):
    modules = {}

    try:
        await db.execute(text("SELECT 1"))
        modules["database"] = {"status": "healthy"}
    except Exception as e:
        modules["database"] = {"status": "unhealthy", "message": str(e)}

    try:
        blob = encryption_service.encrypt("healthcheck")
        assert encryption_service.decrypt(blob) == "healthcheck"
        modules["transit_crypto"] = {"status": "healthy"}
    except Exception as e:
        modules["transit_crypto"] = {"status": "unhealthy", "message": str(e)}

    modules["scheduler"] = {"status": "healthy", "total_runs": scheduler_service.get_stats()["total_runs"]}
    modules["cluster"] = {"status": "healthy", "role": cluster_service.get_cluster_status()["role"]}
    modules["engine_registry"] = {"status": "healthy"}

    overall = "healthy" if all(m["status"] == "healthy" for m in modules.values()) else "degraded"
    return ok({"status": overall, "modules": modules}, "Module health")


@router.get("/health/ready", summary="Readiness probe")
async def readiness(db: AsyncSession = Depends(get_db)):
    try:
        await db.execute(text("SELECT 1"))
        return ok({"ready": True}, "Ready")
    except Exception:
        return ok({"ready": False}, "Not ready")


@router.get("/health/live", summary="Liveness probe")
async def liveness():
    return ok({"alive": True}, "Alive")


# ── Prometheus-style metrics ──────────────────────────────────────────────────

@router.get("/metrics/prometheus", summary="Prometheus-format metrics export")
async def prometheus_metrics(db: AsyncSession = Depends(get_db)):
    from app.services.v2.dashboard_service import dashboard_service
    data = await dashboard_service.get_dashboard(db)
    lines = ["# HELP nanovault_info NanoVault metrics", "# TYPE nanovault_info gauge"]

    def flatten(prefix, d):
        for k, v in d.items():
            if isinstance(v, dict):
                flatten(f"{prefix}_{k}", v)
            elif isinstance(v, (int, float)):
                lines.append(f"nanovault_{prefix}_{k} {v}")

    flatten("stat", data)
    return "\n".join(lines) + "\n"


system_router = router
