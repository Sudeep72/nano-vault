"""Completion endpoints — Engine Marketplace, Storage, real Prometheus, Vault Agent, K8s, Benchmarks. NanoVault v3.0 Completion pass."""
from __future__ import annotations
import time
from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok

router = APIRouter(tags=["Platform Completion"])


# ── Engine Marketplace ─────────────────────────────────────────────────────────

@router.get("/marketplace/engines", summary="Engine Marketplace — discovery view with health/version/config")
async def marketplace_engines(db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.services.v2.engine_service import engine_service
    from app.engines.base import engine_registry
    mounts = await engine_service.list_all(db)
    result = []
    for m in mounts:
        engine_cls = engine_registry.get(m.engine_type)
        result.append({
            "name": m.name, "type": m.engine_type, "status": m.status.value,
            "version": engine_cls.engine_version if engine_cls else "not_installed",
            "mount_path": m.mount_path, "description": m.description,
            "health": "healthy" if engine_cls else "not_available",
            "installed": engine_cls is not None,
            "dependencies": [],
        })
    return ok(result, f"{len(result)} engines in marketplace")


@router.post("/marketplace/engines/{name}/upgrade", summary="Simulate engine upgrade [Admin]")
async def marketplace_upgrade(name: str, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    from app.services.v2.engine_service import engine_service
    mount = await engine_service.get(db, name)
    return ok({"name": name, "previous_status": mount.status.value, "upgraded": True,
               "note": "Simulated — engine binaries are bundled with the platform release"}, f"Engine '{name}' upgrade simulated")


# ── Storage Backend Framework ──────────────────────────────────────────────────

@router.get("/storage/backends", summary="List storage backends")
async def list_storage_backends(_=Depends(require_admin)):
    from app.storage.base import storage_manager
    return ok(storage_manager.list_backends(), "Storage backends")


@router.post("/storage/validate", summary="Validate active storage backend [Admin]")
async def validate_storage(_=Depends(require_admin)):
    from app.storage.base import storage_manager
    return ok(await storage_manager.validate_active(), "Storage validation complete")


@router.post("/storage/switch/{backend_name}", summary="Switch active storage backend [Admin]")
async def switch_storage(backend_name: str, _=Depends(require_admin)):
    from app.storage.base import storage_manager
    success = storage_manager.switch(backend_name)
    return ok({"switched": success, "active": backend_name if success else None},
              f"Switched to '{backend_name}'" if success else f"Backend '{backend_name}' not registered")


# ── Real Prometheus Metrics ────────────────────────────────────────────────────

@router.get("/metrics", summary="Prometheus metrics (official prometheus_client format)")
async def prometheus_metrics_v2(db: AsyncSession = Depends(get_db)):
    from app.services.v3.prometheus_service import sync_gauges_from_db, render_metrics
    await sync_gauges_from_db(db)
    data = render_metrics()
    return Response(content=data, media_type="text/plain; version=0.0.4")


# ── Scheduler (real APScheduler jobs) ─────────────────────────────────────────

@router.get("/scheduler/live-jobs", summary="List live APScheduler jobs (real background jobs) [Admin]")
async def live_scheduler_jobs(_=Depends(require_admin)):
    from app.services.v3.apscheduler_service import get_scheduler_jobs
    jobs = get_scheduler_jobs()
    return ok(jobs, f"{len(jobs)} live background jobs" if jobs else "Scheduler not running or APScheduler unavailable")


# ── Vault Agent Simulation ─────────────────────────────────────────────────────

_AGENT_CACHE: dict = {}

@router.post("/agent/render", summary="Vault Agent: render a secret template locally (simulated agent)")
async def agent_render(secret_id: str, template: str, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    from app.services.secret_service import secret_service
    import uuid as _uuid
    secret, decrypted = await secret_service.read(db, current_user, _uuid.UUID(secret_id))
    rendered = template.replace("{{value}}", decrypted).replace("{{key}}", secret.key)
    _AGENT_CACHE[secret_id] = {"value": decrypted, "cached_at": time.time()}
    return ok({"rendered": rendered, "cached": True}, "Template rendered (Vault Agent simulation)")


@router.get("/agent/cache/status", summary="Vault Agent: cache status")
async def agent_cache_status(_=Depends(get_current_user)):
    return ok({"cached_secrets": len(_AGENT_CACHE), "keys": list(_AGENT_CACHE.keys())}, "Agent cache status")


# ── Kubernetes status (reflects static manifests bundled with the release) ────

@router.get("/kubernetes/status", summary="Kubernetes integration status")
async def kubernetes_status(_=Depends(get_current_user)):
    return ok({
        "manifests_available": ["namespace", "secret", "postgres-statefulset", "deployment", "ingress", "csi-secretproviderclass"],
        "helm_chart_available": True,
        "csi_driver": "simulated",
        "workload_identity": "annotation-based (GCP/AWS IRSA pattern)",
        "vault_agent_injection": "annotation-based sidecar pattern",
        "note": "Manifests are static assets bundled at /k8s and /helm — apply with kubectl/helm directly.",
    }, "Kubernetes integration status")


# ── Benchmarks ─────────────────────────────────────────────────────────────────

@router.post("/benchmark/run", summary="Run a lightweight in-process benchmark [Admin]")
async def run_benchmark(db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    from app.core.encryption import encryption_service
    results = {}

    t0 = time.perf_counter()
    for _ in range(100):
        encryption_service.encrypt("benchmark-payload")
    results["encryption_100_ops_ms"] = round((time.perf_counter() - t0) * 1000, 2)

    from sqlalchemy import text
    t0 = time.perf_counter()
    for _ in range(20):
        await db.execute(text("SELECT 1"))
    results["db_roundtrip_20_ops_ms"] = round((time.perf_counter() - t0) * 1000, 2)

    return ok(results, "Benchmark complete")
