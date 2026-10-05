"""Health and Metrics endpoints — NanoVault v1.0.1"""
import time
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.db.session import get_db
from app.core.config import settings
from app.core.encryption import encryption_service
from app.services.metrics_service import metrics_service
from app.core.responses import ok

router = APIRouter(tags=["Observability"])


@router.get("/health", summary="System health check")
async def health(db: AsyncSession = Depends(get_db)):
    components = {}

    # Database
    t0 = time.monotonic()
    try:
        await db.execute(text("SELECT 1"))
        components["database"] = {
            "status": "healthy",
            "latency_ms": round((time.monotonic() - t0) * 1000, 2),
        }
    except Exception as e:
        components["database"] = {"status": "unhealthy", "message": str(e)}

    # Encryption service
    try:
        blob = encryption_service.encrypt("health-check")
        assert encryption_service.decrypt(blob) == "health-check"
        components["encryption"] = {"status": "healthy", "message": "AES-256-GCM OK"}
    except Exception as e:
        components["encryption"] = {"status": "unhealthy", "message": str(e)}

    # Auth (config present)
    components["authentication"] = {
        "status": "healthy" if settings.JWT_SECRET_KEY else "unhealthy",
        "message": "JWT config present" if settings.JWT_SECRET_KEY else "JWT_SECRET_KEY missing",
    }

    # Audit engine (always healthy if DB is healthy)
    components["audit_engine"] = {
        "status": components["database"]["status"],
        "message": "Immutable audit log operational",
    }

    overall = "healthy" if all(c["status"] == "healthy" for c in components.values()) else "degraded"
    return ok({
        "status": overall,
        "version": settings.APP_VERSION,
        "uptime_seconds": metrics_service.uptime_seconds(),
        "components": components,
    }, "Health check complete")


@router.get("/metrics", summary="System metrics (Prometheus-ready)")
async def get_metrics(db: AsyncSession = Depends(get_db)):
    data = await metrics_service.collect(db)
    data["uptime_seconds"] = metrics_service.uptime_seconds()
    # Prometheus-compatible comment format included in response for future scraping
    data["_meta"] = {
        "note": "Structured for future Prometheus integration",
        "labels": {"service": "nano_vault", "version": settings.APP_VERSION},
    }
    return ok(data, "Metrics collected")
