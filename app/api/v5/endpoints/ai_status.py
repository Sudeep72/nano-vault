"""AI Status + Health — NanoVault v5.0 (Step 8/14/16)"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok

router = APIRouter(prefix="/ai", tags=["AI Security Platform"])


@router.get("/status", summary="AI subsystem status — enabled, provider, model, configured")
async def ai_status(_=Depends(get_current_user)):
    from app.services.v5.ai_provider_service import validate_ai_config
    return ok(validate_ai_config(), "AI status")


@router.get("/health", summary="AI provider reachability check [Admin]")
async def ai_health(_=Depends(require_admin)):
    from app.services.v5.ai_provider_service import get_provider
    provider = get_provider()
    if provider is None:
        return ok({"available": False, "message": "AI is disabled (AI_ENABLED=false)"}, "AI health")
    return ok(await provider.health_check(), "AI health")


@router.get("/metrics", summary="AI-specific metrics summary (also in /api/v3/metrics)")
async def ai_metrics_summary(db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    from app.services.v5.ai_metrics_service import ai_metrics_service
    await ai_metrics_service.sync_gauges(db)
    return ok({"note": "Full Prometheus-format metrics at /api/v3/metrics (nanovault_ai_* series)"}, "AI metrics")
