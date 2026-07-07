"""Enterprise Dashboard endpoint — NanoVault v2.0"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.core.dependencies import require_admin
from app.core.responses import ok
from app.services.v2.dashboard_service import dashboard_service

router = APIRouter(tags=["Enterprise Dashboard"])


@router.get("/dashboard", summary="Enterprise dashboard — full system overview [Admin]")
async def get_dashboard(
    db: AsyncSession = Depends(get_db),
    _=Depends(require_admin),
):
    data = await dashboard_service.get_dashboard(db)
    return ok(data, "Dashboard data retrieved")
