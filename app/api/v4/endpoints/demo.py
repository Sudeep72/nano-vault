"""Enterprise Demo Mode — NanoVault v4.0"""
from __future__ import annotations
import uuid
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.core.dependencies import require_admin
from app.core.responses import ok, created

router = APIRouter(prefix="/demo", tags=["Enterprise Demo Mode"])


@router.post("/load", summary="Load realistic enterprise demo dataset [Admin]")
async def load_demo(db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    from app.services.v4.demo_mode_service import demo_mode_service
    return created(await demo_mode_service.load(db, admin.id), "Demo dataset loaded")


@router.get("/history", summary="Demo dataset load history [Admin]")
async def demo_history(db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    from app.services.v4.demo_mode_service import demo_mode_service
    return ok(await demo_mode_service.get_load_history(db), "Demo load history")


@router.post("/reset/{dataset_id}", summary="Report what a reset would remove (non-destructive) [Admin]")
async def reset_demo(dataset_id: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    from app.services.v4.demo_mode_service import demo_mode_service
    return ok(await demo_mode_service.reset(db, dataset_id), "Reset report")
