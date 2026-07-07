"""Engine Management API — NanoVault v2.0 Enterprise Hardening"""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok
from app.services.v2.engine_service import engine_service

router = APIRouter(prefix="/engines", tags=["Secrets Engine Management"])


class MountRequest(BaseModel):
    mount_path: Optional[str] = None


@router.get("", summary="List all registered secrets engines")
async def list_engines(
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    mounts = await engine_service.list_all(db)
    return ok(
        [engine_service._runtime_info(m) for m in mounts],
        f"{len(mounts)} engines registered",
    )


@router.get("/{name}", summary="Get engine details")
async def get_engine(
    name: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    mount = await engine_service.get(db, name)
    return ok(engine_service._runtime_info(mount), "Engine details")


@router.post("/{name}/enable", summary="Enable a secrets engine [Admin]")
async def enable_engine(
    name: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_admin),
):
    mount = await engine_service.enable(db, name)
    return ok(engine_service._runtime_info(mount), f"Engine '{name}' enabled")


@router.post("/{name}/disable", summary="Disable a secrets engine [Admin]")
async def disable_engine(
    name: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_admin),
):
    mount = await engine_service.disable(db, name)
    return ok(engine_service._runtime_info(mount), f"Engine '{name}' disabled")


@router.post("/{name}/mount", summary="Mount a secrets engine [Admin]")
async def mount_engine(
    name: str,
    body: MountRequest,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_admin),
):
    mount = await engine_service.mount(db, name, body.mount_path)
    return ok(engine_service._runtime_info(mount), f"Engine '{name}' mounted at {mount.mount_path}")


@router.post("/{name}/unmount", summary="Unmount a secrets engine [Admin]")
async def unmount_engine(
    name: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_admin),
):
    mount = await engine_service.unmount(db, name)
    return ok(engine_service._runtime_info(mount), f"Engine '{name}' unmounted")


@router.post("/{name}/reload", summary="Reload a secrets engine [Admin]")
async def reload_engine(
    name: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_admin),
):
    mount = await engine_service.reload(db, name)
    return ok(engine_service._runtime_info(mount), f"Engine '{name}' reloaded")
