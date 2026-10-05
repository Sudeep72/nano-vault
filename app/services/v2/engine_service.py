"""
Engine Registry Service — NanoVault v2.0 Enterprise Hardening

Manages engine mounts: enable, disable, mount, unmount, reload.
The registry persists to the database so engine state survives restarts.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException
from app.models.models import EngineMount, EngineStatus
from app.engines.base import engine_registry

_DEFAULT_MOUNTS = [
    {"name": "kv",         "engine_type": "kv",         "mount_path": "secret/",   "description": "KV Secrets Engine v2 — versioned key-value storage"},
    {"name": "dynamic",    "engine_type": "dynamic",    "mount_path": "dynamic/",  "description": "Dynamic Secrets Engine — on-demand credential generation"},
    {"name": "cubbyhole",  "engine_type": "cubbyhole",  "mount_path": "cubbyhole/","description": "Cubbyhole Engine — private per-token scratch space"},
    # Reserved for future engines
    {"name": "transit",    "engine_type": "transit",    "mount_path": "transit/",  "description": "Transit Engine — encryption-as-a-service"},
    {"name": "pki",        "engine_type": "pki",        "mount_path": "pki/",      "description": "PKI Engine — certificate authority, issuance, revocation, CRL"},
    {"name": "ssh",        "engine_type": "ssh",        "mount_path": "ssh/",      "description": "SSH Engine — dynamic SSH credentials (reserved, v3)",       "status": EngineStatus.DISABLED},
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


class EngineService:

    @staticmethod
    async def seed_defaults(db: AsyncSession) -> None:
        """Seed default engine mounts at startup if not already present."""
        for mount_def in _DEFAULT_MOUNTS:
            exists = (await db.execute(
                select(EngineMount).where(EngineMount.name == mount_def["name"])
            )).scalar_one_or_none()
            if not exists:
                status = mount_def.get("status", EngineStatus.ENABLED)
                db.add(EngineMount(
                    name=mount_def["name"],
                    engine_type=mount_def["engine_type"],
                    mount_path=mount_def["mount_path"],
                    description=mount_def.get("description"),
                    status=status,
                    mounted_at=_now() if status == EngineStatus.ENABLED else None,
                ))
        await db.flush()

    @staticmethod
    async def list_all(db: AsyncSession) -> list[EngineMount]:
        result = await db.execute(select(EngineMount).order_by(EngineMount.name))
        return result.scalars().all()

    @staticmethod
    async def get(db: AsyncSession, name: str) -> EngineMount:
        mount = (await db.execute(
            select(EngineMount).where(EngineMount.name == name)
        )).scalar_one_or_none()
        if not mount:
            raise HTTPException(status_code=404, detail=f"Engine '{name}' not found")
        return mount

    @staticmethod
    async def enable(db: AsyncSession, name: str) -> EngineMount:
        mount = await EngineService.get(db, name)
        mount.status = EngineStatus.ENABLED
        mount.disabled_at = None
        mount.updated_at = _now()
        await db.flush()
        return mount

    @staticmethod
    async def disable(db: AsyncSession, name: str) -> EngineMount:
        mount = await EngineService.get(db, name)
        if name in ("kv", "cubbyhole"):
            raise HTTPException(status_code=400, detail=f"Engine '{name}' cannot be disabled")
        mount.status = EngineStatus.DISABLED
        mount.disabled_at = _now()
        mount.updated_at = _now()
        await db.flush()
        return mount

    @staticmethod
    async def mount(db: AsyncSession, name: str, mount_path: Optional[str] = None) -> EngineMount:
        mount = await EngineService.get(db, name)
        if mount_path:
            mount.mount_path = mount_path
        mount.status = EngineStatus.MOUNTED
        mount.mounted_at = _now()
        mount.updated_at = _now()
        await db.flush()
        return mount

    @staticmethod
    async def unmount(db: AsyncSession, name: str) -> EngineMount:
        mount = await EngineService.get(db, name)
        if name in ("kv", "cubbyhole"):
            raise HTTPException(status_code=400, detail=f"Engine '{name}' cannot be unmounted")
        mount.status = EngineStatus.DISABLED
        mount.mounted_at = None
        mount.updated_at = _now()
        await db.flush()
        return mount

    @staticmethod
    async def reload(db: AsyncSession, name: str) -> EngineMount:
        mount = await EngineService.get(db, name)
        if mount.status == EngineStatus.DISABLED:
            raise HTTPException(status_code=400, detail=f"Engine '{name}' is disabled — enable it first")
        mount.updated_at = _now()
        await db.flush()
        return mount

    @staticmethod
    async def ensure_enabled(db: AsyncSession, name: str) -> EngineMount:
        mount = await EngineService.get(db, name)

        if mount.status == EngineStatus.DISABLED:
            raise HTTPException(
                status_code=400,
                detail=f"Engine '{name}' is disabled — enable it first",
            )

        return mount

    @staticmethod
    def _runtime_info(mount: EngineMount) -> dict:
        """Enrich a mount with runtime engine registry info."""
        engine_cls = engine_registry.get(mount.engine_type)
        available = engine_cls is not None
        return {
            "id": str(mount.id),
            "name": mount.name,
            "engine_type": mount.engine_type,
            "mount_path": mount.mount_path,
            "description": mount.description,
            "status": mount.status.value,
            "available_in_runtime": available,
            "engine_version": engine_cls.engine_version if engine_cls else None,
            "created_at": mount.created_at.isoformat(),
            "mounted_at": mount.mounted_at.isoformat() if mount.mounted_at else None,
            "disabled_at": mount.disabled_at.isoformat() if mount.disabled_at else None,
        }


engine_service = EngineService()
