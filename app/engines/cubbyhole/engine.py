from __future__ import annotations
"""
Cubbyhole Secrets Engine — NanoVault v2.0

Private per-token storage. Accessible only by the owning token/user.
Automatically cleaned up when token expires.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from fastapi import HTTPException
from app.engines.base import BaseSecretsEngine, engine_registry
from app.models.models import CubbyholeEntry, User
from app.core.encryption import encryption_service


def _now():
    return datetime.now(timezone.utc)


@engine_registry.register("cubbyhole")
class CubbyholeEngine(BaseSecretsEngine):
    engine_name = "cubbyhole"
    engine_version = "2.0"
    description = "Private per-token scratch space. Deleted when token expires."

    async def read(self, path: str, **kwargs) -> dict:
        raise NotImplementedError("Use read_entry()")

    async def write(self, path: str, data: dict, **kwargs) -> dict:
        raise NotImplementedError("Use write_entry()")

    async def delete(self, path: str, **kwargs) -> bool:
        raise NotImplementedError("Use delete_entry()")

    async def list(self, path: str, **kwargs) -> list[str]:
        raise NotImplementedError("Use list_entries()")

    @staticmethod
    async def write_entry(
        db: AsyncSession,
        user: User,
        key: str,
        value: str,
        vault_token_id: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> CubbyholeEntry:
        # Upsert
        existing = await db.execute(
            select(CubbyholeEntry).where(
                CubbyholeEntry.user_id == user.id,
                CubbyholeEntry.key == key,
            )
        )
        entry = existing.scalar_one_or_none()
        encrypted = encryption_service.encrypt(value)

        if entry:
            entry.encrypted_value = encrypted
            entry.expires_at = expires_at
        else:
            entry = CubbyholeEntry(
                user_id=user.id,
                vault_token_id=vault_token_id,
                key=key,
                encrypted_value=encrypted,
                expires_at=expires_at,
            )
            db.add(entry)
        await db.flush()
        return entry

    @staticmethod
    async def read_entry(db: AsyncSession, user: User, key: str) -> tuple[CubbyholeEntry, str]:
        result = await db.execute(
            select(CubbyholeEntry).where(
                CubbyholeEntry.user_id == user.id,
                CubbyholeEntry.key == key,
            )
        )
        entry = result.scalar_one_or_none()
        if not entry:
            raise HTTPException(status_code=404, detail="Cubbyhole entry not found")

        if entry.expires_at and entry.expires_at.replace(tzinfo=None) < _now().replace(tzinfo=None):
            await db.delete(entry)
            await db.flush()
            raise HTTPException(status_code=410, detail="Cubbyhole entry has expired")

        return entry, encryption_service.decrypt(entry.encrypted_value)

    @staticmethod
    async def list_entries(db: AsyncSession, user: User) -> list[str]:
        result = await db.execute(
            select(CubbyholeEntry.key).where(CubbyholeEntry.user_id == user.id)
        )
        return result.scalars().all()

    @staticmethod
    async def delete_entry(db: AsyncSession, user: User, key: str) -> None:
        result = await db.execute(
            select(CubbyholeEntry).where(
                CubbyholeEntry.user_id == user.id,
                CubbyholeEntry.key == key,
            )
        )
        entry = result.scalar_one_or_none()
        if not entry:
            raise HTTPException(status_code=404, detail="Cubbyhole entry not found")
        await db.delete(entry)
        await db.flush()

    @staticmethod
    async def cleanup_expired(db: AsyncSession) -> int:
        result = await db.execute(
            delete(CubbyholeEntry).where(
                CubbyholeEntry.expires_at < _now()
            )
        )
        await db.flush()
        return result.rowcount


cubbyhole_engine = CubbyholeEngine()
