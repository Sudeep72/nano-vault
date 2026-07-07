from __future__ import annotations
"""
KV Secrets Engine v2 — versioned, expirable, rotatable.
Extends v1 with full version history, rollback, expiration.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from fastapi import HTTPException
from app.engines.base import BaseSecretsEngine, engine_registry
from app.models.models import Secret, SecretVersion, User, SecretStatus
from app.core.encryption import encryption_service


def _now():
    return datetime.now(timezone.utc)


@engine_registry.register("kv")
class KVSecretsEngine(BaseSecretsEngine):
    engine_name = "kv"
    engine_version = "2.0"
    description = "Key-Value secrets engine with full version history and rotation"

    async def read(self, path: str, **kwargs) -> dict:
        raise NotImplementedError("Use KVSecretsEngine.read_secret()")

    async def write(self, path: str, data: dict, **kwargs) -> dict:
        raise NotImplementedError("Use KVSecretsEngine.create_secret()")

    async def delete(self, path: str, **kwargs) -> bool:
        raise NotImplementedError("Use KVSecretsEngine.delete_secret()")

    async def list(self, path: str, **kwargs) -> list[str]:
        raise NotImplementedError("Use KVSecretsEngine.list_secrets()")

    # ── Version history ───────────────────────────────────────────────────────

    @staticmethod
    async def record_version(
        db: AsyncSession,
        secret: Secret,
        encrypted_value: str,
        created_by: Optional[uuid.UUID] = None,
        change_note: Optional[str] = None,
    ) -> SecretVersion:
        """Record a new version in the immutable history."""
        # Mark all previous versions as not current
        prev = await db.execute(
            select(SecretVersion).where(
                SecretVersion.secret_id == secret.id,
                SecretVersion.is_current == True,  # noqa
            )
        )
        for v in prev.scalars().all():
            v.is_current = False

        version = SecretVersion(
            secret_id=secret.id,
            version_number=secret.version,
            encrypted_value=encrypted_value,
            created_by=created_by,
            change_note=change_note,
            is_current=True,
        )
        db.add(version)
        await db.flush()
        return version

    @staticmethod
    async def get_version_history(
        db: AsyncSession,
        secret: Secret,
    ) -> list[SecretVersion]:
        result = await db.execute(
            select(SecretVersion)
            .where(SecretVersion.secret_id == secret.id)
            .order_by(SecretVersion.version_number.desc())
        )
        return result.scalars().all()

    @staticmethod
    async def get_version(
        db: AsyncSession,
        secret: Secret,
        version_number: int,
    ) -> SecretVersion:
        result = await db.execute(
            select(SecretVersion).where(
                SecretVersion.secret_id == secret.id,
                SecretVersion.version_number == version_number,
            )
        )
        v = result.scalar_one_or_none()
        if not v:
            raise HTTPException(status_code=404, detail=f"Version {version_number} not found")
        return v

    @staticmethod
    async def rollback_to_version(
        db: AsyncSession,
        secret: Secret,
        version_number: int,
        rolled_back_by: Optional[uuid.UUID] = None,
    ) -> tuple[Secret, str]:
        """Roll back secret to a previous version. Creates a new version entry."""
        target = await KVSecretsEngine.get_version(db, secret, version_number)
        decrypted = encryption_service.decrypt(target.encrypted_value)

        # Re-encrypt with fresh nonce for rollback
        new_encrypted = encryption_service.encrypt(decrypted)
        secret.encrypted_value = new_encrypted
        secret.version += 1
        secret.updated_at = _now()

        await KVSecretsEngine.record_version(
            db, secret, new_encrypted,
            created_by=rolled_back_by,
            change_note=f"Rollback to version {version_number}",
        )
        await db.flush()
        return secret, decrypted

    @staticmethod
    async def compare_versions(
        db: AsyncSession,
        secret: Secret,
        version_a: int,
        version_b: int,
    ) -> dict:
        va = await KVSecretsEngine.get_version(db, secret, version_a)
        vb = await KVSecretsEngine.get_version(db, secret, version_b)
        val_a = encryption_service.decrypt(va.encrypted_value)
        val_b = encryption_service.decrypt(vb.encrypted_value)
        return {
            "secret_key": secret.key,
            "version_a": {"number": version_a, "created_at": va.created_at.isoformat(), "value_changed": val_a != val_b},
            "version_b": {"number": version_b, "created_at": vb.created_at.isoformat(), "value_changed": val_a != val_b},
            "values_differ": val_a != val_b,
            "change_note_a": va.change_note,
            "change_note_b": vb.change_note,
        }


kv_engine = KVSecretsEngine()
