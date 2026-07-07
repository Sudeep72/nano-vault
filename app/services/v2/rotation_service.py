from __future__ import annotations
"""Secret Rotation Engine — NanoVault v2.0"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException
from app.models.models import Secret, RotationHistory, RotationStatus, SecretStatus, User
from app.core.encryption import encryption_service
from app.engines.kv.engine import KVSecretsEngine


def _now():
    return datetime.now(timezone.utc)


class RotationService:

    @staticmethod
    async def manual_rotate(
        db: AsyncSession,
        owner: User,
        secret: Secret,
        new_value: str,
        change_note: Optional[str] = None,
    ) -> tuple[Secret, RotationHistory]:
        old_version = secret.version
        new_encrypted = encryption_service.encrypt(new_value)

        secret.encrypted_value = new_encrypted
        secret.version += 1
        secret.last_rotated_at = _now()
        if secret.rotation_interval_days:
            secret.next_rotation_at = _now() + timedelta(days=secret.rotation_interval_days)

        await KVSecretsEngine.record_version(
            db, secret, new_encrypted,
            created_by=owner.id,
            change_note=change_note or "Manual rotation",
        )

        history = RotationHistory(
            secret_id=secret.id,
            old_version=old_version,
            new_version=secret.version,
            rotation_type="manual",
            status=RotationStatus.SUCCESS,
            initiated_by=owner.id,
        )
        db.add(history)
        await db.flush()
        return secret, history

    @staticmethod
    async def enable_auto_rotation(
        db: AsyncSession,
        secret: Secret,
        interval_days: int,
    ) -> Secret:
        if interval_days < 1:
            raise HTTPException(status_code=400, detail="Rotation interval must be at least 1 day")
        secret.rotation_enabled = True
        secret.rotation_interval_days = interval_days
        secret.next_rotation_at = _now() + timedelta(days=interval_days)
        await db.flush()
        return secret

    @staticmethod
    async def disable_auto_rotation(db: AsyncSession, secret: Secret) -> Secret:
        secret.rotation_enabled = False
        secret.rotation_interval_days = None
        secret.next_rotation_at = None
        await db.flush()
        return secret

    @staticmethod
    async def get_rotation_history(
        db: AsyncSession,
        secret: Secret,
    ) -> list[RotationHistory]:
        result = await db.execute(
            select(RotationHistory)
            .where(RotationHistory.secret_id == secret.id)
            .order_by(RotationHistory.created_at.desc())
        )
        return result.scalars().all()

    @staticmethod
    async def run_scheduled_rotations(db: AsyncSession) -> list[str]:
        """Background task: rotate secrets past their next_rotation_at."""
        result = await db.execute(
            select(Secret).where(
                Secret.rotation_enabled == True,  # noqa
                Secret.next_rotation_at <= _now(),
                Secret.is_deleted == False,  # noqa
                Secret.status == SecretStatus.ACTIVE,
            )
        )
        secrets = result.scalars().all()
        rotated = []
        for secret in secrets:
            try:
                current_val = encryption_service.decrypt(secret.encrypted_value)
                # Re-encrypt with fresh nonce (value unchanged, nonce rotated)
                new_encrypted = encryption_service.encrypt(current_val)
                old_version = secret.version
                secret.encrypted_value = new_encrypted
                secret.version += 1
                secret.last_rotated_at = _now()
                secret.next_rotation_at = _now() + timedelta(days=secret.rotation_interval_days)

                await KVSecretsEngine.record_version(
                    db, secret, new_encrypted,
                    change_note="Scheduled auto-rotation",
                )
                history = RotationHistory(
                    secret_id=secret.id,
                    old_version=old_version,
                    new_version=secret.version,
                    rotation_type="scheduled",
                    status=RotationStatus.SUCCESS,
                )
                db.add(history)
                rotated.append(str(secret.id))
            except Exception as e:
                history = RotationHistory(
                    secret_id=secret.id,
                    old_version=secret.version,
                    new_version=secret.version,
                    rotation_type="scheduled",
                    status=RotationStatus.FAILED,
                    error_message=str(e),
                )
                db.add(history)

        await db.flush()
        return rotated


rotation_service = RotationService()
