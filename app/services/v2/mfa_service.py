from __future__ import annotations
"""MFA Service — TOTP + Recovery Codes — NanoVault v2.0"""
import uuid
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional
import pyotp
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException
from app.models.models import MFAConfig, User
from app.core.encryption import encryption_service


def _now():
    return datetime.now(timezone.utc)


def _generate_recovery_codes(count: int = 8) -> list[str]:
    return [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(count)]


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().encode()).hexdigest()


class MFAService:

    @staticmethod
    async def setup(db: AsyncSession, user: User) -> dict:
        """Generate TOTP secret and recovery codes. Not yet active until verified."""
        if user.mfa_enabled:
            raise HTTPException(status_code=400, detail="MFA already enabled")

        totp_secret = pyotp.random_base32()
        recovery_codes = _generate_recovery_codes()
        recovery_hashes = [_hash_code(c) for c in recovery_codes]

        # Upsert MFA config
        existing = await db.execute(select(MFAConfig).where(MFAConfig.user_id == user.id))
        config = existing.scalar_one_or_none()

        encrypted_secret = encryption_service.encrypt(totp_secret)
        if config:
            config.totp_secret = encrypted_secret
            config.recovery_codes = recovery_hashes
        else:
            config = MFAConfig(
                user_id=user.id,
                totp_secret=encrypted_secret,
                recovery_codes=recovery_hashes,
            )
            db.add(config)
        await db.flush()

        totp = pyotp.TOTP(totp_secret)
        provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name="NanoVault")

        return {
            "totp_secret": totp_secret,
            "provisioning_uri": provisioning_uri,
            "recovery_codes": recovery_codes,
            "instructions": "Scan the QR code or enter the secret in your authenticator app, then verify with /mfa/verify",
        }

    @staticmethod
    async def verify_and_enable(db: AsyncSession, user: User, totp_code: str) -> bool:
        """Verify a TOTP code and enable MFA if valid."""
        config = await MFAService._get_config(db, user)
        secret = encryption_service.decrypt(config.totp_secret)
        totp = pyotp.TOTP(secret)

        if not totp.verify(totp_code, valid_window=1):
            raise HTTPException(status_code=400, detail="Invalid TOTP code")

        user.mfa_enabled = True
        config.last_used_at = _now()
        await db.flush()
        return True

    @staticmethod
    async def verify_code(db: AsyncSession, user: User, totp_code: str) -> bool:
        """Verify a TOTP code during login."""
        if not user.mfa_enabled:
            return True  # MFA not required

        config = await MFAService._get_config(db, user)
        secret = encryption_service.decrypt(config.totp_secret)
        totp = pyotp.TOTP(secret)

        if not totp.verify(totp_code, valid_window=1):
            raise HTTPException(status_code=400, detail="Invalid MFA code")

        config.last_used_at = _now()
        await db.flush()
        return True

    @staticmethod
    async def use_recovery_code(db: AsyncSession, user: User, code: str) -> bool:
        """Use a recovery code (one-time use)."""
        config = await MFAService._get_config(db, user)
        code_hash = _hash_code(code)

        if code_hash not in config.recovery_codes:
            raise HTTPException(status_code=400, detail="Invalid recovery code")

        # Remove used code
        config.recovery_codes = [c for c in config.recovery_codes if c != code_hash]
        await db.flush()
        return True

    @staticmethod
    async def disable(db: AsyncSession, user: User, totp_code: str) -> None:
        await MFAService.verify_code(db, user, totp_code)
        config = await MFAService._get_config(db, user)
        await db.delete(config)
        user.mfa_enabled = False
        await db.flush()

    @staticmethod
    async def _get_config(db: AsyncSession, user: User) -> MFAConfig:
        result = await db.execute(select(MFAConfig).where(MFAConfig.user_id == user.id))
        config = result.scalar_one_or_none()
        if not config:
            raise HTTPException(status_code=404, detail="MFA not configured")
        return config


mfa_service = MFAService()
