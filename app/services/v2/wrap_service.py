from __future__ import annotations
"""Response Wrapping Service — NanoVault v2.0"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException
from app.models.models import WrappedToken, User
from app.core.encryption import encryption_service


def _now():
    return datetime.now(timezone.utc)


def _make_wrap_token() -> str:
    return f"wrp.{secrets.token_urlsafe(32)}"


def _hash_token(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


class WrapService:

    @staticmethod
    async def wrap(
        db: AsyncSession,
        payload: dict,
        ttl_seconds: int = 300,
        created_by: Optional[User] = None,
    ) -> tuple[str, datetime]:
        """Wrap a payload in a one-time token."""
        if ttl_seconds < 10:
            raise HTTPException(status_code=400, detail="Wrap TTL must be at least 10 seconds")
        if ttl_seconds > 3600:
            raise HTTPException(status_code=400, detail="Wrap TTL cannot exceed 1 hour")

        raw_token = _make_wrap_token()
        encrypted = encryption_service.encrypt(json.dumps(payload))
        expires = _now() + timedelta(seconds=ttl_seconds)

        wrapped = WrappedToken(
            wrap_token=raw_token,
            wrap_token_hash=_hash_token(raw_token),
            encrypted_payload=encrypted,
            created_by=created_by.id if created_by else None,
            ttl_seconds=ttl_seconds,
            expires_at=expires,
        )
        db.add(wrapped)
        await db.flush()
        return raw_token, expires

    @staticmethod
    async def unwrap(db: AsyncSession, raw_token: str) -> dict:
        """One-time unwrap. Token is destroyed after use."""
        result = await db.execute(
            select(WrappedToken).where(
                WrappedToken.wrap_token_hash == _hash_token(raw_token)
            )
        )
        wrapped = result.scalar_one_or_none()

        if not wrapped:
            raise HTTPException(status_code=404, detail="Wrapped token not found or already used")
        if wrapped.used:
            raise HTTPException(status_code=410, detail="Wrapped token already used")
        if wrapped.expires_at.replace(tzinfo=None) < _now().replace(tzinfo=None):
            raise HTTPException(status_code=410, detail="Wrapped token has expired")

        # Mark as used immediately
        wrapped.used = True
        wrapped.used_at = _now()
        await db.flush()

        return json.loads(encryption_service.decrypt(wrapped.encrypted_payload))

    @staticmethod
    async def lookup(db: AsyncSession, raw_token: str) -> dict:
        """Check wrap token status without unwrapping."""
        result = await db.execute(
            select(WrappedToken).where(
                WrappedToken.wrap_token_hash == _hash_token(raw_token)
            )
        )
        wrapped = result.scalar_one_or_none()
        if not wrapped:
            raise HTTPException(status_code=404, detail="Wrapped token not found")

        now = _now()
        return {
            "used": wrapped.used,
            "expires_at": wrapped.expires_at.isoformat(),
            "expired": wrapped.expires_at.replace(tzinfo=None) < now.replace(tzinfo=None),
            "ttl_seconds": wrapped.ttl_seconds,
            "time_remaining_seconds": max(0, int((wrapped.expires_at.replace(tzinfo=None) - now.replace(tzinfo=None)).total_seconds())),
        }


wrap_service = WrapService()
