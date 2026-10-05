from __future__ import annotations
"""Vault Token Engine — NanoVault v2.0"""
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException
from app.models.models import VaultToken, TokenType, TokenStatus, User


def _now():
    return datetime.now(timezone.utc)


def _make_token_id() -> str:
    return f"nvt.{secrets.token_urlsafe(32)}"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class TokenService:

    @staticmethod
    async def create(
        db: AsyncSession,
        user: User,
        token_type: TokenType = TokenType.SERVICE,
        ttl_seconds: int = 3600,
        policies: Optional[list[str]] = None,
        parent_token_id: Optional[str] = None,
        max_renewals: int = 10,
        metadata: Optional[dict] = None,
    ) -> tuple[VaultToken, str]:
        raw_token = _make_token_id()
        now = _now()

        vault_token = VaultToken(
            token_id=raw_token,
            token_hash=_hash_token(raw_token),
            user_id=user.id,
            parent_token_id=parent_token_id,
            token_type=token_type,
            policies=policies or [],
            ttl_seconds=ttl_seconds,
            expires_at=now + timedelta(seconds=ttl_seconds),
            max_renewals=max_renewals,
            metadata=metadata or {},
        )
        db.add(vault_token)
        await db.flush()
        return vault_token, raw_token

    @staticmethod
    async def lookup(db: AsyncSession, raw_token: str, owner: User) -> dict:
        result = await db.execute(
            select(VaultToken).where(
                VaultToken.token_hash == _hash_token(raw_token),
                VaultToken.user_id == owner.id,
            )
        )
        token = result.scalar_one_or_none()
        if not token:
            raise HTTPException(status_code=404, detail="Token not found")

        now = _now()
        return {
            "token_id": token.token_id,
            "type": token.token_type.value,
            "status": token.status.value,
            "policies": token.policies,
            "ttl_seconds": token.ttl_seconds,
            "issued_at": token.issued_at.isoformat(),
            "expires_at": token.expires_at.isoformat(),
            "renewable": token.renewal_count < token.max_renewals and token.expires_at.replace(tzinfo=None) > now.replace(tzinfo=None),
            "renewal_count": token.renewal_count,
            "time_remaining_seconds": max(0, int((token.expires_at.replace(tzinfo=None) - now.replace(tzinfo=None)).total_seconds())),
            "parent_token_id": token.parent_token_id,
            "metadata": token.extra_data,
        }

    @staticmethod
    async def renew(
        db: AsyncSession,
        raw_token: str,
        owner: User,
        increment_seconds: Optional[int] = None,
    ) -> VaultToken:
        result = await db.execute(
            select(VaultToken).where(
                VaultToken.token_hash == _hash_token(raw_token),
                VaultToken.user_id == owner.id,
            )
        )
        token = result.scalar_one_or_none()
        if not token:
            raise HTTPException(status_code=404, detail="Token not found")

        now = _now()
        if token.status == TokenStatus.REVOKED:
            raise HTTPException(status_code=400, detail="Token has been revoked")
        if token.expires_at.replace(tzinfo=None) < now.replace(tzinfo=None):
            raise HTTPException(status_code=400, detail="Token has expired")
        if token.renewal_count >= token.max_renewals:
            raise HTTPException(status_code=400, detail="Max renewals reached")

        inc = increment_seconds or token.ttl_seconds
        token.expires_at = now + timedelta(seconds=inc)
        token.last_renewed_at = now
        token.renewal_count += 1
        await db.flush()
        return token

    @staticmethod
    async def revoke(db: AsyncSession, raw_token: str, owner: User) -> None:
        result = await db.execute(
            select(VaultToken).where(
                VaultToken.token_hash == _hash_token(raw_token),
                VaultToken.user_id == owner.id,
            )
        )
        token = result.scalar_one_or_none()
        if not token:
            raise HTTPException(status_code=404, detail="Token not found")
        token.status = TokenStatus.REVOKED
        token.revoked_at = _now()
        await db.flush()

    @staticmethod
    async def list_active(db: AsyncSession, owner: User) -> list[VaultToken]:
        result = await db.execute(
            select(VaultToken).where(
                VaultToken.user_id == owner.id,
                VaultToken.status == TokenStatus.ACTIVE,
                VaultToken.expires_at > _now(),
            ).order_by(VaultToken.issued_at.desc())
        )
        return result.scalars().all()


token_service = TokenService()
