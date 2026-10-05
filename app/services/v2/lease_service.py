from __future__ import annotations
"""Lease Management Engine — NanoVault v2.0"""
import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from fastapi import HTTPException
from app.models.models import Lease, LeaseStatus


def _now():
    return datetime.now(timezone.utc)


class LeaseService:

    @staticmethod
    async def get(db: AsyncSession, lease_id: str, owner_id: uuid.UUID) -> Lease:
        result = await db.execute(
            select(Lease).where(Lease.lease_id == lease_id, Lease.owner_id == owner_id)
        )
        lease = result.scalar_one_or_none()
        if not lease:
            raise HTTPException(status_code=404, detail="Lease not found")
        return lease

    @staticmethod
    async def lookup(db: AsyncSession, lease_id: str, owner_id: uuid.UUID) -> dict:
        lease = await LeaseService.get(db, lease_id, owner_id)
        now = _now()
        is_expired = lease.expires_at.replace(tzinfo=None) < now.replace(tzinfo=None)
        return {
            "lease_id": lease.lease_id,
            "status": lease.status.value,
            "ttl_seconds": lease.ttl_seconds,
            "issued_at": lease.issued_at.isoformat(),
            "expires_at": lease.expires_at.isoformat(),
            "renewable": lease.renewal_count < lease.max_renewals and not is_expired,
            "renewal_count": lease.renewal_count,
            "max_renewals": lease.max_renewals,
            "time_remaining_seconds": max(0, int((lease.expires_at.replace(tzinfo=None) - now.replace(tzinfo=None)).total_seconds())),
        }

    @staticmethod
    async def renew(
        db: AsyncSession,
        lease_id: str,
        owner_id: uuid.UUID,
        increment_seconds: int = 3600,
    ) -> Lease:
        lease = await LeaseService.get(db, lease_id, owner_id)
        now = _now()

        if lease.status == LeaseStatus.REVOKED:
            raise HTTPException(status_code=400, detail="Lease has been revoked")
        if lease.expires_at.replace(tzinfo=None) < now.replace(tzinfo=None):
            raise HTTPException(status_code=400, detail="Lease has expired")
        if lease.renewal_count >= lease.max_renewals:
            raise HTTPException(status_code=400, detail=f"Max renewals ({lease.max_renewals}) reached")

        lease.expires_at = now + timedelta(seconds=increment_seconds)
        lease.renewed_at = now
        lease.renewal_count += 1
        lease.status = LeaseStatus.RENEWED
        await db.flush()
        return lease

    @staticmethod
    async def revoke(db: AsyncSession, lease_id: str, owner_id: uuid.UUID) -> None:
        lease = await LeaseService.get(db, lease_id, owner_id)
        lease.status = LeaseStatus.REVOKED
        lease.revoked_at = _now()
        # Also revoke the credential
        if lease.credential_id:
            from app.models.models import DynamicCredential
            cred = (await db.execute(
                select(DynamicCredential).where(DynamicCredential.id == lease.credential_id)
            )).scalar_one_or_none()
            if cred:
                cred.revoked = True
                cred.revoked_at = _now()
        await db.flush()

    @staticmethod
    async def list_active(db: AsyncSession, owner_id: uuid.UUID) -> list[Lease]:
        result = await db.execute(
            select(Lease).where(
                Lease.owner_id == owner_id,
                Lease.status == LeaseStatus.ACTIVE,
                Lease.expires_at > _now().replace(tzinfo=None),
            ).order_by(Lease.expires_at.asc())
        )
        return result.scalars().all()

    @staticmethod
    async def expire_stale(db: AsyncSession) -> int:
        """Background task: mark expired leases."""
        result = await db.execute(
            select(Lease).where(
                Lease.status.in_([LeaseStatus.ACTIVE, LeaseStatus.RENEWED]),
                Lease.expires_at < _now(),
            )
        )
        leases = result.scalars().all()
        for lease in leases:
            lease.status = LeaseStatus.EXPIRED
        await db.flush()
        return len(leases)


lease_service = LeaseService()
