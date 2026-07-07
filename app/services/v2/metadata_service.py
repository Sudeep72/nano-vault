"""
Secret Metadata Service — NanoVault v2.0 Enterprise Hardening

Returns rich metadata about a secret without exposing the encrypted value.
"""
from __future__ import annotations
import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from fastapi import HTTPException
from app.models.models import (
    Secret, SecretVersion, RotationHistory, Lease,
    User, Organization, Project, Team, team_member_table, Namespace,
)


class MetadataService:

    @staticmethod
    async def get_secret_metadata(
        db: AsyncSession,
        secret: Secret,
        owner: User,
    ) -> dict:
        """Full metadata for a secret. Value is never included."""

        # Version count
        version_count = (await db.execute(
            select(func.count()).select_from(SecretVersion)
            .where(SecretVersion.secret_id == secret.id)
        )).scalar_one()

        # Rotation summary
        rotations = (await db.execute(
            select(RotationHistory)
            .where(RotationHistory.secret_id == secret.id)
            .order_by(RotationHistory.created_at.desc())
            .limit(3)
        )).scalars().all()

        # Active leases (if any) — dynamic secrets only
        active_leases = (await db.execute(
            select(func.count()).select_from(Lease)
            .where(Lease.owner_id == secret.owner_id)
        )).scalar_one()

        # Namespace info
        ns_info = None
        if secret.namespace_id:
            ns = (await db.execute(
                select(Namespace).where(Namespace.id == secret.namespace_id)
            )).scalar_one_or_none()
            if ns:
                ns_info = {"id": str(ns.id), "name": ns.name, "path": ns.path}

        # Org/project/team membership
        org_info = project_info = team_info = None
        if owner.org_id:
            org = (await db.execute(
                select(Organization).where(Organization.id == owner.org_id)
            )).scalar_one_or_none()
            if org:
                org_info = {"id": str(org.id), "name": org.name}

        # Teams the owner belongs to
        teams_result = await db.execute(
            select(Team)
            .join(team_member_table, Team.id == team_member_table.c.team_id)
            .where(team_member_table.c.user_id == owner.id)
        )
        teams = teams_result.scalars().all()
        team_info = [{"id": str(t.id), "name": t.name} for t in teams] if teams else []

        return {
            "id": str(secret.id),
            "key": secret.key,
            "owner": {
                "id": str(owner.id),
                "username": owner.username,
                "email": owner.email,
            },
            "namespace": ns_info,
            "organization": org_info,
            "teams": team_info,
            "current_version": secret.version,
            "version_count": version_count,
            "created_at": secret.created_at.isoformat(),
            "updated_at": secret.updated_at.isoformat(),
            "last_accessed_at": secret.last_accessed_at.isoformat() if secret.last_accessed_at else None,
            "access_count": secret.access_count,
            "rotation": {
                "enabled": secret.rotation_enabled,
                "interval_days": secret.rotation_interval_days,
                "last_rotated_at": secret.last_rotated_at.isoformat() if secret.last_rotated_at else None,
                "next_rotation_at": secret.next_rotation_at.isoformat() if secret.next_rotation_at else None,
                "total_rotations": len(rotations),
                "recent_rotations": [
                    {
                        "old_version": r.old_version,
                        "new_version": r.new_version,
                        "type": r.rotation_type,
                        "status": r.status.value,
                        "at": r.created_at.isoformat(),
                    }
                    for r in rotations
                ],
            },
            "lifecycle": {
                "status": secret.status.value,
                "is_deleted": secret.is_deleted,
                "deleted_at": secret.deleted_at.isoformat() if secret.deleted_at else None,
                "expires_at": secret.expires_at.isoformat() if secret.expires_at else None,
                "scheduled_delete_at": secret.scheduled_delete_at.isoformat() if secret.scheduled_delete_at else None,
            },
            "encryption": {
                "algorithm": secret.encryption_algorithm,
                "key_version": secret.key_version,
            },
            "tags": secret.tags or [],
            "category": secret.category,
            "description": secret.description,
        }

    @staticmethod
    async def list_metadata(
        db: AsyncSession,
        owner: User,
        namespace_id: Optional[uuid.UUID] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[dict], int]:
        from app.models.models import SecretStatus
        query = select(Secret).where(
            Secret.owner_id == owner.id,
            Secret.is_deleted == False,  # noqa
        )
        if namespace_id:
            query = query.where(Secret.namespace_id == namespace_id)

        total = (await db.execute(
            select(func.count()).select_from(query.subquery())
        )).scalar_one()

        query = query.order_by(Secret.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        secrets = (await db.execute(query)).scalars().all()

        items = []
        for s in secrets:
            items.append({
                "id": str(s.id),
                "key": s.key,
                "category": s.category,
                "tags": s.tags or [],
                "version": s.version,
                "status": s.status.value,
                "encryption_algorithm": s.encryption_algorithm,
                "key_version": s.key_version,
                "rotation_enabled": s.rotation_enabled,
                "namespace_id": str(s.namespace_id) if s.namespace_id else None,
                "created_at": s.created_at.isoformat(),
                "updated_at": s.updated_at.isoformat(),
            })
        return items, total


metadata_service = MetadataService()
