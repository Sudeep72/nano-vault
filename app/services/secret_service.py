"""KV Secrets Engine v1.0.1 — AES-256-GCM + policy checks + soft-delete + search."""
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, asc, desc
from fastapi import HTTPException, status
from app.models.models import Secret, User, SecretStatus, UserRole
from app.core.encryption import encryption_service
from app.schemas.schemas import SecretSearchRequest


def _now() -> datetime:
    return datetime.now(timezone.utc)


class SecretService:

    @staticmethod
    async def create(
        db: AsyncSession, owner: User, key: str, value: str,
        description: Optional[str] = None, category: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> Secret:
        existing = await db.execute(
            select(Secret).where(
                Secret.owner_id == owner.id,
                Secret.key == key,
                Secret.is_deleted == False,  # noqa
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail=f"Secret with key '{key}' already exists")

        secret = Secret(
            owner_id=owner.id,
            key=key,
            encrypted_value=encryption_service.encrypt(value),
            description=description,
            category=category,
            tags=tags or [],
            encryption_algorithm="AES-256-GCM",
            key_version=1,
        )
        db.add(secret)
        await db.flush()
        # Record initial version in immutable history
        from app.engines.kv.engine import KVSecretsEngine
        await KVSecretsEngine.record_version(db, secret, secret.encrypted_value, created_by=owner.id, change_note="Initial version")
        return secret

    @staticmethod
    async def _get_active(db: AsyncSession, owner: User, secret_id: uuid.UUID) -> Secret:
        result = await db.execute(
            select(Secret).where(
                Secret.id == secret_id,
                Secret.owner_id == owner.id,
                Secret.is_deleted == False,  # noqa
            )
        )
        secret = result.scalar_one_or_none()
        if not secret:
            raise HTTPException(status_code=404, detail="Secret not found")
        return secret

    @staticmethod
    async def read(db: AsyncSession, owner: User, secret_id: uuid.UUID) -> tuple[Secret, str]:
        secret = await SecretService._get_active(db, owner, secret_id)
        decrypted = encryption_service.decrypt(secret.encrypted_value)
        # Update access tracking
        secret.last_accessed_at = _now()
        secret.access_count += 1
        await db.flush()
        return secret, decrypted

    @staticmethod
    async def search(
        db: AsyncSession,
        owner: User,
        req: SecretSearchRequest,
        admin_view: bool = False,
    ) -> tuple[list[Secret], int]:
        query = select(Secret)

        # Admin can see all; regular users see only their own
        if admin_view and owner.role == UserRole.ADMIN:
            if req.owner_id:
                query = query.where(Secret.owner_id == req.owner_id)
        else:
            query = query.where(Secret.owner_id == owner.id)

        # Status filter (default: active only)
        if req.status:
            query = query.where(Secret.status == req.status)
            if req.status == SecretStatus.DELETED:
                query = query.where(Secret.is_deleted == True)  # noqa
            else:
                query = query.where(Secret.is_deleted == False)  # noqa
        else:
            query = query.where(Secret.is_deleted == False)  # noqa

        if req.query:
            query = query.where(Secret.key.ilike(f"%{req.query}%"))
        if req.category:
            query = query.where(Secret.category == req.category)
        if req.tag:
            # cast to string for SQLite compatibility; PostgreSQL handles JSON natively
            from sqlalchemy import cast, String
            query = query.where(cast(Secret.tags, String).ilike(f'%"{req.tag}"%'))
        if req.created_after:
            query = query.where(Secret.created_at >= req.created_after)
        if req.created_before:
            query = query.where(Secret.created_at <= req.created_before)
        if req.updated_after:
            query = query.where(Secret.updated_at >= req.updated_after)
        if req.updated_before:
            query = query.where(Secret.updated_at <= req.updated_before)

        # Count before pagination
        count_q = select(func.count()).select_from(query.subquery())
        total = (await db.execute(count_q)).scalar_one()

        # Sort
        sort_col = getattr(Secret, req.sort_by, Secret.created_at)
        order_fn = asc if req.sort_order == "asc" else desc
        query = query.order_by(order_fn(sort_col))
        query = query.offset((req.page - 1) * req.page_size).limit(req.page_size)

        result = await db.execute(query)
        return result.scalars().all(), total

    @staticmethod
    async def update(
        db: AsyncSession, owner: User, secret_id: uuid.UUID,
        value: Optional[str] = None, description: Optional[str] = None,
        category: Optional[str] = None, tags: Optional[list[str]] = None,
    ) -> Secret:
        secret = await SecretService._get_active(db, owner, secret_id)
        if value is not None:
            new_enc = encryption_service.encrypt(value)
            secret.encrypted_value = new_enc
            secret.version += 1
            from app.engines.kv.engine import KVSecretsEngine
            await KVSecretsEngine.record_version(db, secret, new_enc, change_note="Updated")
        if description is not None:
            secret.description = description
        if category is not None:
            secret.category = category
        if tags is not None:
            secret.tags = tags
        await db.flush()
        return secret

    @staticmethod
    async def delete(db: AsyncSession, owner: User, secret_id: uuid.UUID) -> None:
        """Soft delete — sets is_deleted, deleted_at, status=DELETED."""
        secret = await SecretService._get_active(db, owner, secret_id)
        secret.is_deleted = True
        secret.deleted_at = _now()
        secret.status = SecretStatus.DELETED
        await db.flush()

    @staticmethod
    async def restore(db: AsyncSession, owner: User, secret_id: uuid.UUID) -> Secret:
        """Restore a soft-deleted secret."""
        result = await db.execute(
            select(Secret).where(
                Secret.id == secret_id,
                Secret.owner_id == owner.id,
                Secret.is_deleted == True,  # noqa
            )
        )
        secret = result.scalar_one_or_none()
        if not secret:
            raise HTTPException(status_code=404, detail="Deleted secret not found")

        # Check key collision with an active secret
        conflict = await db.execute(
            select(Secret).where(
                Secret.owner_id == owner.id,
                Secret.key == secret.key,
                Secret.is_deleted == False,  # noqa
                Secret.id != secret_id,
            )
        )
        if conflict.scalar_one_or_none():
            raise HTTPException(
                status_code=409,
                detail=f"Cannot restore: active secret with key '{secret.key}' already exists",
            )

        secret.is_deleted = False
        secret.deleted_at = None
        secret.status = SecretStatus.ACTIVE
        await db.flush()
        return secret

    @staticmethod
    async def purge(db: AsyncSession, secret_id: uuid.UUID) -> None:
        """Permanent deletion — admin only."""
        result = await db.execute(select(Secret).where(Secret.id == secret_id))
        secret = result.scalar_one_or_none()
        if not secret:
            raise HTTPException(status_code=404, detail="Secret not found")
        await db.delete(secret)
        await db.flush()

    @staticmethod
    async def admin_search(
        db: AsyncSession,
        req: SecretSearchRequest,
    ) -> tuple[list[Secret], int]:
        """Admin: search across all users."""
        query = select(Secret)
        if req.owner_id:
            query = query.where(Secret.owner_id == req.owner_id)
        if req.status:
            query = query.where(Secret.status == req.status)
        else:
            query = query.where(Secret.is_deleted == False)  # noqa
        if req.query:
            query = query.where(Secret.key.ilike(f"%{req.query}%"))
        if req.category:
            query = query.where(Secret.category == req.category)
        if req.tag:
            # cast to string for SQLite compatibility; PostgreSQL handles JSON natively
            from sqlalchemy import cast, String
            query = query.where(cast(Secret.tags, String).ilike(f'%"{req.tag}"%'))
        if req.created_after:
            query = query.where(Secret.created_at >= req.created_after)
        if req.created_before:
            query = query.where(Secret.created_at <= req.created_before)

        count_q = select(func.count()).select_from(query.subquery())
        total = (await db.execute(count_q)).scalar_one()

        sort_col = getattr(Secret, req.sort_by, Secret.created_at)
        order_fn = asc if req.sort_order == "asc" else desc
        query = query.order_by(order_fn(sort_col))
        query = query.offset((req.page - 1) * req.page_size).limit(req.page_size)

        result = await db.execute(query)
        return result.scalars().all(), total


secret_service = SecretService()
