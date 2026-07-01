"""KV Secrets Engine — CRUD with AES-256-GCM encryption at rest."""
import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from fastapi import HTTPException, status
from app.models.models import Secret, User
from app.core.encryption import encryption_service


class SecretService:
    @staticmethod
    async def create(
        db: AsyncSession,
        owner: User,
        key: str,
        value: str,
        description: Optional[str] = None,
        category: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> Secret:
        # Enforce uniqueness per owner (soft-delete aware — handled by partial index)
        existing = await db.execute(
            select(Secret).where(
                Secret.owner_id == owner.id,
                Secret.key == key,
                Secret.is_deleted == False,  # noqa: E712
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"Secret with key '{key}' already exists")

        secret = Secret(
            owner_id=owner.id,
            key=key,
            encrypted_value=encryption_service.encrypt(value),
            description=description,
            category=category,
            tags=tags or [],
        )
        db.add(secret)
        await db.flush()
        return secret

    @staticmethod
    async def _get_owned(db: AsyncSession, owner: User, secret_id: uuid.UUID) -> Secret:
        result = await db.execute(
            select(Secret).where(
                Secret.id == secret_id,
                Secret.owner_id == owner.id,
                Secret.is_deleted == False,  # noqa: E712
            )
        )
        secret = result.scalar_one_or_none()
        if not secret:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")
        return secret

    @staticmethod
    async def read(db: AsyncSession, owner: User, secret_id: uuid.UUID) -> tuple[Secret, str]:
        secret = await SecretService._get_owned(db, owner, secret_id)
        decrypted = encryption_service.decrypt(secret.encrypted_value)
        return secret, decrypted

    @staticmethod
    async def list_secrets(
        db: AsyncSession,
        owner: User,
        *,
        category: Optional[str] = None,
        tag: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[Secret], int]:
        query = select(Secret).where(
            Secret.owner_id == owner.id,
            Secret.is_deleted == False,  # noqa: E712
        )
        if category:
            query = query.where(Secret.category == category)
        if tag:
            from sqlalchemy import cast, String
            query = query.where(
                cast(Secret.tags, String).ilike(f'%"{tag}"%')
            )
        #if tag:
            # PostgreSQL JSON array containment
            #query = query.where(Secret.tags.contains([tag]))

        count_q = select(func.count()).select_from(query.subquery())
        total = (await db.execute(count_q)).scalar_one()

        query = query.order_by(Secret.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await db.execute(query)
        return result.scalars().all(), total

    @staticmethod
    async def update(
        db: AsyncSession,
        owner: User,
        secret_id: uuid.UUID,
        *,
        value: Optional[str] = None,
        description: Optional[str] = None,
        category: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> Secret:
        secret = await SecretService._get_owned(db, owner, secret_id)

        if value is not None:
            secret.encrypted_value = encryption_service.encrypt(value)
            secret.version += 1
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
        secret = await SecretService._get_owned(db, owner, secret_id)
        secret.is_deleted = True
        await db.flush()

    # Admin: list all secrets (metadata only)
    @staticmethod
    async def admin_list(
        db: AsyncSession,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[Secret], int]:
        query = select(Secret).where(Secret.is_deleted == False)  # noqa: E712
        count_q = select(func.count()).select_from(query.subquery())
        total = (await db.execute(count_q)).scalar_one()
        query = query.order_by(Secret.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        result = await db.execute(query)
        return result.scalars().all(), total


secret_service = SecretService()
