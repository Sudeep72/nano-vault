"""KV Secrets endpoints — full CRUD with audit logging."""
import uuid
import math
from typing import Optional
from fastapi import APIRouter, Depends, Request, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.schemas.schemas import (
    SecretCreateRequest, SecretUpdateRequest,
    SecretResponse, SecretMetaResponse, MessageResponse, PaginatedResponse,
)
from app.services.secret_service import secret_service
from app.services.audit_service import audit_service
from app.models.models import AuditAction
from app.core.dependencies import get_current_user, require_admin

router = APIRouter(prefix="/secrets", tags=["Secrets"])


@router.post("", response_model=SecretMetaResponse, status_code=status.HTTP_201_CREATED)
async def create_secret(
    body: SecretCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    secret = await secret_service.create(
        db, current_user,
        key=body.key, value=body.value,
        description=body.description, category=body.category, tags=body.tags,
    )
    await audit_service.log(db, AuditAction.SECRET_CREATE, user_id=current_user.id,
                            resource_type="secret", resource_id=str(secret.id), request=request)
    return secret


@router.get("", response_model=PaginatedResponse)
async def list_secrets(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
    category: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    secrets, total = await secret_service.list_secrets(
        db, current_user, category=category, tag=tag, page=page, page_size=page_size
    )
    items = [SecretMetaResponse.model_validate(s) for s in secrets]
    return PaginatedResponse(
        items=[i.model_dump() for i in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=math.ceil(total / page_size) if total else 0,
    )


@router.get("/{secret_id}", response_model=SecretResponse)
async def read_secret(
    secret_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    secret, decrypted = await secret_service.read(db, current_user, secret_id)
    await audit_service.log(db, AuditAction.SECRET_READ, user_id=current_user.id,
                            resource_type="secret", resource_id=str(secret_id), request=request)
    # Manually build response to inject decrypted value
    return SecretResponse(
        id=secret.id, key=secret.key, value=decrypted,
        description=secret.description, category=secret.category,
        tags=secret.tags, version=secret.version,
        created_at=secret.created_at, updated_at=secret.updated_at,
    )


@router.patch("/{secret_id}", response_model=SecretMetaResponse)
async def update_secret(
    secret_id: uuid.UUID,
    body: SecretUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    secret = await secret_service.update(
        db, current_user, secret_id,
        value=body.value, description=body.description,
        category=body.category, tags=body.tags,
    )
    await audit_service.log(db, AuditAction.SECRET_UPDATE, user_id=current_user.id,
                            resource_type="secret", resource_id=str(secret_id), request=request,
                            metadata={"new_version": secret.version})
    return secret


@router.delete("/{secret_id}", response_model=MessageResponse)
async def delete_secret(
    secret_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    await secret_service.delete(db, current_user, secret_id)
    await audit_service.log(db, AuditAction.SECRET_DELETE, user_id=current_user.id,
                            resource_type="secret", resource_id=str(secret_id), request=request)
    return {"message": "Secret deleted"}


# ── Admin routes ─────────────────────────────────────────────────────────────

@router.get("/admin/all", response_model=PaginatedResponse, tags=["Admin"])
async def admin_list_all(
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_admin),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    secrets, total = await secret_service.admin_list(db, page=page, page_size=page_size)
    items = [SecretMetaResponse.model_validate(s) for s in secrets]
    return PaginatedResponse(
        items=[i.model_dump() for i in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=math.ceil(total / page_size) if total else 0,
    )
