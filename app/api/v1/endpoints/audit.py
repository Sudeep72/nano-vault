"""Audit log endpoints — read-only, paginated."""
import math
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.schemas.schemas import AuditLogResponse, PaginatedResponse
from app.services.audit_service import audit_service
from app.models.models import AuditAction
from app.core.dependencies import get_current_user, require_admin

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/my", response_model=PaginatedResponse)
async def my_audit_logs(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
    action: Optional[AuditAction] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    logs, total = await audit_service.get_logs(
        db, user_id=current_user.id, action=action, page=page, page_size=page_size
    )
    items = [AuditLogResponse.model_validate(l) for l in logs]
    return PaginatedResponse(
        items=[i.model_dump() for i in items],
        total=total, page=page, page_size=page_size,
        pages=math.ceil(total / page_size) if total else 0,
    )


@router.get("/all", response_model=PaginatedResponse, tags=["Admin"])
async def all_audit_logs(
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_admin),
    action: Optional[AuditAction] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    logs, total = await audit_service.get_logs(db, action=action, page=page, page_size=page_size)
    items = [AuditLogResponse.model_validate(l) for l in logs]
    return PaginatedResponse(
        items=[i.model_dump() for i in items],
        total=total, page=page, page_size=page_size,
        pages=math.ceil(total / page_size) if total else 0,
    )
