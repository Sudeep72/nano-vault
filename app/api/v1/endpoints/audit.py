"""Audit log endpoints — NanoVault v1.0.1"""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.schemas.schemas import AuditLogResponse
from app.services.audit_service import audit_service
from app.models.models import AuditAction
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import paginated

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/my", summary="My audit log")
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
    items = [AuditLogResponse.model_validate(l).model_dump(mode="json") for l in logs]
    return paginated(items, total, page, page_size, "Audit logs retrieved")


@router.get("/all", tags=["Admin"], summary="[Admin] All audit logs")
async def all_audit_logs(
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_admin),
    action: Optional[AuditAction] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    logs, total = await audit_service.get_logs(db, action=action, page=page, page_size=page_size)
    items = [AuditLogResponse.model_validate(l).model_dump(mode="json") for l in logs]
    return paginated(items, total, page, page_size, "Audit logs retrieved")
