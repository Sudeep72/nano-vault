"""AI Security Findings — NanoVault v5.0 (Step 9)"""
from __future__ import annotations
import uuid
from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok

router = APIRouter(prefix="/ai/findings", tags=["AI Security Platform"])


class UpdateStatusRequest(BaseModel):
    status: str  # open, acknowledged, dismissed, resolved


@router.get("", summary="List AI security findings")
async def list_findings(category: Optional[str] = None, severity: Optional[str] = None,
                        status: Optional[str] = None, limit: int = 50,
                        db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.services.v5.findings_service import findings_service
    return ok(await findings_service.list_findings(db, category, severity, status, limit), "AI findings")


@router.get("/{finding_id}", summary="Get one AI finding")
async def get_finding(finding_id: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.services.v5.findings_service import findings_service, _finding_to_dict
    finding = await findings_service.get(db, finding_id)
    return ok(_finding_to_dict(finding), "Finding")


@router.patch("/{finding_id}/status", summary="Update finding status (triage) [Admin]")
async def update_status(finding_id: uuid.UUID, body: UpdateStatusRequest,
                        db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    from app.services.v5.findings_service import findings_service, _finding_to_dict
    from app.services.audit_service import audit_service
    from app.models.models import AuditAction
    finding = await findings_service.update_status(db, finding_id, body.status)
    await audit_service.log(db, AuditAction.AI_FINDING_STATUS_CHANGE, user_id=admin.id,
                            resource_type="ai_finding", resource_id=str(finding_id),
                            metadata={"new_status": body.status})
    await db.commit()
    return ok(_finding_to_dict(finding), "Status updated")
