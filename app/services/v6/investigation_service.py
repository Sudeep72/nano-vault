"""Investigation Workflow — NanoVault v6.0, Phase 5 (final)

Lifecycle:  OPEN -> INVESTIGATING -> ACKNOWLEDGED -> RESOLVED
            {OPEN, INVESTIGATING, ACKNOWLEDGED} -> DISMISSED
"""
from __future__ import annotations
import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException
from app.models.models import AIFinding, AIFindingStatus, UserRole, AuditAction
from app.services.v5.findings_service import findings_service, _finding_to_dict
from app.services.audit_service import audit_service

VALID_TRANSITIONS: dict[AIFindingStatus, set[AIFindingStatus]] = {
    AIFindingStatus.OPEN: {AIFindingStatus.INVESTIGATING, AIFindingStatus.DISMISSED},
    AIFindingStatus.INVESTIGATING: {AIFindingStatus.ACKNOWLEDGED, AIFindingStatus.DISMISSED},
    AIFindingStatus.ACKNOWLEDGED: {AIFindingStatus.RESOLVED, AIFindingStatus.DISMISSED},
    AIFindingStatus.RESOLVED: set(),
    AIFindingStatus.DISMISSED: set(),
}

def _is_authorized(finding: AIFinding, current_user) -> bool:
    return current_user.role == UserRole.ADMIN or finding.created_by == current_user.id

class InvestigationWorkflowService:

    @staticmethod
    async def get_finding(db: AsyncSession, current_user, finding_id: uuid.UUID) -> dict:
        finding = await findings_service.get(db, finding_id)
        if not _is_authorized(finding, current_user):
            raise HTTPException(status_code=403, detail="Not authorized to access this finding")
        return _finding_to_dict(finding)

    @staticmethod
    async def list_my_findings(db, current_user, category=None, status=None, limit=50) -> list[dict]:
        q = select(AIFinding).order_by(AIFinding.created_at.desc()).limit(limit)
        if current_user.role != UserRole.ADMIN:
            q = q.where(AIFinding.created_by == current_user.id)
        if category: q = q.where(AIFinding.category == category)
        if status: q = q.where(AIFinding.status == AIFindingStatus(status))
        findings = (await db.execute(q)).scalars().all()
        return [_finding_to_dict(f) for f in findings]

    @staticmethod
    async def _transition(db, current_user, finding_id: uuid.UUID, target: AIFindingStatus, extra_note=None) -> dict:
        finding = await findings_service.get(db, finding_id)
        if not _is_authorized(finding, current_user):
            raise HTTPException(403, "Not authorized to change this finding's status")
        current = finding.status
        allowed = VALID_TRANSITIONS.get(current, set())
        if target not in allowed:
            raise HTTPException(409, f"Invalid state transition: cannot move from '{current.value}' to '{target.value}'. Valid from '{current.value}': {sorted(s.value for s in allowed) or 'none (terminal)'}")
        finding.status = target
        if extra_note:
            finding.recommended_actions = list(finding.recommended_actions or []) + [extra_note]
        await db.flush()
        await audit_service.log(db, AuditAction.AI_FINDING_STATUS_CHANGE, user_id=current_user.id, resource_type="ai_finding", resource_id=str(finding_id), metadata={"from_status": current.value, "to_status": target.value})
        await db.commit()
        return _finding_to_dict(finding)

    @staticmethod
    async def start_investigation(db, current_user, finding_id): return await InvestigationWorkflowService._transition(db, current_user, finding_id, AIFindingStatus.INVESTIGATING)
    @staticmethod
    async def acknowledge(db, current_user, finding_id): return await InvestigationWorkflowService._transition(db, current_user, finding_id, AIFindingStatus.ACKNOWLEDGED)
    @staticmethod
    async def resolve(db, current_user, finding_id, note=None): return await InvestigationWorkflowService._transition(db, current_user, finding_id, AIFindingStatus.RESOLVED, f"Resolved: {note}" if note else None)
    @staticmethod
    async def dismiss(db, current_user, finding_id, reason=None): return await InvestigationWorkflowService._transition(db, current_user, finding_id, AIFindingStatus.DISMISSED, f"Dismissed: {reason}" if reason else None)

investigation_workflow_service = InvestigationWorkflowService()
