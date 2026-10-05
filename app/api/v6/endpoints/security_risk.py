"""Security Risk Engine, Correlation, AI Analyst, Investigation Workflow — NanoVault v6.0, Phases 1-5"""
from __future__ import annotations
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok
from app.models.models import UserRole

router = APIRouter(prefix="/security", tags=["Security Operations Platform"])


# ── Phase 1 — Risk Engine ─────────────────────────────────────────────────────

@router.get("/risk/rules", summary="List registered deterministic risk rules")
async def list_rules(_=Depends(get_current_user)):
    from app.services.v6.risk_engine import risk_engine
    return ok(risk_engine.list_rules(), "Registered risk rules")

@router.get("/risk/users/{user_id}", summary="Preview user risk assessment (read-only, not persisted)")
async def preview_user_risk(user_id: uuid.UUID, window_hours: int = 24, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    if current_user.role != UserRole.ADMIN and current_user.id != user_id:
        raise HTTPException(403, "Not authorized to view this user's risk assessment")
    from app.services.v6.risk_engine import risk_engine
    return ok(await risk_engine.assess_user(db, user_id, window_hours), "Risk assessment (preview)")

@router.post("/risk/users/{user_id}/assess", summary="Run and persist a risk assessment for a user [Admin]")
async def assess_and_record_user(user_id: uuid.UUID, window_hours: int = 24, db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    from app.services.v6.risk_assessment_service import risk_assessment_service
    return ok(await risk_assessment_service.assess_and_record_user(db, admin, user_id, window_hours), "Risk assessment recorded")

@router.post("/risk/platform/assess", summary="Run and persist a platform-wide risk assessment [Admin]")
async def assess_and_record_platform(window_hours: int = 24, db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    from app.services.v6.risk_assessment_service import risk_assessment_service
    return ok(await risk_assessment_service.assess_and_record_platform(db, admin, window_hours), "Platform risk assessment recorded")


# ── Phase 2 — Correlation Engine ──────────────────────────────────────────────

@router.get("/correlation/rules", summary="List registered correlation chain rules")
async def list_correlation_rules(_=Depends(get_current_user)):
    from app.services.v6.correlation_service import correlation_engine
    return ok(correlation_engine.list_rules(), "Registered correlation rules")

@router.get("/correlation/users/{user_id}", summary="Preview user correlation analysis (read-only, not persisted)")
async def preview_user_correlation(user_id: uuid.UUID, window_hours: int = 24, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    if current_user.role != UserRole.ADMIN and current_user.id != user_id:
        raise HTTPException(403, "Not authorized to view this user's correlation analysis")
    from app.services.v6.correlation_service import correlation_engine
    return ok(await correlation_engine.correlate_user(db, user_id, window_hours), "Correlation analysis (preview)")

@router.post("/correlation/users/{user_id}/assess", summary="Run and persist correlation analysis for a user [Admin]")
async def correlate_and_record_user(user_id: uuid.UUID, window_hours: int = 24, db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    from app.services.v6.correlation_assessment_service import correlation_assessment_service
    return ok(await correlation_assessment_service.correlate_and_record_user(db, admin, user_id, window_hours), "Correlation analysis recorded")

@router.post("/correlation/platform/assess", summary="Run and persist a platform-wide correlation analysis [Admin]")
async def correlate_and_record_platform(window_hours: int = 24, db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    from app.services.v6.correlation_assessment_service import correlation_assessment_service
    return ok(await correlation_assessment_service.correlate_and_record_platform(db, admin, window_hours), "Platform correlation analysis recorded")


# ── Phase 3 — AI Security Analyst ─────────────────────────────────────────────

class ExplainFindingRequest(BaseModel):
    question: Optional[str] = None

@router.post("/findings/{finding_id}/explain", summary="AI explanation of a deterministic risk/correlation finding")
async def explain_finding(finding_id: uuid.UUID, body: ExplainFindingRequest = ExplainFindingRequest(), db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    from app.services.v6.security_analyst_v6 import security_analyst_v6_service
    result = await security_analyst_v6_service.explain_finding(db, current_user, finding_id, body.question)
    return ok(result.to_dict(), "AI explanation generated" if result.success else "AI explanation failed")


# ── Phase 5 — Investigation Workflow ──────────────────────────────────────────

class DismissRequest(BaseModel):
    reason: Optional[str] = None

class ResolveRequest(BaseModel):
    resolution_note: Optional[str] = None

@router.get("/findings", summary="List findings scoped to caller (admin sees all, others see own only)")
async def list_my_findings(category: Optional[str] = None, status: Optional[str] = None, limit: int = 50, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    from app.services.v6.investigation_service import investigation_workflow_service
    return ok(await investigation_workflow_service.list_my_findings(db, current_user, category, status, limit), "Findings")

@router.get("/findings/{finding_id}", summary="Get a finding (creator or admin only)")
async def get_finding_scoped(finding_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    from app.services.v6.investigation_service import investigation_workflow_service
    return ok(await investigation_workflow_service.get_finding(db, current_user, finding_id), "Finding")

@router.post("/findings/{finding_id}/investigate", summary="Start investigating a finding (OPEN -> INVESTIGATING)")
async def start_investigation(finding_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    from app.services.v6.investigation_service import investigation_workflow_service
    return ok(await investigation_workflow_service.start_investigation(db, current_user, finding_id), "Investigation started")

@router.post("/findings/{finding_id}/acknowledge", summary="Acknowledge a finding (INVESTIGATING -> ACKNOWLEDGED)")
async def acknowledge_finding(finding_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    from app.services.v6.investigation_service import investigation_workflow_service
    return ok(await investigation_workflow_service.acknowledge(db, current_user, finding_id), "Finding acknowledged")

@router.post("/findings/{finding_id}/resolve", summary="Resolve a finding (ACKNOWLEDGED -> RESOLVED)")
async def resolve_finding(finding_id: uuid.UUID, body: ResolveRequest = ResolveRequest(), db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    from app.services.v6.investigation_service import investigation_workflow_service
    return ok(await investigation_workflow_service.resolve(db, current_user, finding_id, body.resolution_note), "Finding resolved")

@router.post("/findings/{finding_id}/dismiss", summary="Dismiss a finding (OPEN/INVESTIGATING/ACKNOWLEDGED -> DISMISSED)")
async def dismiss_finding(finding_id: uuid.UUID, body: DismissRequest = DismissRequest(), db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    from app.services.v6.investigation_service import investigation_workflow_service
    return ok(await investigation_workflow_service.dismiss(db, current_user, finding_id, body.reason), "Finding dismissed")
