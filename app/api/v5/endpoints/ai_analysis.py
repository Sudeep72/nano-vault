"""AI Analysis + Investigation — NanoVault v5.0 (Step 5/7/8)"""
from __future__ import annotations
import uuid
from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.db.session import get_db
from app.core.dependencies import get_current_user
from app.core.responses import ok

router = APIRouter(prefix="/ai", tags=["AI Security Platform"])


class ExplainRequest(BaseModel):
    audit_log_id: uuid.UUID
    question: Optional[str] = None


class InvestigateRequest(BaseModel):
    audit_log_id: uuid.UUID
    question: str


@router.post("/explain", summary="Explain a specific audit event — observed evidence vs. AI inference, with confidence")
async def explain(body: ExplainRequest, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    from app.services.v5.security_analyst_service import security_analyst_service
    result = await security_analyst_service.explain_event(db, current_user, body.audit_log_id, body.question)
    return ok(result, "Explanation generated" if result["success"] else "Explanation failed")


@router.post("/investigate", summary="Ask a free-form investigation question about a specific event")
async def investigate(body: InvestigateRequest, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    from app.services.v5.security_analyst_service import security_analyst_service
    result = await security_analyst_service.investigate(db, current_user, body.audit_log_id, body.question)
    return ok(result, "Investigation complete" if result["success"] else "Investigation failed")
