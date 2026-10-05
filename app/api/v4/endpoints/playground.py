"""Interactive API Playground — NanoVault v4.0"""
from __future__ import annotations
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from app.db.session import get_db
from app.core.dependencies import get_current_user
from app.core.responses import ok
from app.models.models import AuditLog

router = APIRouter(prefix="/playground", tags=["API Playground"])


class ExecuteRequest(BaseModel):
    method: str
    path: str
    token: Optional[str] = None
    namespace: Optional[str] = None
    body: Optional[dict] = None


@router.post("/execute", summary="Execute any NanoVault API request live, in-process, and see the real result")
async def execute(body: ExecuteRequest, request: Request, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    """
    Runs the request against the actual running app (no separate network hop).
    Because this calls the real endpoint, any audit event the target endpoint
    would normally emit (SECRET_CREATE, VAULT_TOKEN_CREATE, etc.) is generated
    by that endpoint's own real logic — the playground surfaces the most recent
    matching audit entry afterward rather than fabricating a separate one.
    """
    from app.services.v4.playground_service import playground_service
    result = await playground_service.execute(
        request.app, body.method, body.path,
        token=body.token or request.headers.get("Authorization", "").replace("Bearer ", ""),
        namespace=body.namespace, json_body=body.body,
    )

    latest_audit = (await db.execute(
        select(AuditLog).where(AuditLog.user_id == current_user.id)
        .order_by(AuditLog.created_at.desc()).limit(1)
    )).scalar_one_or_none()
    result["generated_audit_event"] = {
        "action": latest_audit.action.value, "created_at": latest_audit.created_at.isoformat(),
    } if latest_audit else None

    return ok(result, f"Executed {body.method.upper()} {body.path}")


@router.get("/examples", summary="Curated example payloads for common endpoints")
async def examples(_=Depends(get_current_user)):
    from app.services.v4.playground_service import playground_service
    return ok(playground_service.get_example_payloads(), "Example payloads")


@router.get("/namespaces", summary="Available namespaces for playground namespace selector")
async def playground_namespaces(db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.models.models import Namespace
    namespaces = (await db.execute(select(Namespace))).scalars().all()
    return ok([{"id": str(n.id), "path": n.path} for n in namespaces], "Namespaces")
