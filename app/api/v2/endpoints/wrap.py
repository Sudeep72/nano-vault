"""Response Wrapping endpoints — NanoVault v2.0"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional
from app.db.session import get_db
from app.core.dependencies import get_current_user
from app.core.responses import ok, created
from app.services.v2.wrap_service import wrap_service
from app.services.audit_service import audit_service
from app.models.models import AuditAction

router = APIRouter(prefix="/wrap", tags=["Response Wrapping"])


class WrapRequest(BaseModel):
    payload: dict
    ttl_seconds: int = Field(300, ge=10, le=3600, description="Wrap token TTL in seconds")


class UnwrapRequest(BaseModel):
    wrap_token: str


class LookupRequest(BaseModel):
    wrap_token: str


@router.post("/", summary="Wrap a payload in a one-time token")
async def wrap(
    body: WrapRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    token, expires = await wrap_service.wrap(db, body.payload, body.ttl_seconds, current_user)
    await audit_service.log(db, AuditAction.WRAP_CREATE, user_id=current_user.id,
                            request=request, metadata={"ttl": body.ttl_seconds})
    return created({
        "wrap_token": token,
        "ttl_seconds": body.ttl_seconds,
        "expires_at": expires.isoformat(),
        "usage": "POST /api/v2/wrap/unwrap with this token — single use only",
    }, "Payload wrapped")


@router.post("/unwrap", summary="Unwrap a one-time token (destroys token)")
async def unwrap(
    body: UnwrapRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    payload = await wrap_service.unwrap(db, body.wrap_token)
    return ok(payload, "Payload unwrapped — token destroyed")


@router.post("/lookup", summary="Check wrap token status without unwrapping")
async def lookup(
    body: LookupRequest,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    info = await wrap_service.lookup(db, body.wrap_token)
    return ok(info, "Wrap token status")
