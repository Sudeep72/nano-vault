"""Cubbyhole Secrets Engine endpoints — NanoVault v2.0"""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.db.session import get_db
from app.core.dependencies import get_current_user
from app.core.responses import ok, created
from app.engines.cubbyhole.engine import CubbyholeEngine
from app.services.audit_service import audit_service
from app.models.models import AuditAction

router = APIRouter(prefix="/cubbyhole", tags=["Cubbyhole Engine"])


class WriteRequest(BaseModel):
    key: str
    value: str
    expires_at: Optional[datetime] = None


@router.put("/", summary="Write to cubbyhole (private per-user storage)")
async def write(
    body: WriteRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    entry = await CubbyholeEngine.write_entry(db, current_user, body.key, body.value, expires_at=body.expires_at)
    await audit_service.log(db, AuditAction.CUBBYHOLE_WRITE, user_id=current_user.id,
                            resource_type="cubbyhole", resource_id=body.key, request=request)
    return ok({
        "key": entry.key,
        "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
        "created_at": entry.created_at.isoformat(),
    }, "Written to cubbyhole")


@router.get("/{key}", summary="Read from cubbyhole")
async def read(
    key: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    entry, decrypted = await CubbyholeEngine.read_entry(db, current_user, key)
    await audit_service.log(db, AuditAction.CUBBYHOLE_READ, user_id=current_user.id,
                            resource_type="cubbyhole", resource_id=key, request=request)
    return ok({
        "key": entry.key,
        "value": decrypted,
        "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
        "created_at": entry.created_at.isoformat(),
    }, "Cubbyhole entry retrieved")


@router.get("/", summary="List cubbyhole keys")
async def list_keys(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    keys = await CubbyholeEngine.list_entries(db, current_user)
    return ok({"keys": keys, "count": len(keys)}, "Cubbyhole keys listed")


@router.delete("/{key}", summary="Delete a cubbyhole entry")
async def delete(
    key: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    await CubbyholeEngine.delete_entry(db, current_user, key)
    await audit_service.log(db, AuditAction.CUBBYHOLE_DELETE, user_id=current_user.id,
                            resource_type="cubbyhole", resource_id=key, request=request)
    return ok(message="Cubbyhole entry deleted")
