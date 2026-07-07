"""KV Secrets Engine v2 endpoints — versioning, rollback, rotation"""
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.core.dependencies import get_current_user
from app.core.responses import ok, created, paginated
from app.services.secret_service import secret_service
from app.services.v2.rotation_service import rotation_service
from app.services.audit_service import audit_service
from app.models.models import AuditAction
from app.engines.kv.engine import KVSecretsEngine
from app.core.encryption import encryption_service
from pydantic import BaseModel

router = APIRouter(prefix="/kv", tags=["KV Secrets Engine v2"])


class RotateRequest(BaseModel):
    new_value: str
    change_note: Optional[str] = None


class EnableRotationRequest(BaseModel):
    interval_days: int


class RollbackRequest(BaseModel):
    version_number: int
    change_note: Optional[str] = None


@router.get("/{secret_id}/versions", summary="List all versions of a secret")
async def list_versions(
    secret_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    secret, _ = await secret_service.read(db, current_user, secret_id)
    versions = await KVSecretsEngine.get_version_history(db, secret)
    data = [
        {
            "version_number": v.version_number,
            "created_at": v.created_at.isoformat(),
            "created_by": str(v.created_by) if v.created_by else None,
            "change_note": v.change_note,
            "is_current": v.is_current,
        }
        for v in versions
    ]
    return ok(data, f"Found {len(data)} versions")


@router.get("/{secret_id}/versions/{version_number}", summary="Read a specific version")
async def read_version(
    secret_id: uuid.UUID,
    version_number: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    secret, _ = await secret_service.read(db, current_user, secret_id)
    version = await KVSecretsEngine.get_version(db, secret, version_number)
    decrypted = encryption_service.decrypt(version.encrypted_value)
    await audit_service.log(db, AuditAction.SECRET_VERSION_READ, user_id=current_user.id,
                            resource_type="secret_version", resource_id=f"{secret_id}@v{version_number}",
                            request=request)
    return ok({
        "secret_id": str(secret_id),
        "key": secret.key,
        "version_number": version.version_number,
        "value": decrypted,
        "created_at": version.created_at.isoformat(),
        "change_note": version.change_note,
        "is_current": version.is_current,
    }, f"Version {version_number} retrieved")


@router.get("/{secret_id}/versions/{va}/compare/{vb}", summary="Compare two versions")
async def compare_versions(
    secret_id: uuid.UUID,
    va: int, vb: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    secret, _ = await secret_service.read(db, current_user, secret_id)
    result = await KVSecretsEngine.compare_versions(db, secret, va, vb)
    return ok(result, f"Comparison of versions {va} and {vb}")


@router.post("/{secret_id}/rollback", summary="Rollback to a previous version")
async def rollback(
    secret_id: uuid.UUID,
    body: RollbackRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    secret, _ = await secret_service.read(db, current_user, secret_id)
    updated_secret, _ = await KVSecretsEngine.rollback_to_version(
        db, secret, body.version_number,
        rolled_back_by=current_user.id,
    )
    await audit_service.log(db, AuditAction.SECRET_ROLLBACK, user_id=current_user.id,
                            resource_type="secret", resource_id=str(secret_id), request=request,
                            metadata={"target_version": body.version_number})
    return ok({"version": updated_secret.version, "key": updated_secret.key},
              f"Rolled back to version {body.version_number}")


@router.post("/{secret_id}/rotate", summary="Manually rotate a secret value")
async def rotate_secret(
    secret_id: uuid.UUID,
    body: RotateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    secret, _ = await secret_service.read(db, current_user, secret_id)
    updated, history = await rotation_service.manual_rotate(
        db, current_user, secret, body.new_value, body.change_note
    )
    await audit_service.log(db, AuditAction.SECRET_ROTATE, user_id=current_user.id,
                            resource_type="secret", resource_id=str(secret_id), request=request,
                            metadata={"new_version": updated.version})
    return ok({"version": updated.version, "rotated_at": updated.last_rotated_at.isoformat()},
              "Secret rotated successfully")


@router.post("/{secret_id}/rotation/enable", summary="Enable automatic rotation")
async def enable_rotation(
    secret_id: uuid.UUID,
    body: EnableRotationRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    secret, _ = await secret_service.read(db, current_user, secret_id)
    updated = await rotation_service.enable_auto_rotation(db, secret, body.interval_days)
    return ok({
        "rotation_enabled": True,
        "interval_days": updated.rotation_interval_days,
        "next_rotation_at": updated.next_rotation_at.isoformat() if updated.next_rotation_at else None,
    }, "Auto-rotation enabled")


@router.delete("/{secret_id}/rotation", summary="Disable automatic rotation")
async def disable_rotation(
    secret_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    secret, _ = await secret_service.read(db, current_user, secret_id)
    await rotation_service.disable_auto_rotation(db, secret)
    return ok(message="Auto-rotation disabled")


@router.get("/{secret_id}/rotation/history", summary="View rotation history")
async def rotation_history(
    secret_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    secret, _ = await secret_service.read(db, current_user, secret_id)
    history = await rotation_service.get_rotation_history(db, secret)
    data = [
        {
            "id": str(h.id),
            "old_version": h.old_version,
            "new_version": h.new_version,
            "rotation_type": h.rotation_type,
            "status": h.status.value,
            "created_at": h.created_at.isoformat(),
            "error_message": h.error_message,
        }
        for h in history
    ]
    return ok(data, f"Found {len(data)} rotation events")
