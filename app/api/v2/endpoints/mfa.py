"""MFA endpoints — NanoVault v2.0"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.db.session import get_db
from app.core.dependencies import get_current_user
from app.core.responses import ok
from app.services.v2.mfa_service import mfa_service
from app.services.audit_service import audit_service
from app.models.models import AuditAction

router = APIRouter(prefix="/mfa", tags=["Identity & MFA"])


class VerifyRequest(BaseModel):
    totp_code: str


class RecoveryRequest(BaseModel):
    recovery_code: str


class DisableRequest(BaseModel):
    totp_code: str


@router.post("/setup", summary="Set up TOTP MFA — returns secret and QR URI")
async def setup_mfa(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    data = await mfa_service.setup(db, current_user)
    await audit_service.log(db, AuditAction.MFA_ENABLED, user_id=current_user.id, request=request)
    return ok(data, "MFA setup initiated — verify with /mfa/verify to activate")


@router.post("/verify", summary="Verify TOTP code and activate MFA")
async def verify_mfa(
    body: VerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    await mfa_service.verify_and_enable(db, current_user, body.totp_code)
    await audit_service.log(db, AuditAction.MFA_VERIFIED, user_id=current_user.id, request=request)
    return ok({"mfa_enabled": True}, "MFA activated successfully")


@router.post("/recovery", summary="Use a recovery code to bypass MFA")
async def use_recovery(
    body: RecoveryRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    await mfa_service.use_recovery_code(db, current_user, body.recovery_code)
    return ok(message="Recovery code accepted")


@router.delete("/disable", summary="Disable MFA (requires valid TOTP)")
async def disable_mfa(
    body: DisableRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    await mfa_service.disable(db, current_user, body.totp_code)
    await audit_service.log(db, AuditAction.MFA_DISABLED, user_id=current_user.id, request=request)
    return ok({"mfa_enabled": False}, "MFA disabled")


@router.get("/status", summary="Check MFA status for current user")
async def mfa_status(current_user=Depends(get_current_user)):
    return ok({
        "mfa_enabled": current_user.mfa_enabled,
        "username": current_user.username,
    }, "MFA status")
