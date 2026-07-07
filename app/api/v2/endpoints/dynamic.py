"""Dynamic Secrets Engine endpoints — NanoVault v2.0"""
from fastapi import APIRouter, Depends, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional
from app.db.session import get_db
from app.core.dependencies import get_current_user
from app.core.responses import ok, created
from app.engines.dynamic.engine import DynamicSecretsEngine
from app.services.v2.lease_service import lease_service
from app.services.audit_service import audit_service
from app.models.models import AuditAction, CredentialType
from app.engines.base import engine_registry

router = APIRouter(prefix="/dynamic", tags=["Dynamic Secrets Engine"])


class GenerateRequest(BaseModel):
    credential_type: CredentialType
    ttl_seconds: int = Field(3600, ge=60, le=86400)
    max_renewals: int = Field(5, ge=0, le=20)
    db_name: Optional[str] = "app_db"


class RenewLeaseRequest(BaseModel):
    lease_id: str
    increment_seconds: int = Field(3600, ge=60, le=86400)


class RevokeLeaseRequest(BaseModel):
    lease_id: str


@router.get("/engines", summary="List available secrets engines")
async def list_engines(_=Depends(get_current_user)):
    return ok(engine_registry.list_engines(), "Available engines")


@router.post("/generate", summary="Generate dynamic credentials with lease")
async def generate(
    body: GenerateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    kwargs = {}
    if body.db_name and body.credential_type in (
        CredentialType.DATABASE_POSTGRES, CredentialType.DATABASE_MYSQL
    ):
        kwargs["db_name"] = body.db_name

    cred, lease, plaintext = await DynamicSecretsEngine.generate(
        db, current_user, body.credential_type,
        body.ttl_seconds, body.max_renewals, **kwargs,
    )
    await audit_service.log(
        db, AuditAction.DYNAMIC_CRED_GENERATE, user_id=current_user.id,
        resource_type="dynamic_credential", resource_id=str(cred.id),
        request=request, metadata={"type": body.credential_type.value, "ttl": body.ttl_seconds},
    )
    return created({
        "credential_id": str(cred.id),
        "lease_id": lease.lease_id,
        "credential_type": body.credential_type.value,
        "expires_at": cred.expires_at.isoformat(),
        "ttl_seconds": body.ttl_seconds,
        "renewable": True,
        "max_renewals": body.max_renewals,
        "credentials": plaintext,
    }, "Dynamic credential generated")


@router.get("/leases", summary="List active leases")
async def list_leases(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    leases = await lease_service.list_active(db, current_user.id)
    data = [{
        "lease_id": l.lease_id,
        "status": l.status.value,
        "expires_at": l.expires_at.isoformat(),
        "renewable": l.renewal_count < l.max_renewals,
        "renewal_count": l.renewal_count,
        "ttl_seconds": l.ttl_seconds,
    } for l in leases]
    return ok(data, f"{len(data)} active leases")


@router.post("/leases/lookup", summary="Look up a lease by ID")
async def lookup_lease(
    body: RevokeLeaseRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    info = await lease_service.lookup(db, body.lease_id, current_user.id)
    return ok(info, "Lease details")


@router.post("/leases/renew", summary="Renew a lease")
async def renew_lease(
    body: RenewLeaseRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    lease = await lease_service.renew(db, body.lease_id, current_user.id, body.increment_seconds)
    await audit_service.log(db, AuditAction.LEASE_RENEW, user_id=current_user.id,
                            resource_type="lease", resource_id=body.lease_id, request=request)
    return ok({
        "lease_id": lease.lease_id,
        "expires_at": lease.expires_at.isoformat(),
        "renewal_count": lease.renewal_count,
    }, "Lease renewed")


@router.post("/leases/revoke", summary="Revoke a lease and its credential")
async def revoke_lease(
    body: RevokeLeaseRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    await lease_service.revoke(db, body.lease_id, current_user.id)
    await audit_service.log(db, AuditAction.LEASE_REVOKE, user_id=current_user.id,
                            resource_type="lease", resource_id=body.lease_id, request=request)
    return ok(message="Lease revoked and credential invalidated")
