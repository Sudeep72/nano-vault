from __future__ import annotations
import uuid
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok, created
from app.services.v3.shamir_service import shamir_service
from app.services.v3.auto_unseal_service import auto_unseal_service
from app.models.models import UnsealProviderType, AuditAction
from app.services.audit_service import audit_service

router = APIRouter(prefix="/seal", tags=["Seal Management"])

class InitializeRequest(BaseModel):
    total_shares: int = Field(5, ge=2, le=20); threshold: int = Field(3, ge=2, le=20)
class UnsealRequest(BaseModel):
    share: str
class AutoUnsealConfigRequest(BaseModel):
    name: str; provider_type: UnsealProviderType; config: dict

@router.get("/status", summary="Get vault seal status")
async def seal_status(db: AsyncSession = Depends(get_db)):
    return ok(await shamir_service.get_status(db), "Seal status")

@router.post("/initialize", summary="Initialize vault with Shamir shares [Admin]")
async def initialize(body: InitializeRequest, request: Request, db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    if body.threshold > body.total_shares: raise HTTPException(400, f"Threshold ({body.threshold}) cannot exceed total shares ({body.total_shares})")
    result = await shamir_service.initialize(db, body.total_shares, body.threshold)
    await audit_service.log(db, AuditAction.VAULT_TOKEN_CREATE, user_id=admin.id, resource_type="vault_seal", resource_id="init", request=request, metadata={"total_shares": body.total_shares, "threshold": body.threshold})
    return created(result, "Vault initialized. Distribute key shares securely.")

@router.post("/unseal", summary="Submit a Shamir key share to unseal")
async def unseal(body: UnsealRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await shamir_service.unseal(db, body.share)
    return ok(result, result.get("message", "Share submitted"))

@router.post("/seal", summary="Immediately seal the vault [Admin]")
async def seal(request: Request, db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    result = await shamir_service.seal(db)
    await audit_service.log(db, AuditAction.VAULT_TOKEN_REVOKE, user_id=admin.id, resource_type="vault_seal", resource_id="seal", request=request)
    return ok(result, "Vault sealed")

@router.post("/auto-unseal/providers", summary="Configure an auto-unseal provider [Admin]")
async def configure_provider(body: AutoUnsealConfigRequest, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    p = await auto_unseal_service.configure(db, body.name, body.provider_type, body.config)
    return created({"id": str(p.id), "name": p.name, "type": p.provider_type.value, "is_active": p.is_active, "is_healthy": p.is_healthy, "created_at": p.created_at.isoformat()}, f"Provider '{body.name}' configured")

@router.get("/auto-unseal/providers", summary="List auto-unseal providers")
async def list_providers(db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    providers = await auto_unseal_service.list_providers(db)
    return ok([{"id": str(p.id), "name": p.name, "type": p.provider_type.value, "is_active": p.is_active, "is_healthy": p.is_healthy,
                "last_health_check": p.last_health_check.isoformat() if p.last_health_check else None,
                "last_used_at": p.last_used_at.isoformat() if p.last_used_at else None} for p in providers], f"{len(providers)} providers")

@router.post("/auto-unseal/providers/{provider_id}/enable", summary="Enable an auto-unseal provider [Admin]")
async def enable_provider(provider_id: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    p = await auto_unseal_service.enable(db, provider_id)
    return ok({"name": p.name, "is_active": p.is_active}, f"Provider '{p.name}' activated")

@router.post("/auto-unseal/providers/{provider_id}/health", summary="Health check a provider [Admin]")
async def health_check_provider(provider_id: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    return ok(await auto_unseal_service.health_check(db, provider_id), "Health check complete")

@router.post("/auto-unseal/trigger", summary="Trigger auto-unseal using active provider [Admin]")
async def trigger_auto_unseal(request: Request, db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    result = await auto_unseal_service.auto_unseal(db)
    await audit_service.log(db, AuditAction.VAULT_TOKEN_RENEW, user_id=admin.id, resource_type="vault_seal", resource_id="auto_unseal", request=request, metadata={"provider": result.get("provider")})
    return ok(result, "Auto-unseal triggered")
