from __future__ import annotations
import uuid
from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok, created
from app.services.v3.identity_provider_service import identity_provider_service
from app.models.models import IdentityProviderType

router = APIRouter(prefix="/identity", tags=["Enterprise Identity Providers"])

class ConfigureProviderRequest(BaseModel):
    name: str; provider_type: IdentityProviderType; config: dict
    group_mappings: Optional[dict] = None; role_mappings: Optional[dict] = None; namespace_mappings: Optional[dict] = None
class UpdateMappingsRequest(BaseModel):
    group_mappings: Optional[dict] = None; role_mappings: Optional[dict] = None; namespace_mappings: Optional[dict] = None

def _pd(p):
    return {"id": str(p.id), "name": p.name, "type": p.provider_type.value, "is_enabled": p.is_enabled,
            "group_mappings": p.group_mappings or {}, "role_mappings": p.role_mappings or {}, "namespace_mappings": p.namespace_mappings or {},
            "last_sync_at": p.last_sync_at.isoformat() if p.last_sync_at else None, "created_at": p.created_at.isoformat()}

@router.get("/providers/templates/{provider_type}", summary="Get config template for a provider type")
async def get_template(provider_type: IdentityProviderType, _=Depends(get_current_user)):
    return ok(await identity_provider_service.get_config_template(provider_type), f"Template for {provider_type.value}")

@router.post("/providers", summary="Configure an identity provider [Admin]")
async def configure_provider(body: ConfigureProviderRequest, db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    p = await identity_provider_service.configure(db, body.name, body.provider_type, body.config, body.group_mappings, body.role_mappings, body.namespace_mappings, admin.id)
    return created(_pd(p), f"Identity provider '{body.name}' configured")

@router.get("/providers", summary="List identity providers [Admin]")
async def list_providers(db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    providers = await identity_provider_service.list_providers(db)
    return ok([_pd(p) for p in providers], f"{len(providers)} providers")

@router.post("/providers/{provider_id}/enable", summary="Enable an identity provider [Admin]")
async def enable_provider(provider_id: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    p = await identity_provider_service.enable(db, provider_id)
    return ok({"name": p.name, "is_enabled": True}, f"Provider '{p.name}' enabled")

@router.post("/providers/{provider_id}/disable", summary="Disable an identity provider [Admin]")
async def disable_provider(provider_id: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    p = await identity_provider_service.disable(db, provider_id)
    return ok({"name": p.name, "is_enabled": False}, f"Provider '{p.name}' disabled")

@router.post("/providers/{provider_id}/test", summary="Test provider connection [Admin]")
async def test_connection(provider_id: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    return ok(await identity_provider_service.test_connection(db, provider_id), "Connection test complete")

@router.post("/providers/{provider_id}/sync", summary="Sync users and groups [Admin]")
async def sync_provider(provider_id: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    return ok(await identity_provider_service.sync(db, provider_id), "Sync complete")

@router.patch("/providers/{provider_id}/mappings", summary="Update group/role/namespace mappings [Admin]")
async def update_mappings(provider_id: uuid.UUID, body: UpdateMappingsRequest, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    p = await identity_provider_service.update_mappings(db, provider_id, body.group_mappings, body.role_mappings, body.namespace_mappings)
    return ok(_pd(p), "Mappings updated")
