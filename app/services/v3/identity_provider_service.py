from __future__ import annotations
import uuid
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException
from app.models.models import IdentityProvider, IdentityProviderType

def _now(): return datetime.now(timezone.utc)

_TEMPLATES = {
    IdentityProviderType.OIDC: {"required": ["issuer_url","client_id","client_secret"], "optional": ["scopes","redirect_uri","allowed_groups"]},
    IdentityProviderType.LDAP: {"required": ["ldap_url","bind_dn","bind_password","user_dn","group_dn"], "optional": ["user_attr","group_attr","tls"]},
    IdentityProviderType.ACTIVE_DIRECTORY: {"required": ["domain","server_url","bind_dn","bind_password"], "optional": ["user_ou","group_ou","tls"]},
    IdentityProviderType.JWT: {"required": ["jwks_url","issuer","audience"], "optional": ["bound_claims","role_claim","groups_claim"]},
    IdentityProviderType.SAML: {"required": ["idp_metadata_url","sp_entity_id","acs_url"], "optional": ["sign_requests","want_assertions_signed"]},
}

class IdentityProviderService:
    @staticmethod
    def _validate(pt, config):
        req = _TEMPLATES.get(pt, {}).get("required", [])
        return [k for k in req if k not in config]

    @staticmethod
    async def configure(db, name, provider_type, config, group_mappings=None, role_mappings=None, namespace_mappings=None, created_by=None):
        if (await db.execute(select(IdentityProvider).where(IdentityProvider.name==name))).scalar_one_or_none():
            raise HTTPException(409, f"'{name}' exists")
        missing = IdentityProviderService._validate(provider_type, config)
        if missing: raise HTTPException(422, f"Missing config for {provider_type.value}: {missing}")
        p = IdentityProvider(name=name, provider_type=provider_type, config=config,
            group_mappings=group_mappings or {}, role_mappings=role_mappings or {},
            namespace_mappings=namespace_mappings or {}, created_by=created_by)
        db.add(p); await db.flush(); return p

    @staticmethod
    async def enable(db, provider_id):
        p = (await db.execute(select(IdentityProvider).where(IdentityProvider.id==provider_id))).scalar_one_or_none()
        if not p: raise HTTPException(404, "Not found")
        p.is_enabled = True; p.updated_at = _now(); await db.flush(); return p

    @staticmethod
    async def disable(db, provider_id):
        p = (await db.execute(select(IdentityProvider).where(IdentityProvider.id==provider_id))).scalar_one_or_none()
        if not p: raise HTTPException(404, "Not found")
        p.is_enabled = False; p.updated_at = _now(); await db.flush(); return p

    @staticmethod
    async def test_connection(db, provider_id):
        p = (await db.execute(select(IdentityProvider).where(IdentityProvider.id==provider_id))).scalar_one_or_none()
        if not p: raise HTTPException(404, "Not found")
        sim = {IdentityProviderType.OIDC: "OIDC discovery reachable.", IdentityProviderType.LDAP: "LDAP bind successful.",
               IdentityProviderType.ACTIVE_DIRECTORY: "AD reachable.", IdentityProviderType.JWT: "JWKS reachable.",
               IdentityProviderType.SAML: "IdP metadata fetched."}
        return {"provider": p.name, "type": p.provider_type.value, "connected": True,
                "message": sim.get(p.provider_type, "Connected (simulated)"), "tested_at": _now().isoformat(),
                "note": "Simulated test. Real integration ships v3.1."}

    @staticmethod
    async def sync(db, provider_id):
        p = (await db.execute(select(IdentityProvider).where(IdentityProvider.id==provider_id))).scalar_one_or_none()
        if not p: raise HTTPException(404, "Not found")
        if not p.is_enabled: raise HTTPException(400, "Provider disabled")
        p.last_sync_at = _now(); await db.flush()
        return {"provider": p.name, "synced_at": p.last_sync_at.isoformat(), "users_synced": 0,
                "groups_synced": 0, "roles_assigned": 0, "note": "Simulated sync."}

    @staticmethod
    async def update_mappings(db, provider_id, group_mappings=None, role_mappings=None, namespace_mappings=None):
        p = (await db.execute(select(IdentityProvider).where(IdentityProvider.id==provider_id))).scalar_one_or_none()
        if not p: raise HTTPException(404, "Not found")
        if group_mappings is not None: p.group_mappings = group_mappings
        if role_mappings is not None: p.role_mappings = role_mappings
        if namespace_mappings is not None: p.namespace_mappings = namespace_mappings
        p.updated_at = _now(); await db.flush(); return p

    @staticmethod
    async def list_providers(db):
        return (await db.execute(select(IdentityProvider).order_by(IdentityProvider.name))).scalars().all()

    @staticmethod
    async def get_config_template(provider_type):
        t = _TEMPLATES.get(provider_type, {})
        return {"provider_type": provider_type.value, "required_fields": t.get("required", []), "optional_fields": t.get("optional", [])}

identity_provider_service = IdentityProviderService()
