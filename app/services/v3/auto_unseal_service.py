from __future__ import annotations
import uuid
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException
from app.models.models import AutoUnsealProvider, UnsealProviderType, VaultSealState, SealStatus

def _now(): return datetime.now(timezone.utc)

class _Base:
    def health_check(self, config): raise NotImplementedError
    def unseal(self, config, enc): raise NotImplementedError

class AWSKMS(_Base):
    def health_check(self, c):
        m = [k for k in ["region","key_id"] if k not in c]
        return (False, f"Missing: {m}") if m else (True, "AWS KMS simulated healthy")
    def unseal(self, c, enc): return f"SIM_AWS:{enc[:16]}"

class AzureKV(_Base):
    def health_check(self, c):
        m = [k for k in ["vault_url","key_name"] if k not in c]
        return (False, f"Missing: {m}") if m else (True, "Azure KV simulated healthy")
    def unseal(self, c, enc): return f"SIM_AZURE:{enc[:16]}"

class GCPKMS(_Base):
    def health_check(self, c):
        m = [k for k in ["project_id","key_ring","crypto_key"] if k not in c]
        return (False, f"Missing: {m}") if m else (True, "GCP KMS simulated healthy")
    def unseal(self, c, enc): return f"SIM_GCP:{enc[:16]}"

class LocalHSM(_Base):
    def health_check(self, c): return (True, "Local HSM simulated healthy")
    def unseal(self, c, enc): return f"SIM_HSM:{enc[:16]}"

_PROVIDERS = {
    UnsealProviderType.AWS_KMS: AWSKMS(), UnsealProviderType.AZURE_KEY_VAULT: AzureKV(),
    UnsealProviderType.GCP_KMS: GCPKMS(), UnsealProviderType.LOCAL_HSM: LocalHSM(),
}

class AutoUnsealService:
    @staticmethod
    async def configure(db, name, provider_type, config):
        if (await db.execute(select(AutoUnsealProvider).where(AutoUnsealProvider.name==name))).scalar_one_or_none():
            raise HTTPException(409, f"Provider '{name}' exists")
        provider = _PROVIDERS.get(provider_type)
        healthy, msg = provider.health_check(config) if provider else (False, "Unknown provider")
        p = AutoUnsealProvider(name=name, provider_type=provider_type, config=config, is_healthy=healthy, last_health_check=_now())
        db.add(p); await db.flush(); return p

    @staticmethod
    async def enable(db, provider_id):
        p = (await db.execute(select(AutoUnsealProvider).where(AutoUnsealProvider.id==provider_id))).scalar_one_or_none()
        if not p: raise HTTPException(404, "Provider not found")
        for ap in (await db.execute(select(AutoUnsealProvider))).scalars().all(): ap.is_active = False
        p.is_active = True; p.updated_at = _now(); await db.flush(); return p

    @staticmethod
    async def health_check(db, provider_id):
        p = (await db.execute(select(AutoUnsealProvider).where(AutoUnsealProvider.id==provider_id))).scalar_one_or_none()
        if not p: raise HTTPException(404, "Provider not found")
        provider = _PROVIDERS.get(p.provider_type)
        healthy, msg = provider.health_check(p.config or {}) if provider else (False, "Unknown")
        p.is_healthy = healthy; p.last_health_check = _now(); await db.flush()
        return {"provider": p.name, "type": p.provider_type.value, "healthy": healthy, "message": msg,
                "checked_at": p.last_health_check.isoformat()}

    @staticmethod
    async def auto_unseal(db):
        active = (await db.execute(select(AutoUnsealProvider).where(AutoUnsealProvider.is_active==True, AutoUnsealProvider.is_healthy==True))).scalar_one_or_none()
        if not active: raise HTTPException(400, "No active healthy provider configured")
        state = (await db.execute(select(VaultSealState))).scalar_one_or_none()
        if not state: raise HTTPException(400, "Vault not initialized")
        if state.status == SealStatus.UNSEALED:
            return {"sealed": False, "message": "Already unsealed", "provider": active.name}
        provider = _PROVIDERS.get(active.provider_type)
        provider.unseal(active.config or {}, state.encrypted_master_key or "")
        state.status = SealStatus.UNSEALED; state.unsealed_at = _now(); state.unseal_provider = active.name
        active.last_used_at = _now(); await db.flush()
        return {"sealed": False, "unsealed_at": state.unsealed_at.isoformat(), "provider": active.name,
                "provider_type": active.provider_type.value, "message": "Auto-unseal successful (simulated)"}

    @staticmethod
    async def list_providers(db):
        return (await db.execute(select(AutoUnsealProvider).order_by(AutoUnsealProvider.name))).scalars().all()

auto_unseal_service = AutoUnsealService()
