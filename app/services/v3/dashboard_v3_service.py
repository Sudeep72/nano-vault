"""Enterprise Dashboard v3 additions — Transit, PKI, Cluster, Storage, Scheduler sections."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.models import (
    TransitKey, TransitKeyVersion, TransitKeyStatus,
    CertificateAuthority, Certificate, CertificateStatus, CertificateType,
    VaultSealState, AutoUnsealProvider, IdentityProvider,
    PolicyFile, AuditLog, AuditAction,
)


class DashboardV3Service:

    @staticmethod
    async def get_transit_stats(db: AsyncSession) -> dict:
        async def cnt(model, *cond):
            q = select(func.count()).select_from(model)
            for c in cond: q = q.where(c)
            return (await db.execute(q)).scalar_one()

        return {
            "active_keys": await cnt(TransitKey, TransitKey.status == TransitKeyStatus.ACTIVE),
            "disabled_keys": await cnt(TransitKey, TransitKey.status == TransitKeyStatus.DISABLED),
            "total_key_versions": await cnt(TransitKeyVersion),
            "exportable_keys": await cnt(TransitKey, TransitKey.exportable == True),  # noqa
            "encrypt_operations": await cnt(AuditLog, AuditLog.resource_type == "transit_encrypt"),
            "decrypt_operations": await cnt(AuditLog, AuditLog.resource_type == "transit_decrypt"),
        }

    @staticmethod
    async def get_pki_stats(db: AsyncSession) -> dict:
        async def cnt(model, *cond):
            q = select(func.count()).select_from(model)
            for c in cond: q = q.where(c)
            return (await db.execute(q)).scalar_one()

        soon = datetime.now(timezone.utc) + timedelta(days=30)
        return {
            "root_cas": await cnt(CertificateAuthority, CertificateAuthority.ca_type == CertificateType.ROOT_CA),
            "intermediate_cas": await cnt(CertificateAuthority, CertificateAuthority.ca_type == CertificateType.INTERMEDIATE_CA),
            "total_certificates": await cnt(Certificate),
            "valid_certificates": await cnt(Certificate, Certificate.status == CertificateStatus.VALID),
            "revoked_certificates": await cnt(Certificate, Certificate.status == CertificateStatus.REVOKED),
            "expiring_within_30_days": await cnt(Certificate, Certificate.status == CertificateStatus.VALID, Certificate.not_after < soon),
        }

    @staticmethod
    async def get_seal_stats(db: AsyncSession) -> dict:
        state = (await db.execute(select(VaultSealState))).scalar_one_or_none()
        providers = (await db.execute(select(AutoUnsealProvider))).scalars().all()
        return {
            "initialized": state.initialized if state else False,
            "sealed": (state.status.value == "sealed") if state else True,
            "auto_unseal_providers": len(providers),
            "active_provider": next((p.name for p in providers if p.is_active), None),
        }

    @staticmethod
    async def get_identity_stats(db: AsyncSession) -> dict:
        providers = (await db.execute(select(IdentityProvider))).scalars().all()
        by_type: dict[str, int] = {}
        for p in providers:
            by_type[p.provider_type.value] = by_type.get(p.provider_type.value, 0) + 1
        return {
            "total_providers": len(providers),
            "enabled_providers": len([p for p in providers if p.is_enabled]),
            "by_type": by_type,
        }

    @staticmethod
    async def get_policy_as_code_stats(db: AsyncSession) -> dict:
        files = (await db.execute(select(PolicyFile))).scalars().all()
        return {
            "total_policy_files": len(files),
            "active_policy_files": len([f for f in files if f.is_active]),
        }


dashboard_v3_service = DashboardV3Service()
