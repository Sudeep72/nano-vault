"""Enterprise Dashboard Service — NanoVault v2.0 Enterprise Hardening"""
from __future__ import annotations
import time
from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.models import (
    User, Secret, AuditLog, AuditAction, VaultToken, TokenStatus, TokenType,
    Lease, LeaseStatus, DynamicCredential, RotationHistory,
    SecretVersion, Organization, Project, Team, Namespace,
    WrappedToken, CubbyholeEntry, MFAConfig, Policy, EngineMount, EngineStatus,
)

_START = time.time()


class DashboardService:

    @staticmethod
    def uptime() -> float:
        return round(time.time() - _START, 2)

    @staticmethod
    async def get_dashboard(db: AsyncSession) -> dict:
        now = datetime.now(timezone.utc)
        soon = now + timedelta(hours=24)

        async def cnt(model, *conditions):
            q = select(func.count()).select_from(model)
            for c in conditions:
                q = q.where(c)
            return (await db.execute(q)).scalar_one()

        async def audit_cnt(action):
            return await cnt(AuditLog, AuditLog.action == action)

        return {
            "authentication": {
                "total_users": await cnt(User),
                "active_users": await cnt(User, User.is_active == True),  # noqa
                "mfa_enabled_users": await cnt(MFAConfig),
                "active_vault_tokens": await cnt(VaultToken, VaultToken.status == TokenStatus.ACTIVE, VaultToken.expires_at > now),
                "active_sessions": await cnt(VaultToken, VaultToken.status == TokenStatus.ACTIVE),
                "service_accounts": 0,
                "tokens_by_type": {
                    "service": await cnt(VaultToken, VaultToken.token_type == TokenType.SERVICE),
                    "batch": await cnt(VaultToken, VaultToken.token_type == TokenType.BATCH),
                    "periodic": await cnt(VaultToken, VaultToken.token_type == TokenType.PERIODIC),
                    "orphan": await cnt(VaultToken, VaultToken.token_type == TokenType.ORPHAN),
                    "revoked": await cnt(VaultToken, VaultToken.status == TokenStatus.REVOKED),
                },
            },
            "secrets": {
                "total_secrets": await cnt(Secret),
                "active_secrets": await cnt(Secret, Secret.is_deleted == False),  # noqa
                "deleted_secrets": await cnt(Secret, Secret.is_deleted == True),  # noqa
                "archived_secrets": 0,
                "total_versions": await cnt(SecretVersion),
                "rotation_enabled": await cnt(Secret, Secret.rotation_enabled == True, Secret.is_deleted == False),  # noqa
                "total_rotations": await cnt(RotationHistory),
                "expiring_soon": await cnt(Secret, Secret.expires_at != None, Secret.expires_at < soon, Secret.is_deleted == False),  # noqa
            },
            "dynamic_secrets": {
                "active_credentials": await cnt(DynamicCredential, DynamicCredential.revoked == False, DynamicCredential.expires_at > now),  # noqa
                "active_leases": await cnt(Lease, Lease.status == LeaseStatus.ACTIVE, Lease.expires_at > now),
                "expiring_leases": await cnt(Lease, Lease.status == LeaseStatus.ACTIVE, Lease.expires_at < soon, Lease.expires_at > now),
                "expired_leases": await cnt(Lease, Lease.status == LeaseStatus.EXPIRED),
                "renewed_leases": await cnt(Lease, Lease.status == LeaseStatus.RENEWED),
                "revoked_leases": await cnt(Lease, Lease.status == LeaseStatus.REVOKED),
                "total_leases": await cnt(Lease),
            },
            "security": {
                "total_audit_events": await cnt(AuditLog),
                "failed_logins": await audit_cnt(AuditAction.USER_LOGIN_FAILED),
                "successful_logins": await audit_cnt(AuditAction.USER_LOGIN),
                "mfa_verifications": await audit_cnt(AuditAction.MFA_VERIFIED),
                "wrapped_tokens_created": await audit_cnt(AuditAction.WRAP_CREATE),
                "cubbyhole_reads": await audit_cnt(AuditAction.CUBBYHOLE_READ),
                "policy_denials": await audit_cnt(AuditAction.SECRET_ACCESS_DENIED),
            },
            "policy_engine": {
                "total_policies": await cnt(Policy),
                "builtin_policies": await cnt(Policy, Policy.is_builtin == True),  # noqa
                "custom_policies": await cnt(Policy, Policy.is_builtin == False),  # noqa
                "policies_with_parents": await cnt(Policy, Policy.parent_policy_id != None),  # noqa
            },
            "secrets_engines": {
                "total_registered": await cnt(EngineMount),
                "enabled": await cnt(EngineMount, EngineMount.status == EngineStatus.ENABLED),
                "mounted": await cnt(EngineMount, EngineMount.status == EngineStatus.MOUNTED),
                "disabled": await cnt(EngineMount, EngineMount.status == EngineStatus.DISABLED),
            },
            "administration": {
                "organizations": await cnt(Organization),
                "projects": await cnt(Project),
                "teams": await cnt(Team),
                "total_namespaces": await cnt(Namespace),
                "active_namespaces": await cnt(Namespace),
            },
            "uptime_seconds": DashboardService.uptime(),
            "version": "2.0",
        }


dashboard_service = DashboardService()
