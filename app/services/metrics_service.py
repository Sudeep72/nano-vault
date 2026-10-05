"""Metrics service — aggregate statistics for the /metrics endpoint."""
import time
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.models import User, Secret, AuditLog, AuditAction, Policy, SecretStatus

_START_TIME = time.time()


class MetricsService:

    @staticmethod
    def uptime_seconds() -> float:
        return round(time.time() - _START_TIME, 2)

    @staticmethod
    async def collect(db: AsyncSession) -> dict:
        async def count(model, *conditions):
            q = select(func.count()).select_from(model)
            for c in conditions:
                q = q.where(c)
            return (await db.execute(q)).scalar_one()

        async def audit_count(action: AuditAction):
            return await count(AuditLog, AuditLog.action == action)

        return {
            "total_users": await count(User),
            "active_users": await count(User, User.is_active == True),  # noqa
            "total_secrets": await count(Secret),
            "active_secrets": await count(Secret, Secret.is_deleted == False),  # noqa
            "deleted_secrets": await count(Secret, Secret.is_deleted == True),  # noqa
            "total_audit_events": await count(AuditLog),
            "secret_reads": await audit_count(AuditAction.SECRET_READ),
            "secret_writes": await audit_count(AuditAction.SECRET_CREATE),
            "secret_updates": await audit_count(AuditAction.SECRET_UPDATE),
            "secret_deletes": await audit_count(AuditAction.SECRET_DELETE),
            "successful_logins": await audit_count(AuditAction.USER_LOGIN),
            "failed_logins": await audit_count(AuditAction.USER_LOGIN_FAILED),
            "total_policies": await count(Policy),
        }


metrics_service = MetricsService()
