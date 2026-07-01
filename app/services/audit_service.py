"""Audit Engine v1.0.1 — structured, append-only event log."""
import uuid
import time
import logging
from typing import Optional
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.models import AuditLog, AuditAction

logger = logging.getLogger("nano_vault.audit")


class AuditService:

    @staticmethod
    async def log(
        db: AsyncSession,
        action: AuditAction,
        *,
        user_id: Optional[uuid.UUID] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        success: bool = True,
        request: Optional[Request] = None,
        metadata: Optional[dict] = None,
        execution_time_ms: Optional[int] = None,
        status_code: Optional[int] = None,
    ) -> AuditLog:
        ip = ua = endpoint = None
        if request:
            fwd = request.headers.get("X-Forwarded-For")
            ip = fwd.split(",")[0].strip() if fwd else (
                request.client.host if request.client else None
            )
            ua = request.headers.get("User-Agent")
            endpoint = str(request.url.path)

        log = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            ip_address=ip,
            user_agent=ua,
            endpoint=endpoint,
            execution_time_ms=execution_time_ms,
            status_code=status_code,
            success=success,
            extra_data=metadata,
        )
        db.add(log)
        await db.flush()

        # Structured log line
        logger.info(
            "AUDIT",
            extra={
                "action": action.value,
                "user_id": str(user_id) if user_id else None,
                "resource": f"{resource_type}/{resource_id}" if resource_type else None,
                "ip": ip,
                "success": success,
                "endpoint": endpoint,
                "exec_ms": execution_time_ms,
            },
        )
        return log

    @staticmethod
    async def get_logs(
        db: AsyncSession,
        *,
        user_id: Optional[uuid.UUID] = None,
        action: Optional[AuditAction] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[AuditLog], int]:
        query = select(AuditLog)
        if user_id:
            query = query.where(AuditLog.user_id == user_id)
        if action:
            query = query.where(AuditLog.action == action)

        total = (await db.execute(
            select(func.count()).select_from(query.subquery())
        )).scalar_one()

        query = query.order_by(AuditLog.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)
        return (await db.execute(query)).scalars().all(), total


audit_service = AuditService()
