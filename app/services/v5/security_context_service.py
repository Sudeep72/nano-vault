"""
Security Context Layer — NanoVault v5.0

Composes EXISTING v1-v4 services to gather security signals. This module
does not query the database directly for anything RBAC/namespace-sensitive —
it calls the same service functions a human-driven endpoint would, so
authorization is inherited by construction rather than reimplemented.

Every dict returned from here has already had forbidden fields stripped
(guardrails_service.strip_forbidden_fields) before it's handed to the
AI layer. Redaction of the final serialized string happens one step
later, in guardrails_service.build_full_context.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.v5.guardrails_service import strip_forbidden_fields

_now = lambda: datetime.now(timezone.utc)


class SecurityContextService:

    @staticmethod
    async def gather_audit_context(
        db: AsyncSession, current_user, since: Optional[datetime] = None, limit: int = 50,
    ) -> list[dict]:
        """
        Reuses v4's live_audit_stream_service, which already scopes by
        user_id when the caller isn't an admin — see
        app/api/v4/endpoints/replay.py for the same pattern used by a
        human-facing endpoint.
        """
        from app.services.v4.replay_service import live_audit_stream_service
        from app.models.models import UserRole

        user_id = None if current_user.role == UserRole.ADMIN else current_user.id
        result = await live_audit_stream_service.get_recent_events(
            db, since=since, limit=limit, user_id=user_id,
        )
        return [strip_forbidden_fields(e) for e in result["events"]]

    @staticmethod
    async def gather_architecture_context(component_id: Optional[str] = None) -> list[dict]:
        """
        Reuses v4's architecture_service — already pure metadata (API
        paths, table names, descriptions), nothing secret-shaped exists
        in this data source by design.
        """
        from app.services.v4.architecture_service import architecture_service
        if component_id:
            node = architecture_service.get_node(component_id)
            return [strip_forbidden_fields(node)] if node else []
        return [strip_forbidden_fields(n) for n in architecture_service.get_full_graph()["nodes"]]

    @staticmethod
    async def gather_policy_context(db: AsyncSession, current_user) -> list[dict]:
        """Policy permissions are metadata, not secrets — safe to include
        the actual rule set so the model can reason about what's allowed."""
        from app.services.policy_service import policy_service
        policies = await policy_service.list_all(db)
        return [strip_forbidden_fields({
            "name": p.name, "description": p.description, "permissions": p.permissions,
        }) for p in policies]

    @staticmethod
    async def gather_secret_metadata_context(db: AsyncSession, current_user, namespace: Optional[str] = None) -> list[dict]:
        """
        Explicitly metadata-only. Calls secret_service.search (the same
        function GET /api/v1/secrets uses) which already never returns the
        decrypted `value` field on list operations — this function
        additionally strips forbidden fields as defense in depth.
        """
        from app.services.secret_service import secret_service
        from app.schemas.schemas import SecretSearchRequest
        req = SecretSearchRequest(page=1, page_size=100)
        items, _total = await secret_service.search(db, current_user, req)
        return [strip_forbidden_fields({
            "key": s.key, "category": s.category, "tags": s.tags,
            "version": s.version, "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        }) for s in items]

    @staticmethod
    async def gather_identity_context(db: AsyncSession) -> list[dict]:
        from app.services.v3.identity_provider_service import identity_provider_service
        providers = await identity_provider_service.list_providers(db)
        return [strip_forbidden_fields({
            "name": p.name, "type": p.provider_type.value, "is_enabled": p.is_enabled,
        }) for p in providers]

    @staticmethod
    async def gather_replay_context(db: AsyncSession, session_id: str) -> list[dict]:
        """Reuses v4's replay_service directly — this is exactly the data
        Step 4 of the spec asks for ('replay events') with zero new code."""
        from app.services.v4.replay_service import replay_service
        timeline = await replay_service.get_replay_timeline(db, session_id)
        return [strip_forbidden_fields(e) for e in timeline]

    @staticmethod
    async def gather_health_context(db: AsyncSession) -> dict:
        from app.services.v3.alerting_service import alerting_service
        return strip_forbidden_fields(await alerting_service.get_dependency_health(db))

    @staticmethod
    async def build_context_for_event(db: AsyncSession, current_user, audit_log_id: uuid.UUID) -> dict:
        """
        Investigation-focused bundle for Step 5/Step 8 — everything
        relevant to explaining ONE event: the event itself, surrounding
        timeline, and current architecture/policy state.
        """
        from sqlalchemy import select
        from app.models.models import AuditLog
        from app.models.models import UserRole

        log = (await db.execute(select(AuditLog).where(AuditLog.id == audit_log_id))).scalar_one_or_none()
        if not log:
            return {"error": "Event not found"}
        if current_user.role != UserRole.ADMIN and log.user_id != current_user.id:
            return {"error": "Not authorized to view this event"}

        window_start = log.created_at - timedelta(minutes=15)
        window_end = log.created_at + timedelta(minutes=15)
        surrounding = await SecurityContextService.gather_audit_context(db, current_user, since=window_start, limit=30)
        surrounding = [e for e in surrounding if e.get("timestamp", "") <= window_end.isoformat()]

        return {
            "target_event": strip_forbidden_fields({
                "action": log.action.value, "resource_type": log.resource_type,
                "resource_id": log.resource_id, "success": log.success,
                "ip_address": log.ip_address, "timestamp": log.created_at.isoformat(),
            }),
            "surrounding_timeline": surrounding,
            "architecture_context": await SecurityContextService.gather_architecture_context(log.resource_type),
        }


security_context_service = SecurityContextService()
