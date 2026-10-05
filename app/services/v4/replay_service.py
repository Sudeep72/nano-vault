"""
Secret Access Replay + Live Audit Stream — NanoVault v4.0

Replay reconstructs a timeline from the real audit_logs table (which already
captures every action across auth/secrets/transit/pki/scheduler/engines).
This does not duplicate audit_service — it builds a queryable, seekable
snapshot on top of it for timeline scrubbing.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.models import AuditLog, AuditReplayEvent, User

_now = lambda: datetime.now(timezone.utc)

REPLAYABLE_ACTIONS = [
    "USER_LOGIN", "USER_LOGIN_FAILED", "SECRET_CREATE", "SECRET_READ",
    "SECRET_UPDATE", "SECRET_ROTATE", "SECRET_DELETE",
    "VAULT_TOKEN_CREATE", "VAULT_TOKEN_RENEW", "VAULT_TOKEN_REVOKE",
]


class ReplayService:

    @staticmethod
    async def create_replay_session(
        db: AsyncSession, since: Optional[datetime] = None, until: Optional[datetime] = None,
        user_id: Optional[uuid.UUID] = None, limit: int = 200,
    ) -> dict:
        """Builds a replay session from real audit_logs rows, in chronological order."""
        session_id = str(uuid.uuid4())
        q = select(AuditLog).order_by(AuditLog.created_at.asc()).limit(limit)
        if since:
            q = q.where(AuditLog.created_at >= since)
        if until:
            q = q.where(AuditLog.created_at <= until)
        if user_id:
            q = q.where(AuditLog.user_id == user_id)

        logs = (await db.execute(q)).scalars().all()

        for i, log in enumerate(logs):
            db.add(AuditReplayEvent(
                audit_log_id=log.id, session_id=session_id, sequence=i,
                action=log.action.value if hasattr(log.action, "value") else str(log.action),
                actor=str(log.user_id) if log.user_id else None,
                resource=log.resource_id, namespace=str(log.namespace_id) if log.namespace_id else None,
                payload_summary={"resource_type": log.resource_type, "success": log.success,
                                 "status_code": log.status_code},
                original_timestamp=log.created_at,
            ))
        await db.flush()

        return {"session_id": session_id, "event_count": len(logs),
                "range": {"since": since.isoformat() if since else None,
                          "until": until.isoformat() if until else None}}

    @staticmethod
    async def get_replay_timeline(db: AsyncSession, session_id: str) -> list[dict]:
        events = (await db.execute(
            select(AuditReplayEvent).where(AuditReplayEvent.session_id == session_id)
            .order_by(AuditReplayEvent.sequence.asc())
        )).scalars().all()
        return [{
            "sequence": e.sequence, "action": e.action, "actor": e.actor,
            "resource": e.resource, "namespace": e.namespace,
            "payload_summary": e.payload_summary,
            "timestamp": e.original_timestamp.isoformat(),
        } for e in events]

    @staticmethod
    async def seek(db: AsyncSession, session_id: str, sequence: int) -> Optional[dict]:
        """Jump to a specific point in the replay timeline."""
        event = (await db.execute(
            select(AuditReplayEvent).where(
                AuditReplayEvent.session_id == session_id,
                AuditReplayEvent.sequence == sequence,
            )
        )).scalar_one_or_none()
        if not event:
            return None
        return {"sequence": event.sequence, "action": event.action, "actor": event.actor,
                "resource": event.resource, "timestamp": event.original_timestamp.isoformat()}

    @staticmethod
    async def search_replay(db: AsyncSession, session_id: str, action: Optional[str] = None,
                            actor: Optional[str] = None) -> list[dict]:
        q = select(AuditReplayEvent).where(AuditReplayEvent.session_id == session_id)
        if action:
            q = q.where(AuditReplayEvent.action == action)
        if actor:
            q = q.where(AuditReplayEvent.actor == actor)
        events = (await db.execute(q.order_by(AuditReplayEvent.sequence.asc()))).scalars().all()
        return [{"sequence": e.sequence, "action": e.action, "actor": e.actor,
                 "resource": e.resource, "timestamp": e.original_timestamp.isoformat()} for e in events]


class LiveAuditStreamService:
    """
    Real-time-ish audit stream. True push-based streaming (SSE/WebSocket)
    is a transport-layer concern; this provides the real polling-friendly
    query layer — "give me everything since timestamp X" — which is what
    an SSE endpoint or dashboard poll loop would call on an interval.
    """

    @staticmethod
    async def get_recent_events(
        db: AsyncSession, since: Optional[datetime] = None, limit: int = 50,
        severity: Optional[str] = None, namespace: Optional[str] = None,
        engine: Optional[str] = None, user_id: Optional[uuid.UUID] = None,
    ) -> dict:
        q = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
        if since:
            q = q.where(AuditLog.created_at > since)
        if namespace:
            q = q.where(AuditLog.namespace_id == namespace)
        if engine:
            q = q.where(AuditLog.resource_type == engine)
        if user_id:
            q = q.where(AuditLog.user_id == user_id)
        if severity == "critical":
            q = q.where(AuditLog.success == False)  # noqa

        logs = (await db.execute(q)).scalars().all()
        return {
            "events": [{
                "id": str(l.id), "action": l.action.value if hasattr(l.action, "value") else str(l.action),
                "user_id": str(l.user_id) if l.user_id else None,
                "resource_type": l.resource_type, "resource_id": l.resource_id,
                "success": l.success, "ip_address": l.ip_address,
                "timestamp": l.created_at.isoformat(),
            } for l in logs],
            "count": len(logs), "polled_at": _now().isoformat(),
        }

    @staticmethod
    async def get_event_type_breakdown(db: AsyncSession) -> dict:
        result = (await db.execute(
            select(AuditLog.action, func.count()).group_by(AuditLog.action)
        )).all()
        return {"breakdown": [{"action": a.value if hasattr(a, "value") else str(a), "count": c} for a, c in result]}


replay_service = ReplayService()
live_audit_stream_service = LiveAuditStreamService()
