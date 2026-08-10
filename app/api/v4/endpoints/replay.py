"""Secret Access Replay + Live Audit Stream — NanoVault v4.0"""
from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok, created

router = APIRouter(tags=["Replay & Audit Stream"])


class CreateReplayRequest(BaseModel):
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    user_id: Optional[uuid.UUID] = None
    limit: int = 200


@router.post("/replay/sessions", summary="Create a replay session from real audit history [Admin]")
async def create_replay(body: CreateReplayRequest, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    from app.services.v4.replay_service import replay_service
    result = await replay_service.create_replay_session(db, body.since, body.until, body.user_id, body.limit)
    return created(result, "Replay session created")


@router.get("/replay/sessions/{session_id}/timeline", summary="Full replay timeline")
async def get_timeline(session_id: str, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.services.v4.replay_service import replay_service
    return ok(await replay_service.get_replay_timeline(db, session_id), "Replay timeline")


@router.get("/replay/sessions/{session_id}/seek/{sequence}", summary="Seek to a specific point in the replay")
async def seek(session_id: str, sequence: int, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.services.v4.replay_service import replay_service
    result = await replay_service.seek(db, session_id, sequence)
    if not result:
        from fastapi import HTTPException
        raise HTTPException(404, "Sequence not found in this replay session")
    return ok(result, f"Seeked to sequence {sequence}")


@router.get("/replay/sessions/{session_id}/search", summary="Search within a replay session")
async def search_replay(session_id: str, action: Optional[str] = None, actor: Optional[str] = None,
                        db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.services.v4.replay_service import replay_service
    return ok(await replay_service.search_replay(db, session_id, action, actor), "Search results")


# ── Live Audit Stream ──────────────────────────────────────────────────────────

@router.get("/audit-stream/recent", summary="Poll for recent audit events (real-time-ish via polling)")
async def recent_events(since: Optional[datetime] = None, limit: int = 50, severity: Optional[str] = None,
                        namespace: Optional[str] = None, engine: Optional[str] = None,
                        db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.services.v4.replay_service import live_audit_stream_service
    return ok(await live_audit_stream_service.get_recent_events(db, since, limit, severity, namespace, engine), "Recent audit events")


@router.get("/audit-stream/breakdown", summary="Audit event type breakdown")
async def event_breakdown(db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.services.v4.replay_service import live_audit_stream_service
    return ok(await live_audit_stream_service.get_event_type_breakdown(db), "Event breakdown")
