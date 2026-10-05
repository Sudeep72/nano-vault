"""Integration tests — Secret Access Replay + Live Audit Stream."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"replayadm_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "ReplayAdmin123!"})
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "ReplayAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}


async def test_create_replay_session(client: AsyncClient, auth_headers):
    admin = await _admin(client)
    await client.post("/api/v1/secrets", json={"key": "replay/test1", "value": "v1"}, headers=auth_headers)
    r = await client.post("/api/v4/replay/sessions", json={"limit": 50}, headers=admin)
    assert r.status_code == 201
    assert "session_id" in r.json()["data"]


async def test_replay_timeline_ordered(client: AsyncClient, auth_headers):
    admin = await _admin(client)
    await client.post("/api/v1/secrets", json={"key": "replay/ordered1", "value": "v1"}, headers=auth_headers)
    await client.post("/api/v1/secrets", json={"key": "replay/ordered2", "value": "v2"}, headers=auth_headers)
    create = await client.post("/api/v4/replay/sessions", json={"limit": 100}, headers=admin)
    session_id = create.json()["data"]["session_id"]

    timeline = await client.get(f"/api/v4/replay/sessions/{session_id}/timeline", headers=auth_headers)
    events = timeline.json()["data"]
    sequences = [e["sequence"] for e in events]
    assert sequences == sorted(sequences)


async def test_replay_seek(client: AsyncClient, auth_headers):
    admin = await _admin(client)
    await client.post("/api/v1/secrets", json={"key": "replay/seek1", "value": "v1"}, headers=auth_headers)
    create = await client.post("/api/v4/replay/sessions", json={"limit": 50}, headers=admin)
    session_id = create.json()["data"]["session_id"]
    r = await client.get(f"/api/v4/replay/sessions/{session_id}/seek/0", headers=auth_headers)
    assert r.status_code == 200


async def test_replay_seek_out_of_range(client: AsyncClient, auth_headers):
    admin = await _admin(client)
    create = await client.post("/api/v4/replay/sessions", json={"limit": 5}, headers=admin)
    session_id = create.json()["data"]["session_id"]
    r = await client.get(f"/api/v4/replay/sessions/{session_id}/seek/99999", headers=auth_headers)
    assert r.status_code == 404


async def test_non_admin_cannot_create_replay(client: AsyncClient, auth_headers):
    r = await client.post("/api/v4/replay/sessions", json={"limit": 10}, headers=auth_headers)
    assert r.status_code == 403


async def test_recent_audit_stream(client: AsyncClient, auth_headers):
    await client.post("/api/v1/secrets", json={"key": "audit-stream/e1", "value": "v1"}, headers=auth_headers)
    r = await client.get("/api/v4/audit-stream/recent", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["data"]["count"] >= 1


async def test_audit_stream_breakdown(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/audit-stream/breakdown", headers=auth_headers)
    assert r.status_code == 200
    assert "breakdown" in r.json()["data"]
