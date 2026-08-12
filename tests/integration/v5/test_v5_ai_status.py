"""Integration tests — AI status/health endpoints. AI_ENABLED=false by default (verified real default)."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"aiadm_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "AiAdmin123!"})
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "AiAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}


async def test_ai_status_default_disabled(client: AsyncClient, auth_headers):
    """Confirms Step 10's 'default to disabled' requirement holds in this
    test environment where GEMINI_API_KEY is never set."""
    r = await client.get("/api/v5/ai/status", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()["data"]
    assert data["enabled"] is False
    assert data["configured"] is False


async def test_ai_health_when_disabled(client: AsyncClient):
    admin = await _admin(client)
    r = await client.get("/api/v5/ai/health", headers=admin)
    assert r.status_code == 200
    assert r.json()["data"]["available"] is False


async def test_ai_health_requires_admin(client: AsyncClient, auth_headers):
    r = await client.get("/api/v5/ai/health", headers=auth_headers)
    assert r.status_code == 403


async def test_ai_status_no_auth_rejected(client: AsyncClient):
    r = await client.get("/api/v5/ai/status")
    assert r.status_code == 401
