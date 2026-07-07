"""Integration tests — Enterprise Dashboard."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _make_admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    await client.post("/api/v1/auth/register", json={
        "username": "dashadmin", "email": "dashadmin@nano.com", "password": "DashAdmin123!"
    })
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.username == "dashadmin"))).scalar_one()
        user.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": "dashadmin", "password": "DashAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}


async def test_dashboard_requires_admin(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/v2/dashboard", headers=auth_headers)
    assert resp.status_code == 403


async def test_dashboard_structure(client: AsyncClient):
    admin = await _make_admin(client)
    resp = await client.get("/api/v2/dashboard", headers=admin)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert "authentication" in data
    assert "secrets" in data
    assert "dynamic_secrets" in data
    assert "security" in data
    assert "administration" in data
    assert "uptime_seconds" in data
    assert data["version"] == "2.0"


async def test_dashboard_counts_users(client: AsyncClient, registered_user: dict):
    admin = await _make_admin(client)
    resp = await client.get("/api/v2/dashboard", headers=admin)
    data = resp.json()["data"]
    assert data["authentication"]["total_users"] >= 1


async def test_dashboard_counts_secrets(client: AsyncClient, auth_headers: dict):
    admin = await _make_admin(client)
    await client.post("/api/v1/secrets", json={"key": "dash/test", "value": "v"}, headers=auth_headers)
    resp = await client.get("/api/v2/dashboard", headers=admin)
    data = resp.json()["data"]
    assert data["secrets"]["total_secrets"] >= 1
    assert data["secrets"]["active_secrets"] >= 1


async def test_dashboard_counts_dynamic_secrets(client: AsyncClient, auth_headers: dict):
    admin = await _make_admin(client)
    await client.post("/api/v2/dynamic/generate", json={
        "credential_type": "app_api_key", "ttl_seconds": 3600,
    }, headers=auth_headers)
    resp = await client.get("/api/v2/dashboard", headers=admin)
    data = resp.json()["data"]
    assert data["dynamic_secrets"]["active_leases"] >= 1
    assert data["dynamic_secrets"]["active_credentials"] >= 1


async def test_dashboard_uptime_positive(client: AsyncClient):
    admin = await _make_admin(client)
    resp = await client.get("/api/v2/dashboard", headers=admin)
    assert resp.json()["data"]["uptime_seconds"] >= 0
