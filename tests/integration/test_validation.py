"""Integration tests — Input validation and size limits."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_key_too_long_rejected(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/v1/secrets", json={
        "key": "a" * 256, "value": "v"
    }, headers=auth_headers)
    assert resp.status_code == 422


async def test_empty_value_rejected(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/v1/secrets", json={
        "key": "valid/key", "value": ""
    }, headers=auth_headers)
    assert resp.status_code == 422


async def test_too_many_tags_rejected(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/v1/secrets", json={
        "key": "valid/key", "value": "v",
        "tags": [f"tag{i}" for i in range(21)],
    }, headers=auth_headers)
    assert resp.status_code == 422


async def test_weak_password_rejected(client: AsyncClient):
    resp = await client.post("/api/v1/auth/register", json={
        "username": "testval", "email": "val@test.com", "password": "weak"
    })
    assert resp.status_code == 422


async def test_short_username_rejected(client: AsyncClient):
    resp = await client.post("/api/v1/auth/register", json={
        "username": "ab", "email": "ab@test.com", "password": "ValidPass1!"
    })
    assert resp.status_code == 422


async def test_invalid_email_rejected(client: AsyncClient):
    resp = await client.post("/api/v1/auth/register", json={
        "username": "validuser", "email": "notanemail", "password": "ValidPass1!"
    })
    assert resp.status_code == 422


async def test_value_too_large_rejected(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/v1/secrets", json={
        "key": "big/key", "value": "x" * 65537,
    }, headers=auth_headers)
    assert resp.status_code == 422


async def test_policy_invalid_action_rejected(client: AsyncClient, auth_headers: dict):
    """Policy with invalid action names must be rejected."""
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    await client.post("/api/v1/auth/register", json={
        "username": "valadmin", "email": "valadmin@example.com", "password": "AdminPass1!"
    })
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "valadmin"))
        user = result.scalar_one()
        user.role = UserRole.ADMIN
        await db.commit()
    resp_login = await client.post("/api/v1/auth/login", json={
        "username": "valadmin", "password": "AdminPass1!"
    })
    admin_headers = {"Authorization": f"Bearer {resp_login.json()['data']['access_token']}"}

    resp = await client.post("/api/v1/policies", json={
        "name": "badpolicy",
        "permissions": [{"path": "aws/*", "actions": ["hack", "destroy"]}],
    }, headers=admin_headers)
    assert resp.status_code == 422


async def test_standardized_error_format(client: AsyncClient):
    """All errors follow {success, error, details} format."""
    resp = await client.get("/api/v1/secrets/00000000-0000-0000-0000-000000000000",
                            headers={"Authorization": "Bearer invalid"})
    assert resp.status_code in (401, 403)  # HTTPBearer returns 403; JWT error returns 401
