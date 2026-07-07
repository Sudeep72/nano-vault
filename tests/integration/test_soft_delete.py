"""Integration tests — Soft delete, restore, purge."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _make_admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    await client.post("/api/v1/auth/register", json={
        "username": "purgeadmin", "email": "purge@example.com", "password": "PurgePass1!"
    })
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "purgeadmin"))
        user = result.scalar_one()
        user.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": "purgeadmin", "password": "PurgePass1!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}


async def _create_secret(client, headers, key="test/key", value="testval"):
    resp = await client.post("/api/v1/secrets", json={"key": key, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["data"]


async def test_soft_delete_sets_deleted_flag(client: AsyncClient, auth_headers: dict):
    s = await _create_secret(client, auth_headers)
    del_resp = await client.delete(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    assert del_resp.status_code == 200
    # Should not appear in normal list
    lst = await client.get("/api/v1/secrets", headers=auth_headers)
    ids = [i["id"] for i in lst.json()["data"]["items"]]
    assert s["id"] not in ids


async def test_soft_delete_not_readable(client: AsyncClient, auth_headers: dict):
    s = await _create_secret(client, auth_headers, key="del/key")
    await client.delete(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    resp = await client.get(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    assert resp.status_code == 404


async def test_restore_secret(client: AsyncClient, auth_headers: dict):
    s = await _create_secret(client, auth_headers, key="restore/key")
    await client.delete(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    # Restore
    resp = await client.post(f"/api/v1/secrets/{s['id']}/restore", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["status"] == "active"
    # Now readable again
    read = await client.get(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    assert read.status_code == 200


async def test_restore_conflict(client: AsyncClient, auth_headers: dict):
    """Cannot restore if active secret with same key already exists."""
    s = await _create_secret(client, auth_headers, key="conflict/key")
    await client.delete(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    # Create new secret with same key
    await _create_secret(client, auth_headers, key="conflict/key")
    resp = await client.post(f"/api/v1/secrets/{s['id']}/restore", headers=auth_headers)
    assert resp.status_code == 409


async def test_purge_permanent(client: AsyncClient, auth_headers: dict):
    admin = await _make_admin(client)
    s = await _create_secret(client, auth_headers, key="purge/key")
    await client.delete(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    # Admin purge
    resp = await client.delete(f"/api/v1/secrets/admin/{s['id']}/purge", headers=admin)
    assert resp.status_code == 200
    # Cannot restore after purge
    resp2 = await client.post(f"/api/v1/secrets/{s['id']}/restore", headers=auth_headers)
    assert resp2.status_code == 404
