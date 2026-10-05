"""Integration tests — Engine Registry Management."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"engadmin_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={
        "username": uname, "email": f"{uname}@nano.com", "password": "EngAdmin123!"
    })
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "EngAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}


async def test_list_engines_returns_defaults(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/v2/engines", headers=auth_headers)
    assert resp.status_code == 200
    names = [e["name"] for e in resp.json()["data"]]
    assert "kv" in names
    assert "dynamic" in names
    assert "cubbyhole" in names
    assert "transit" in names   # reserved/disabled
    assert "pki" in names       # reserved/disabled


async def test_get_engine_detail(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/v2/engines/kv", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["name"] == "kv"
    assert data["mount_path"] == "secret/"
    assert data["status"] in ("enabled", "mounted")
    assert data["available_in_runtime"] is True


async def test_disabled_engine_shows_correctly(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/v2/engines/ssh", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["status"] == "disabled"
    assert data["available_in_runtime"] is False


async def test_enable_and_disable_engine(client: AsyncClient):
    admin = await _admin(client)
    # Enable dynamic (in case it's disabled)
    en = await client.post("/api/v2/engines/dynamic/enable", headers=admin)
    assert en.status_code == 200
    assert en.json()["data"]["status"] == "enabled"

    # Disable dynamic
    dis = await client.post("/api/v2/engines/dynamic/disable", headers=admin)
    assert dis.status_code == 200
    assert dis.json()["data"]["status"] == "disabled"

    # Re-enable
    await client.post("/api/v2/engines/dynamic/enable", headers=admin)


async def test_cannot_disable_kv(client: AsyncClient):
    admin = await _admin(client)
    resp = await client.post("/api/v2/engines/kv/disable", headers=admin)
    assert resp.status_code == 400


async def test_cannot_disable_cubbyhole(client: AsyncClient):
    admin = await _admin(client)
    resp = await client.post("/api/v2/engines/cubbyhole/disable", headers=admin)
    assert resp.status_code == 400


async def test_mount_engine(client: AsyncClient):
    admin = await _admin(client)
    resp = await client.post("/api/v2/engines/dynamic/mount",
                             json={"mount_path": "dynamic/v2/"}, headers=admin)
    assert resp.status_code == 200
    assert resp.json()["data"]["status"] == "mounted"


async def test_reload_engine(client: AsyncClient):
    admin = await _admin(client)
    await client.post("/api/v2/engines/kv/enable", headers=admin)
    resp = await client.post("/api/v2/engines/kv/reload", headers=admin)
    assert resp.status_code == 200


async def test_unknown_engine_404(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/v2/engines/nonexistent", headers=auth_headers)
    assert resp.status_code == 404
