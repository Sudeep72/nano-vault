"""Integration tests — Enterprise Demo Mode."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"demoadm_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "DemoAdmin123!"})
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "DemoAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}


async def test_load_demo_dataset(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v4/demo/load", headers=admin)
    assert r.status_code == 201
    data = r.json()["data"]
    assert data["records_created"]["orgs"] >= 0
    assert data["records_created"]["secrets"] > 0


async def test_demo_load_idempotent(client: AsyncClient):
    admin = await _admin(client)
    r1 = await client.post("/api/v4/demo/load", headers=admin)
    r2 = await client.post("/api/v4/demo/load", headers=admin)
    assert r1.status_code == 201
    assert r2.status_code == 201  # second load doesn't crash on duplicates


async def test_demo_history(client: AsyncClient):
    admin = await _admin(client)
    await client.post("/api/v4/demo/load", headers=admin)
    r = await client.get("/api/v4/demo/history", headers=admin)
    assert len(r.json()["data"]) >= 1


async def test_demo_reset_report(client: AsyncClient):
    admin = await _admin(client)
    load = await client.post("/api/v4/demo/load", headers=admin)
    dataset_id = load.json()["data"]["dataset_id"]
    r = await client.post(f"/api/v4/demo/reset/{dataset_id}", headers=admin)
    assert r.status_code == 200
    assert "demo_secrets_found" in r.json()["data"]


async def test_non_admin_cannot_load_demo(client: AsyncClient, auth_headers):
    r = await client.post("/api/v4/demo/load", headers=auth_headers)
    assert r.status_code == 403
