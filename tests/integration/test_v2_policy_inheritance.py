"""Integration tests — Policy Inheritance + Effective Permissions."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"piadmin_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={
        "username": uname, "email": f"{uname}@nano.com", "password": "PiAdmin123!"
    })
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "PiAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}


async def test_admin_has_all_permissions(client: AsyncClient):
    admin = await _admin(client)
    resp = await client.get("/api/v2/policies/effective", headers=admin)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["role"] == "ADMIN"
    # Admin has wildcard allow
    assert "*" in data["allowed"]


async def test_user_no_policy_has_no_permissions(client: AsyncClient, registered_user: dict):
    # Register a fresh user with no policies
    import uuid
    uname = f"nopol_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={
        "username": uname, "email": f"{uname}@test.com", "password": "NoPolPass123!"
    })
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "NoPolPass123!"})
    headers = {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}
    eff = await client.get("/api/v2/policies/effective", headers=headers)
    assert eff.status_code == 200
    data = eff.json()["data"]
    # No policies assigned — no allowed paths
    assert data["allowed"] == {} or all(v == [] for v in data["allowed"].values())


async def test_effective_after_policy_assign(client: AsyncClient):
    admin = await _admin(client)
    import uuid
    uname = f"poluser_{uuid.uuid4().hex[:6]}"
    reg = await client.post("/api/v1/auth/register", json={
        "username": uname, "email": f"{uname}@test.com", "password": "PolPass123!"
    })
    user_id = reg.json()["data"]["id"]

    # Get readonly policy
    pols = await client.get("/api/v1/policies", headers=admin)
    readonly_id = next(p["id"] for p in pols.json()["data"] if p["name"] == "readonly")

    # Assign readonly
    await client.post("/api/v1/policies/assign", json={
        "user_id": user_id, "policy_id": readonly_id,
    }, headers=admin)

    user_resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "PolPass123!"})
    user_headers = {"Authorization": f"Bearer {user_resp.json()['data']['access_token']}"}

    eff = await client.get("/api/v2/policies/effective", headers=user_headers)
    assert eff.status_code == 200
    data = eff.json()["data"]
    # readonly policy allows read and list on *
    assert "*" in data["allowed"]
    assert "read" in data["allowed"]["*"]
    assert "list" in data["allowed"]["*"]
    assert "create" not in data["allowed"].get("*", [])


async def test_permission_check_endpoint(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/v2/policies/check?secret_key=aws/prod/key&action=read",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert "allowed" in data
    assert data["secret_key"] == "aws/prod/key"
    assert data["action"] == "read"


async def test_admin_permission_check_always_allowed(client: AsyncClient):
    admin = await _admin(client)
    resp = await client.post(
        "/api/v2/policies/check?secret_key=any/path&action=delete",
        headers=admin,
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["allowed"] is True


async def test_policy_inheritance_tree(client: AsyncClient, auth_headers: dict):
    # Get devops policy ID
    pols = (await client.get("/api/v1/policies", headers=auth_headers)).json()["data"]
    devops_id = next(p["id"] for p in pols if p["name"] == "devops")
    resp = await client.get(f"/api/v2/policies/{devops_id}/inheritance", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["policy"]["name"] == "devops"
    assert "parent_chain" in data
    assert "depth" in data
