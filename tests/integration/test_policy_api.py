"""Integration tests — Policy Engine API."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _admin_headers(client: AsyncClient) -> dict:
    """Register an admin user and return auth headers."""
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select

    # Register via API then promote in DB
    await client.post("/api/v1/auth/register", json={
        "username": "adminuser", "email": "admin@example.com", "password": "AdminPass1!"
    })
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "adminuser"))
        user = result.scalar_one()
        user.role = UserRole.ADMIN
        await db.commit()

    resp = await client.post("/api/v1/auth/login", json={
        "username": "adminuser", "password": "AdminPass1!"
    })
    token = resp.json()["data"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


async def test_list_policies_includes_builtins(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/v1/policies", headers=auth_headers)
    assert resp.status_code == 200
    names = [p["name"] for p in resp.json()["data"]]
    assert "admin" in names
    assert "developer" in names
    assert "readonly" in names
    assert "database-team" in names
    assert "devops" in names


async def test_create_custom_policy(client: AsyncClient):
    admin = await _admin_headers(client)
    resp = await client.post("/api/v1/policies", json={
        "name": "custom-team",
        "description": "Custom policy for testing",
        "permissions": [{"path": "custom/*", "actions": ["read", "list"]}],
    }, headers=admin)
    assert resp.status_code == 201
    data = resp.json()["data"]
    assert data["name"] == "custom-team"
    assert data["is_builtin"] is False


async def test_cannot_delete_builtin(client: AsyncClient):
    admin = await _admin_headers(client)
    policies = (await client.get("/api/v1/policies", headers=admin)).json()["data"]
    admin_policy_id = next(p["id"] for p in policies if p["name"] == "admin")
    resp = await client.delete(f"/api/v1/policies/{admin_policy_id}", headers=admin)
    assert resp.status_code == 403


async def test_cannot_modify_builtin(client: AsyncClient):
    admin = await _admin_headers(client)
    policies = (await client.get("/api/v1/policies", headers=admin)).json()["data"]
    readonly_id = next(p["id"] for p in policies if p["name"] == "readonly")
    resp = await client.patch(f"/api/v1/policies/{readonly_id}", json={
        "description": "modified"
    }, headers=admin)
    assert resp.status_code == 403


async def test_assign_and_revoke_policy(client: AsyncClient, registered_user: dict, auth_headers: dict):
    admin = await _admin_headers(client)

    # Get user ID
    me = await client.get("/api/v1/auth/me", headers=auth_headers)
    user_id = me.json()["data"]["id"]

    # Get readonly policy ID
    policies = (await client.get("/api/v1/policies", headers=admin)).json()["data"]
    readonly_id = next(p["id"] for p in policies if p["name"] == "readonly")

    # Assign
    resp = await client.post("/api/v1/policies/assign", json={
        "user_id": user_id, "policy_id": readonly_id
    }, headers=admin)
    assert resp.status_code == 200

    # Verify
    user_policies = await client.get(f"/api/v1/policies/user/{user_id}", headers=admin)
    names = [p["name"] for p in user_policies.json()["data"]]
    assert "readonly" in names

    # Revoke
    resp = await client.post("/api/v1/policies/revoke", json={
        "user_id": user_id, "policy_id": readonly_id
    }, headers=admin)
    assert resp.status_code == 200


async def test_duplicate_assignment_rejected(client: AsyncClient, registered_user: dict, auth_headers: dict):
    admin = await _admin_headers(client)
    me = await client.get("/api/v1/auth/me", headers=auth_headers)
    user_id = me.json()["data"]["id"]
    policies = (await client.get("/api/v1/policies", headers=admin)).json()["data"]
    readonly_id = next(p["id"] for p in policies if p["name"] == "readonly")

    await client.post("/api/v1/policies/assign", json={
        "user_id": user_id, "policy_id": readonly_id
    }, headers=admin)
    resp = await client.post("/api/v1/policies/assign", json={
        "user_id": user_id, "policy_id": readonly_id
    }, headers=admin)
    assert resp.status_code == 409
