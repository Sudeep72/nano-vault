"""Integration tests — Namespace Isolation."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"nsadmin_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={
        "username": uname, "email": f"{uname}@nano.com", "password": "NsAdmin123!"
    })
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "NsAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}


async def _create_org_and_ns(client, admin, suffix=""):
    org = (await client.post("/api/v2/orgs/", json={"name": f"ns-test-org{suffix}"},
                             headers=admin)).json()["data"]
    ns = (await client.post("/api/v2/namespaces", json={
        "org_id": org["id"],
        "name": f"dev{suffix}",
        "path": f"ns-test{suffix}/dev",
        "description": "Dev namespace",
    }, headers=admin)).json()["data"]
    return org, ns


async def test_create_namespace(client: AsyncClient):
    admin = await _admin(client)
    org, ns = await _create_org_and_ns(client, admin, "_create")
    assert ns["path"] == "ns-test_create/dev"
    assert ns["name"] == "dev_create"


async def test_duplicate_path_rejected(client: AsyncClient):
    admin = await _admin(client)
    org, ns = await _create_org_and_ns(client, admin, "_dup")
    resp = await client.post("/api/v2/namespaces", json={
        "org_id": org["id"],
        "name": "another",
        "path": ns["path"],
    }, headers=admin)
    assert resp.status_code == 409


async def test_namespace_hierarchy(client: AsyncClient):
    admin = await _admin(client)
    org, parent_ns = await _create_org_and_ns(client, admin, "_hier")
    # Create child namespace
    child = (await client.post("/api/v2/namespaces", json={
        "org_id": org["id"],
        "name": "prod",
        "path": "ns-test_hier/dev/prod",
        "parent_id": parent_ns["id"],
    }, headers=admin)).json()["data"]
    assert child["parent_id"] == parent_ns["id"]

    # Get hierarchy
    resp = await client.get(f"/api/v2/namespaces/{child['id']}/hierarchy", headers=admin)
    assert resp.status_code == 200
    chain = resp.json()["data"]
    assert len(chain) == 2
    paths = [n["path"] for n in chain]
    assert parent_ns["path"] in paths
    assert child["path"] in paths


async def test_delete_namespace(client: AsyncClient):
    admin = await _admin(client)
    org, ns = await _create_org_and_ns(client, admin, "_del")
    resp = await client.delete(f"/api/v2/namespaces/{ns['id']}", headers=admin)
    assert resp.status_code == 200


async def test_cannot_delete_namespace_with_children(client: AsyncClient):
    admin = await _admin(client)
    org, parent_ns = await _create_org_and_ns(client, admin, "_nodelete")
    await client.post("/api/v2/namespaces", json={
        "org_id": org["id"],
        "name": "child",
        "path": "ns-test_nodelete/dev/child",
        "parent_id": parent_ns["id"],
    }, headers=admin)
    resp = await client.delete(f"/api/v2/namespaces/{parent_ns['id']}", headers=admin)
    assert resp.status_code == 400


async def test_switch_namespace(client: AsyncClient):
    admin = await _admin(client)
    org, ns = await _create_org_and_ns(client, admin, "_switch")
    resp = await client.post("/api/v2/namespaces/switch", json={"path": ns["path"]}, headers=admin)
    assert resp.status_code == 200
    assert resp.json()["data"]["path"] == ns["path"]
    assert "X-Vault-Namespace" in resp.json()["data"]["instruction"]


async def test_resolve_active_namespace_from_header(client: AsyncClient):
    admin = await _admin(client)
    org, ns = await _create_org_and_ns(client, admin, "_resolve")
    headers = {**admin, "X-Vault-Namespace": ns["path"]}
    resp = await client.get("/api/v2/namespaces/resolve/active", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["path"] == ns["path"]


async def test_resolve_root_when_no_header(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/v2/namespaces/resolve/active", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["path"] == "root"


async def test_non_admin_cannot_switch(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/v2/namespaces/switch",
                             json={"path": "any/path"}, headers=auth_headers)
    assert resp.status_code == 403


async def test_invalid_namespace_header_rejected(client: AsyncClient):
    admin = await _admin(client)
    headers = {**admin, "X-Vault-Namespace": "does/not/exist"}
    resp = await client.get("/api/v2/namespaces/resolve/active", headers=headers)
    assert resp.status_code == 404
