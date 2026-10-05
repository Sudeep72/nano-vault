"""Integration tests — Organizations, Projects, Teams, Namespaces."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _get_admin_headers(client: AsyncClient) -> dict:
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    await client.post("/api/v1/auth/register", json={
        "username": "orgadmin", "email": "orgadmin@nano.com", "password": "OrgAdmin1!"
    })
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.username == "orgadmin"))).scalar_one()
        user.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": "orgadmin", "password": "OrgAdmin1!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}


async def test_create_org(client: AsyncClient, auth_headers: dict):
    admin = await _get_admin_headers(client)
    resp = await client.post("/api/v2/orgs/", json={"name": "acme-corp", "description": "ACME Corp"}, headers=admin)
    assert resp.status_code == 201
    assert resp.json()["data"]["name"] == "acme-corp"


async def test_list_orgs(client: AsyncClient, auth_headers: dict):
    admin = await _get_admin_headers(client)
    await client.post("/api/v2/orgs/", json={"name": "org-list-test"}, headers=admin)
    resp = await client.get("/api/v2/orgs/", headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json()["data"]) >= 1


async def test_duplicate_org_rejected(client: AsyncClient):
    admin = await _get_admin_headers(client)
    await client.post("/api/v2/orgs/", json={"name": "dup-org"}, headers=admin)
    resp = await client.post("/api/v2/orgs/", json={"name": "dup-org"}, headers=admin)
    assert resp.status_code == 409


async def test_create_project(client: AsyncClient, auth_headers: dict):
    admin = await _get_admin_headers(client)
    org = (await client.post("/api/v2/orgs/", json={"name": "proj-org"}, headers=admin)).json()["data"]
    resp = await client.post(f"/api/v2/orgs/{org['id']}/projects",
                             json={"name": "backend", "description": "Backend team project"}, headers=admin)
    assert resp.status_code == 201
    assert resp.json()["data"]["name"] == "backend"


async def test_list_projects(client: AsyncClient, auth_headers: dict):
    admin = await _get_admin_headers(client)
    org = (await client.post("/api/v2/orgs/", json={"name": "list-proj-org"}, headers=admin)).json()["data"]
    await client.post(f"/api/v2/orgs/{org['id']}/projects", json={"name": "p1"}, headers=admin)
    await client.post(f"/api/v2/orgs/{org['id']}/projects", json={"name": "p2"}, headers=admin)
    resp = await client.get(f"/api/v2/orgs/{org['id']}/projects", headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json()["data"]) == 2


async def test_create_team(client: AsyncClient, auth_headers: dict):
    admin = await _get_admin_headers(client)
    org = (await client.post("/api/v2/orgs/", json={"name": "team-org"}, headers=admin)).json()["data"]
    proj = (await client.post(f"/api/v2/orgs/{org['id']}/projects",
                              json={"name": "team-project"}, headers=admin)).json()["data"]
    resp = await client.post(
        f"/api/v2/orgs/{org['id']}/projects/{proj['id']}/teams",
        json={"name": "security-team", "policy_ids": []}, headers=admin,
    )
    assert resp.status_code == 201
    assert resp.json()["data"]["name"] == "security-team"


async def test_create_namespace(client: AsyncClient, auth_headers: dict):
    admin = await _get_admin_headers(client)
    org = (await client.post("/api/v2/orgs/", json={"name": "ns-org"}, headers=admin)).json()["data"]
    resp = await client.post(f"/api/v2/orgs/{org['id']}/namespaces", json={
        "name": "production", "path": "ns/production", "description": "Production namespace"
    }, headers=admin)
    assert resp.status_code == 201
    assert resp.json()["data"]["path"] == "ns/production"


async def test_namespace_path_unique(client: AsyncClient):
    admin = await _get_admin_headers(client)
    org = (await client.post("/api/v2/orgs/", json={"name": "ns-unique-org"}, headers=admin)).json()["data"]
    await client.post(f"/api/v2/orgs/{org['id']}/namespaces",
                      json={"name": "n1", "path": "unique/path"}, headers=admin)
    resp = await client.post(f"/api/v2/orgs/{org['id']}/namespaces",
                             json={"name": "n2", "path": "unique/path"}, headers=admin)
    assert resp.status_code == 409


async def test_list_namespaces(client: AsyncClient, auth_headers: dict):
    admin = await _get_admin_headers(client)
    org = (await client.post("/api/v2/orgs/", json={"name": "ns-list-org"}, headers=admin)).json()["data"]
    await client.post(f"/api/v2/orgs/{org['id']}/namespaces",
                      json={"name": "dev", "path": "list/dev"}, headers=admin)
    await client.post(f"/api/v2/orgs/{org['id']}/namespaces",
                      json={"name": "prod", "path": "list/prod"}, headers=admin)
    resp = await client.get(f"/api/v2/orgs/{org['id']}/namespaces", headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json()["data"]) == 2
