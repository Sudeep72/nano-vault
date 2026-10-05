"""Integration tests — Policy as Code."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio

async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"pacadm_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "PacAdmin123!"})
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "PacAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}

YAML_P = "permissions:\n  - path: \"aws/*\"\n    actions: [\"read\", \"list\"]\n  - path: \"database/*\"\n    actions: [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n"
JSON_P = '{"permissions": [{"path": "dev/*", "actions": ["create","read","update","delete","list"]}, {"path": "*", "actions": ["read","list"]}]}'
HCL_P = 'path "production/*" {\n  capabilities = ["read", "list"]\n}\npath "aws/*" {\n  capabilities = ["create", "read", "update", "delete", "list"]\n}\n'
INVALID_P = 'permissions:\n  - path: "aws/*"\n    actions: ["hack", "destroy"]\n'

async def test_upload_yaml(client: AsyncClient, auth_headers):
    r = await client.post("/api/v3/policy-as-code/upload", json={"name": "devp", "content": YAML_P, "format": "yaml"}, headers=auth_headers)
    assert r.status_code == 201
    assert r.json()["data"]["is_valid"] is True

async def test_upload_json(client: AsyncClient, auth_headers):
    r = await client.post("/api/v3/policy-as-code/upload", json={"name": "jsonp", "content": JSON_P, "format": "json"}, headers=auth_headers)
    assert r.json()["data"]["permissions_parsed"] == 2

async def test_upload_hcl(client: AsyncClient, auth_headers):
    r = await client.post("/api/v3/policy-as-code/upload", json={"name": "hclp", "content": HCL_P, "format": "hcl"}, headers=auth_headers)
    assert r.json()["data"]["permissions_parsed"] == 2

async def test_upload_apply(client: AsyncClient, auth_headers):
    r = await client.post("/api/v3/policy-as-code/upload", json={"name": "applyp", "content": YAML_P, "format": "yaml", "apply": True}, headers=auth_headers)
    assert r.json()["data"]["applied"] is True
    pols = await client.get("/api/v1/policies", headers=auth_headers)
    assert "pac:applyp" in [p["name"] for p in pols.json()["data"]]

async def test_invalid_not_applied(client: AsyncClient, auth_headers):
    r = await client.post("/api/v3/policy-as-code/upload", json={"name": "badp", "content": INVALID_P, "format": "yaml", "apply": True}, headers=auth_headers)
    assert r.json()["data"]["is_valid"] is False
    assert r.json()["data"]["applied"] is False

async def test_validate_endpoint(client: AsyncClient, auth_headers):
    r = await client.post("/api/v3/policy-as-code/validate", json={"content": YAML_P, "format": "yaml"}, headers=auth_headers)
    assert r.json()["data"]["valid"] is True

async def test_simulate_allow_deny(client: AsyncClient, auth_headers):
    await client.post("/api/v3/policy-as-code/upload", json={"name": "simp", "content": YAML_P, "format": "yaml"}, headers=auth_headers)
    allow = await client.post("/api/v3/policy-as-code/simulate", json={"policy_name": "simp", "secret_key": "aws/prod/key", "action": "read"}, headers=auth_headers)
    assert allow.json()["data"]["allowed"] is True
    deny = await client.post("/api/v3/policy-as-code/simulate", json={"policy_name": "simp", "secret_key": "aws/prod/key", "action": "delete"}, headers=auth_headers)
    assert deny.json()["data"]["allowed"] is False

async def test_version_increment(client: AsyncClient, auth_headers):
    await client.post("/api/v3/policy-as-code/upload", json={"name": "verp", "content": YAML_P, "format": "yaml"}, headers=auth_headers)
    r2 = await client.post("/api/v3/policy-as-code/upload", json={"name": "verp", "content": JSON_P, "format": "json"}, headers=auth_headers)
    assert r2.json()["data"]["version"] == 2

async def test_diff(client: AsyncClient, auth_headers):
    await client.post("/api/v3/policy-as-code/upload", json={"name": "diffp", "content": YAML_P, "format": "yaml"}, headers=auth_headers)
    await client.post("/api/v3/policy-as-code/upload", json={"name": "diffp", "content": JSON_P, "format": "json"}, headers=auth_headers)
    r = await client.post("/api/v3/policy-as-code/diff", json={"policy_name": "diffp", "version_a": 1, "version_b": 2}, headers=auth_headers)
    assert "total_changes" in r.json()["data"]

async def test_rollback(client: AsyncClient, auth_headers):
    admin = await _admin(client)
    await client.post("/api/v3/policy-as-code/upload", json={"name": "rbp", "content": YAML_P, "format": "yaml"}, headers=auth_headers)
    await client.post("/api/v3/policy-as-code/upload", json={"name": "rbp", "content": JSON_P, "format": "json"}, headers=auth_headers)
    r = await client.post("/api/v3/policy-as-code/rbp/rollback", json={"target_version": 1}, headers=admin)
    assert r.json()["data"]["new_version"] == 3

async def test_list_files_and_versions(client: AsyncClient, auth_headers):
    await client.post("/api/v3/policy-as-code/upload", json={"name": "listp", "content": YAML_P, "format": "yaml"}, headers=auth_headers)
    files = await client.get("/api/v3/policy-as-code/files", headers=auth_headers)
    assert "listp" in [f["name"] for f in files.json()["data"]]
    versions = await client.get("/api/v3/policy-as-code/listp/versions", headers=auth_headers)
    assert len(versions.json()["data"]) == 1
