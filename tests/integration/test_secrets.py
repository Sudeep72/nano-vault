"""Integration tests — Secrets CRUD (v1.0.1)."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _create(client, headers, key="db/password", value="supersecret"):
    resp = await client.post("/api/v1/secrets", json={
        "key": key, "value": value, "category": "database", "tags": ["prod"],
    }, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["data"]


async def test_create_secret(client: AsyncClient, auth_headers):
    data = await _create(client, auth_headers)
    assert data["key"] == "db/password"
    assert "value" not in data
    assert data["encryption_algorithm"] == "AES-256-GCM"
    assert data["status"] == "active"


async def test_read_secret_decrypted(client: AsyncClient, auth_headers):
    s = await _create(client, auth_headers, value="my-actual-secret")
    resp = await client.get(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["value"] == "my-actual-secret"


async def test_list_no_values(client: AsyncClient, auth_headers):
    await _create(client, auth_headers, key="k1", value="v1")
    await _create(client, auth_headers, key="k2", value="v2")
    resp = await client.get("/api/v1/secrets", headers=auth_headers)
    assert resp.status_code == 200
    for item in resp.json()["data"]["items"]:
        assert "value" not in item


async def test_update_increments_version(client: AsyncClient, auth_headers):
    s = await _create(client, auth_headers)
    resp = await client.patch(f"/api/v1/secrets/{s['id']}",
                              json={"value": "new"}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["version"] == s["version"] + 1


async def test_delete_hides_secret(client: AsyncClient, auth_headers):
    s = await _create(client, auth_headers, key="del/test")
    await client.delete(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    assert (await client.get(f"/api/v1/secrets/{s['id']}", headers=auth_headers)).status_code == 404


async def test_duplicate_key_rejected(client: AsyncClient, auth_headers):
    await _create(client, auth_headers, key="unique/key")
    resp = await client.post("/api/v1/secrets", json={"key": "unique/key", "value": "v2"},
                             headers=auth_headers)
    assert resp.status_code == 409


async def test_cross_user_isolation(client: AsyncClient, auth_headers):
    s = await _create(client, auth_headers)
    await client.post("/api/v1/auth/register", json={
        "username": "bob", "email": "bob@example.com", "password": "BobsPass1!"
    })
    login = await client.post("/api/v1/auth/login", json={"username": "bob", "password": "BobsPass1!"})
    bob = {"Authorization": f"Bearer {login.json()['data']['access_token']}"}
    assert (await client.get(f"/api/v1/secrets/{s['id']}", headers=bob)).status_code in (403, 404)


async def test_audit_log_on_create(client: AsyncClient, auth_headers):
    await _create(client, auth_headers)
    resp = await client.get("/api/v1/audit/my", headers=auth_headers)
    actions = [i["action"] for i in resp.json()["data"]["items"]]
    assert "SECRET_CREATE" in actions


async def test_response_is_standardized(client: AsyncClient, auth_headers):
    s = await _create(client, auth_headers, key="std/test")
    resp = await client.get(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    body = resp.json()
    assert "success" in body
    assert "message" in body
    assert "data" in body
    assert body["success"] is True
