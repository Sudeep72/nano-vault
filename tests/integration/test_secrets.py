"""Integration tests — Secrets CRUD + audit trail."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _create_secret(client, headers, key="db/password", value="supersecret") -> dict:
    resp = await client.post("/api/v1/secrets", json={
        "key": key, "value": value,
        "description": "test secret", "category": "database", "tags": ["prod", "db"],
    }, headers=headers)
    assert resp.status_code == 201
    return resp.json()


async def test_create_secret(client: AsyncClient, auth_headers: dict):
    data = await _create_secret(client, auth_headers)
    assert data["key"] == "db/password"
    assert data["category"] == "database"
    assert "encrypted_value" not in data  # never exposed
    assert "value" not in data


async def test_read_secret_decrypted(client: AsyncClient, auth_headers: dict):
    s = await _create_secret(client, auth_headers, value="my-actual-secret")
    resp = await client.get(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["value"] == "my-actual-secret"


async def test_list_secrets_no_values(client: AsyncClient, auth_headers: dict):
    await _create_secret(client, auth_headers, key="key1", value="val1")
    await _create_secret(client, auth_headers, key="key2", value="val2")
    resp = await client.get("/api/v1/secrets", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) >= 2
    for item in items:
        assert "value" not in item  # metadata only


async def test_list_filter_by_category(client: AsyncClient, auth_headers: dict):
    await _create_secret(client, auth_headers, key="cat1", value="v")
    resp = await client.get("/api/v1/secrets?category=database", headers=auth_headers)
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert item["category"] == "database"


async def test_update_secret_increments_version(client: AsyncClient, auth_headers: dict):
    s = await _create_secret(client, auth_headers)
    original_version = s["version"]
    resp = await client.patch(f"/api/v1/secrets/{s['id']}",
                              json={"value": "new-password"},
                              headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["version"] == original_version + 1


async def test_update_secret_value_encrypted(client: AsyncClient, auth_headers: dict):
    s = await _create_secret(client, auth_headers)
    await client.patch(f"/api/v1/secrets/{s['id']}",
                       json={"value": "updated-value"}, headers=auth_headers)
    read = await client.get(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    assert read.json()["value"] == "updated-value"


async def test_delete_secret(client: AsyncClient, auth_headers: dict):
    s = await _create_secret(client, auth_headers)
    del_resp = await client.delete(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    assert del_resp.status_code == 200
    # Should 404 on read after soft delete
    get_resp = await client.get(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    assert get_resp.status_code == 404


async def test_duplicate_key_rejected(client: AsyncClient, auth_headers: dict):
    await _create_secret(client, auth_headers, key="unique-key")
    resp = await client.post("/api/v1/secrets", json={"key": "unique-key", "value": "v2"},
                             headers=auth_headers)
    assert resp.status_code == 409


async def test_cannot_read_other_users_secret(client: AsyncClient, auth_headers: dict):
    s = await _create_secret(client, auth_headers)

    # Register second user
    await client.post("/api/v1/auth/register", json={
        "username": "bob", "email": "bob@example.com", "password": "BobsPass1!"
    })
    login = await client.post("/api/v1/auth/login", json={"username": "bob", "password": "BobsPass1!"})
    bob_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    resp = await client.get(f"/api/v1/secrets/{s['id']}", headers=bob_headers)
    assert resp.status_code == 404  # not exposed, not leaked


async def test_audit_log_populated(client: AsyncClient, auth_headers: dict):
    await _create_secret(client, auth_headers)
    resp = await client.get("/api/v1/audit/my", headers=auth_headers)
    assert resp.status_code == 200
    actions = [item["action"] for item in resp.json()["items"]]
    assert "SECRET_CREATE" in actions
