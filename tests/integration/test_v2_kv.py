"""Integration tests — KV Engine v2 (versioning, rollback, rotation)."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _create(client, headers, key="kv/test", value="v1"):
    resp = await client.post("/api/v1/secrets", json={"key": key, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["data"]


async def test_version_history_on_create(client: AsyncClient, auth_headers: dict):
    s = await _create(client, auth_headers)
    resp = await client.get(f"/api/v2/kv/{s['id']}/versions", headers=auth_headers)
    assert resp.status_code == 200
    versions = resp.json()["data"]
    assert len(versions) == 1
    assert versions[0]["version_number"] == 1
    assert versions[0]["is_current"] is True


async def test_version_grows_on_update(client: AsyncClient, auth_headers: dict):
    s = await _create(client, auth_headers, key="kv/grow")
    await client.patch(f"/api/v1/secrets/{s['id']}", json={"value": "v2"}, headers=auth_headers)
    await client.patch(f"/api/v1/secrets/{s['id']}", json={"value": "v3"}, headers=auth_headers)
    resp = await client.get(f"/api/v2/kv/{s['id']}/versions", headers=auth_headers)
    # 1 initial + 2 updates = 3 total versions
    assert len(resp.json()["data"]) == 3
    # Check current version is 3
    me = await client.get(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    assert me.json()["data"]["version"] == 3


async def test_read_specific_version(client: AsyncClient, auth_headers: dict):
    s = await _create(client, auth_headers, key="kv/ver", value="original")
    resp = await client.get(f"/api/v2/kv/{s['id']}/versions/1", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["value"] == "original"
    assert resp.json()["data"]["version_number"] == 1


async def test_rollback_to_version(client: AsyncClient, auth_headers: dict):
    s = await _create(client, auth_headers, key="kv/rollback", value="original")
    await client.patch(f"/api/v1/secrets/{s['id']}", json={"value": "updated"}, headers=auth_headers)
    # Rollback to v1
    resp = await client.post(f"/api/v2/kv/{s['id']}/rollback",
                             json={"version_number": 1}, headers=auth_headers)
    assert resp.status_code == 200
    # Read — should have original value
    read = await client.get(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    assert read.json()["data"]["value"] == "original"
    assert read.json()["data"]["version"] == 3  # v1 original, v2 updated, v3 rollback


async def test_compare_versions(client: AsyncClient, auth_headers: dict):
    s = await _create(client, auth_headers, key="kv/compare", value="aaa")
    await client.patch(f"/api/v1/secrets/{s['id']}", json={"value": "bbb"}, headers=auth_headers)
    resp = await client.get(f"/api/v2/kv/{s['id']}/versions/1/compare/2", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["values_differ"] is True


async def test_manual_rotation(client: AsyncClient, auth_headers: dict):
    s = await _create(client, auth_headers, key="kv/rotate")
    resp = await client.post(f"/api/v2/kv/{s['id']}/rotate",
                             json={"new_value": "rotated-value", "change_note": "security rotation"},
                             headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["version"] == 2

    read = await client.get(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    assert read.json()["data"]["value"] == "rotated-value"


async def test_enable_auto_rotation(client: AsyncClient, auth_headers: dict):
    s = await _create(client, auth_headers, key="kv/autorot")
    resp = await client.post(f"/api/v2/kv/{s['id']}/rotation/enable",
                             json={"interval_days": 30}, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["rotation_enabled"] is True
    assert data["interval_days"] == 30
    assert data["next_rotation_at"] is not None


async def test_disable_auto_rotation(client: AsyncClient, auth_headers: dict):
    s = await _create(client, auth_headers, key="kv/disablerot")
    await client.post(f"/api/v2/kv/{s['id']}/rotation/enable",
                      json={"interval_days": 7}, headers=auth_headers)
    resp = await client.delete(f"/api/v2/kv/{s['id']}/rotation", headers=auth_headers)
    assert resp.status_code == 200


async def test_rotation_history(client: AsyncClient, auth_headers: dict):
    s = await _create(client, auth_headers, key="kv/rothist")
    await client.post(f"/api/v2/kv/{s['id']}/rotate",
                      json={"new_value": "v2"}, headers=auth_headers)
    await client.post(f"/api/v2/kv/{s['id']}/rotate",
                      json={"new_value": "v3"}, headers=auth_headers)
    resp = await client.get(f"/api/v2/kv/{s['id']}/rotation/history", headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json()["data"]) == 2
