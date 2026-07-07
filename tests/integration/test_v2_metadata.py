"""Integration tests — Secret Metadata API."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _create(client, headers, key="meta/secret", value="v1"):
    resp = await client.post("/api/v1/secrets", json={"key": key, "value": value,
                             "category": "test", "tags": ["a", "b"]}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["data"]


async def test_metadata_returns_no_value(client: AsyncClient, auth_headers: dict):
    s = await _create(client, auth_headers)
    resp = await client.get(f"/api/v2/secrets/{s['id']}/metadata", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert "value" not in data
    assert "encrypted_value" not in data


async def test_metadata_has_all_fields(client: AsyncClient, auth_headers: dict):
    s = await _create(client, auth_headers, key="meta/full")
    resp = await client.get(f"/api/v2/secrets/{s['id']}/metadata", headers=auth_headers)
    data = resp.json()["data"]
    assert data["id"] == s["id"]
    assert data["key"] == "meta/full"
    assert data["category"] == "test"
    assert data["tags"] == ["a", "b"]
    assert data["current_version"] == 1
    assert data["version_count"] >= 1
    assert "owner" in data
    assert "encryption" in data
    assert data["encryption"]["algorithm"] == "AES-256-GCM"
    assert data["encryption"]["key_version"] == 1
    assert "rotation" in data
    assert "lifecycle" in data
    assert data["lifecycle"]["status"] == "active"
    assert data["lifecycle"]["is_deleted"] is False


async def test_metadata_tracks_access(client: AsyncClient, auth_headers: dict):
    s = await _create(client, auth_headers, key="meta/access")
    # Read the secret to increment access count
    await client.get(f"/api/v1/secrets/{s['id']}", headers=auth_headers)
    resp = await client.get(f"/api/v2/secrets/{s['id']}/metadata", headers=auth_headers)
    data = resp.json()["data"]
    assert data["access_count"] >= 1
    assert data["last_accessed_at"] is not None


async def test_metadata_shows_rotation_info(client: AsyncClient, auth_headers: dict):
    s = await _create(client, auth_headers, key="meta/rot")
    await client.post(f"/api/v2/kv/{s['id']}/rotate",
                      json={"new_value": "rotated", "change_note": "test rotation"},
                      headers=auth_headers)
    resp = await client.get(f"/api/v2/secrets/{s['id']}/metadata", headers=auth_headers)
    data = resp.json()["data"]
    assert data["rotation"]["total_rotations"] >= 1
    assert len(data["rotation"]["recent_rotations"]) >= 1
    assert data["rotation"]["recent_rotations"][0]["type"] == "manual"


async def test_metadata_after_delete_shows_deleted(client: AsyncClient, auth_headers: dict):
    s = await _create(client, auth_headers, key="meta/del")
    sid = s["id"]
    await client.delete(f"/api/v1/secrets/{sid}", headers=auth_headers)
    # Restore first to read metadata
    await client.post(f"/api/v1/secrets/{sid}/restore", headers=auth_headers)
    resp = await client.get(f"/api/v2/secrets/{sid}/metadata", headers=auth_headers)
    assert resp.status_code == 200


async def test_metadata_list(client: AsyncClient, auth_headers: dict):
    await _create(client, auth_headers, key="meta/list1")
    await _create(client, auth_headers, key="meta/list2")
    resp = await client.get("/api/v2/secrets/metadata/list", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert "items" in data
    assert data["pagination"]["total"] >= 2
    # Values never appear in listing
    for item in data["items"]:
        assert "value" not in item
        assert "encrypted_value" not in item
