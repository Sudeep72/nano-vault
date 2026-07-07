"""Integration tests — Secret metadata fields."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_secret_has_full_metadata(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/v1/secrets", json={
        "key": "meta/test", "value": "secret123",
        "category": "test", "tags": ["a", "b"],
        "description": "A test secret",
    }, headers=auth_headers)
    data = resp.json()["data"]
    assert data["id"] is not None
    assert data["owner_id"] is not None
    assert data["version"] == 1
    assert data["encryption_algorithm"] == "AES-256-GCM"
    assert data["key_version"] == 1
    assert data["status"] == "active"
    assert data["status"] == "active"
    assert data["deleted_at"] is None
    assert data["created_at"] is not None
    assert data["updated_at"] is not None
    assert data["access_count"] == 0
    assert data["last_accessed_at"] is None


async def test_read_updates_access_metadata(client: AsyncClient, auth_headers: dict):
    create = await client.post("/api/v1/secrets", json={"key": "access/test", "value": "v"}, headers=auth_headers)
    sid = create.json()["data"]["id"]

    before = create.json()["data"]["access_count"]
    await client.get(f"/api/v1/secrets/{sid}", headers=auth_headers)
    await client.get(f"/api/v1/secrets/{sid}", headers=auth_headers)

    # Read again to get updated metadata
    read = await client.get(f"/api/v1/secrets/{sid}", headers=auth_headers)
    after_count = read.json()["data"]["access_count"]
    assert after_count >= 2
    assert read.json()["data"]["last_accessed_at"] is not None


async def test_update_increments_version(client: AsyncClient, auth_headers: dict):
    create = await client.post("/api/v1/secrets", json={"key": "ver/test", "value": "v1"}, headers=auth_headers)
    sid = create.json()["data"]["id"]
    assert create.json()["data"]["version"] == 1

    update = await client.patch(f"/api/v1/secrets/{sid}", json={"value": "v2"}, headers=auth_headers)
    assert update.json()["data"]["version"] == 2

    update2 = await client.patch(f"/api/v1/secrets/{sid}", json={"value": "v3"}, headers=auth_headers)
    assert update2.json()["data"]["version"] == 3


async def test_deleted_secret_has_deleted_at(client: AsyncClient, auth_headers: dict):
    create = await client.post("/api/v1/secrets", json={"key": "del/meta", "value": "v"}, headers=auth_headers)
    sid = create.json()["data"]["id"]
    await client.delete(f"/api/v1/secrets/{sid}", headers=auth_headers)

    # Search deleted
    search = await client.post("/api/v1/secrets/search", json={"status": "deleted"}, headers=auth_headers)
    deleted = next(i for i in search.json()["data"]["items"] if i["id"] == sid)
    assert deleted["deleted_at"] is not None
    assert deleted["status"] == "deleted"
    # is_deleted is internal; check status
