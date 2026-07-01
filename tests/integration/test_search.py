"""Integration tests — Advanced search and filtering."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _setup_secrets(client, headers):
    secrets = [
        {"key": "aws/prod/key", "value": "v1", "category": "cloud", "tags": ["aws", "prod"]},
        {"key": "aws/dev/key", "value": "v2", "category": "cloud", "tags": ["aws", "dev"]},
        {"key": "database/prod/pass", "value": "v3", "category": "database", "tags": ["postgres", "prod"]},
        {"key": "database/dev/pass", "value": "v4", "category": "database", "tags": ["postgres", "dev"]},
    ]
    ids = []
    for s in secrets:
        r = await client.post("/api/v1/secrets", json=s, headers=headers)
        ids.append(r.json()["data"]["id"])
    return ids


async def test_search_by_query(client: AsyncClient, auth_headers: dict):
    await _setup_secrets(client, auth_headers)
    resp = await client.post("/api/v1/secrets/search", json={"query": "aws"}, headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()["data"]["items"]
    assert len(items) == 2
    assert all("aws" in i["key"] for i in items)


async def test_search_by_category(client: AsyncClient, auth_headers: dict):
    await _setup_secrets(client, auth_headers)
    resp = await client.post("/api/v1/secrets/search", json={"category": "database"}, headers=auth_headers)
    items = resp.json()["data"]["items"]
    assert len(items) == 2
    assert all(i["category"] == "database" for i in items)


async def test_search_by_tag(client: AsyncClient, auth_headers: dict):
    await _setup_secrets(client, auth_headers)
    resp = await client.post("/api/v1/secrets/search", json={"tag": "prod"}, headers=auth_headers)
    items = resp.json()["data"]["items"]
    assert len(items) == 2
    assert all("prod" in i["tags"] for i in items)


async def test_search_sort_by_key_asc(client: AsyncClient, auth_headers: dict):
    await _setup_secrets(client, auth_headers)
    resp = await client.post("/api/v1/secrets/search", json={
        "sort_by": "key", "sort_order": "asc"
    }, headers=auth_headers)
    items = resp.json()["data"]["items"]
    keys = [i["key"] for i in items]
    assert keys == sorted(keys)


async def test_search_pagination(client: AsyncClient, auth_headers: dict):
    await _setup_secrets(client, auth_headers)
    resp = await client.post("/api/v1/secrets/search", json={
        "page": 1, "page_size": 2
    }, headers=auth_headers)
    data = resp.json()["data"]
    assert len(data["items"]) == 2
    assert data["pagination"]["total"] == 4
    assert data["pagination"]["pages"] == 2


async def test_search_deleted_secrets(client: AsyncClient, auth_headers: dict):
    ids = await _setup_secrets(client, auth_headers)
    # Delete one
    await client.delete(f"/api/v1/secrets/{ids[0]}", headers=auth_headers)
    # Search deleted
    resp = await client.post("/api/v1/secrets/search", json={"status": "deleted"}, headers=auth_headers)
    items = resp.json()["data"]["items"]
    assert len(items) == 1
    assert items[0]["id"] == ids[0]


async def test_list_endpoint_backward_compatible(client: AsyncClient, auth_headers: dict):
    """GET /secrets still works as before."""
    await _setup_secrets(client, auth_headers)
    resp = await client.get("/api/v1/secrets", headers=auth_headers)
    assert resp.status_code == 200
    assert "items" in resp.json()["data"]
