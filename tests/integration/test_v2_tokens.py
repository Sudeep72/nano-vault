"""Integration tests — Vault Token Engine."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_create_service_token(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/v2/tokens/create", json={
        "token_type": "service",
        "ttl_seconds": 3600,
        "policies": ["readonly"],
    }, headers=auth_headers)
    assert resp.status_code == 201
    data = resp.json()["data"]
    assert data["token"].startswith("nvt.")
    assert data["type"] == "service"
    assert data["renewable"] is True


async def test_lookup_token(client: AsyncClient, auth_headers: dict):
    create = await client.post("/api/v2/tokens/create", json={
        "token_type": "service", "ttl_seconds": 3600,
    }, headers=auth_headers)
    raw_token = create.json()["data"]["token"]
    resp = await client.post("/api/v2/tokens/lookup", json={"token": raw_token}, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["type"] == "service"
    assert data["time_remaining_seconds"] > 0


async def test_renew_token(client: AsyncClient, auth_headers: dict):
    create = await client.post("/api/v2/tokens/create", json={
        "token_type": "service", "ttl_seconds": 3600,
    }, headers=auth_headers)
    raw_token = create.json()["data"]["token"]
    resp = await client.post("/api/v2/tokens/renew", json={
        "token": raw_token, "increment_seconds": 1800,
    }, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["renewal_count"] == 1


async def test_revoke_token(client: AsyncClient, auth_headers: dict):
    create = await client.post("/api/v2/tokens/create", json={
        "token_type": "service", "ttl_seconds": 3600,
    }, headers=auth_headers)
    raw_token = create.json()["data"]["token"]
    resp = await client.post("/api/v2/tokens/revoke", json={"token": raw_token}, headers=auth_headers)
    assert resp.status_code == 200
    # After revoke, renew should fail
    renew = await client.post("/api/v2/tokens/renew", json={"token": raw_token}, headers=auth_headers)
    assert renew.status_code == 400


async def test_list_active_tokens(client: AsyncClient, auth_headers: dict):
    await client.post("/api/v2/tokens/create", json={"ttl_seconds": 3600}, headers=auth_headers)
    resp = await client.get("/api/v2/tokens/active", headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json()["data"]) >= 1
