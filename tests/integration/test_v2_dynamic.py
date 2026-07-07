"""Integration tests — Dynamic Secrets Engine + Lease Engine."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _generate(client, headers, ctype="app_api_key", ttl=3600, max_renewals=5):
    resp = await client.post("/api/v2/dynamic/generate", json={
        "credential_type": ctype,
        "ttl_seconds": ttl,
        "max_renewals": max_renewals,
    }, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["data"]


async def test_generate_postgres_credential(client: AsyncClient, auth_headers: dict):
    data = await _generate(client, auth_headers, "database_postgres")
    assert "lease_id" in data
    assert data["credentials"]["type"] == "database/postgresql"
    assert "username" in data["credentials"]
    assert "password" in data["credentials"]
    assert data["ttl_seconds"] == 3600


async def test_generate_aws_credential(client: AsyncClient, auth_headers: dict):
    data = await _generate(client, auth_headers, "cloud_aws", ttl=1800)
    creds = data["credentials"]
    assert "access_key_id" in creds
    assert "secret_access_key" in creds


async def test_generate_api_key(client: AsyncClient, auth_headers: dict):
    data = await _generate(client, auth_headers, "app_api_key", ttl=600)
    assert data["credentials"]["api_key"].startswith("nv_live_")


async def test_ttl_too_short_rejected(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/v2/dynamic/generate", json={
        "credential_type": "app_api_key", "ttl_seconds": 30,
    }, headers=auth_headers)
    assert resp.status_code == 422


async def test_list_active_leases(client: AsyncClient, auth_headers: dict):
    await _generate(client, auth_headers)
    resp = await client.get("/api/v2/dynamic/leases", headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json()["data"]) >= 1


async def test_lookup_lease(client: AsyncClient, auth_headers: dict):
    data = await _generate(client, auth_headers, "app_access_token")
    lease_id = data["lease_id"]
    resp = await client.post("/api/v2/dynamic/leases/lookup",
                             json={"lease_id": lease_id}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["lease_id"] == lease_id
    assert resp.json()["data"]["renewable"] is True


async def test_renew_lease(client: AsyncClient, auth_headers: dict):
    data = await _generate(client, auth_headers)
    lease_id = data["lease_id"]
    resp = await client.post("/api/v2/dynamic/leases/renew", json={
        "lease_id": lease_id, "increment_seconds": 1800,
    }, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["renewal_count"] == 1


async def test_revoke_lease(client: AsyncClient, auth_headers: dict):
    data = await _generate(client, auth_headers)
    lease_id = data["lease_id"]
    resp = await client.post("/api/v2/dynamic/leases/revoke",
                             json={"lease_id": lease_id}, headers=auth_headers)
    assert resp.status_code == 200
    # Verify no longer in active list
    leases = await client.get("/api/v2/dynamic/leases", headers=auth_headers)
    ids = [l["lease_id"] for l in leases.json()["data"]]
    assert lease_id not in ids


async def test_all_credential_types(client: AsyncClient, auth_headers: dict):
    for ctype in ["database_mysql", "database_sqlite", "cloud_azure",
                  "cloud_gcp", "app_access_token"]:
        data = await _generate(client, auth_headers, ctype)
        assert "lease_id" in data
        assert "credentials" in data


async def test_list_engines(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/v2/dynamic/engines", headers=auth_headers)
    assert resp.status_code == 200
    names = [e["name"] for e in resp.json()["data"]]
    assert "kv" in names
    assert "dynamic" in names
    assert "cubbyhole" in names
