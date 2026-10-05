"""Integration tests — Response Wrapping + Cubbyhole."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


# ── Response Wrapping ─────────────────────────────────────────────────────────

async def test_wrap_and_unwrap(client: AsyncClient, auth_headers: dict):
    payload = {"secret": "top-secret-value", "env": "production"}
    wrap_resp = await client.post("/api/v2/wrap/", json={
        "payload": payload, "ttl_seconds": 60,
    }, headers=auth_headers)
    assert wrap_resp.status_code == 201
    wrap_token = wrap_resp.json()["data"]["wrap_token"]
    assert wrap_token.startswith("wrp.")

    unwrap_resp = await client.post("/api/v2/wrap/unwrap", json={"wrap_token": wrap_token})
    assert unwrap_resp.status_code == 200
    assert unwrap_resp.json()["data"] == payload


async def test_wrap_token_single_use(client: AsyncClient, auth_headers: dict):
    wrap_resp = await client.post("/api/v2/wrap/", json={
        "payload": {"k": "v"}, "ttl_seconds": 60,
    }, headers=auth_headers)
    token = wrap_resp.json()["data"]["wrap_token"]
    await client.post("/api/v2/wrap/unwrap", json={"wrap_token": token})
    resp2 = await client.post("/api/v2/wrap/unwrap", json={"wrap_token": token})
    assert resp2.status_code == 410


async def test_wrap_lookup(client: AsyncClient, auth_headers: dict):
    wrap_resp = await client.post("/api/v2/wrap/", json={
        "payload": {"x": 1}, "ttl_seconds": 300,
    }, headers=auth_headers)
    token = wrap_resp.json()["data"]["wrap_token"]
    lookup = await client.post("/api/v2/wrap/lookup", json={"wrap_token": token},
                               headers=auth_headers)
    assert lookup.status_code == 200
    data = lookup.json()["data"]
    assert data["used"] is False
    assert data["time_remaining_seconds"] > 0


async def test_invalid_wrap_token(client: AsyncClient):
    resp = await client.post("/api/v2/wrap/unwrap", json={"wrap_token": "wrp.invalid"})
    assert resp.status_code == 404


async def test_wrap_ttl_too_short_rejected(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/v2/wrap/", json={
        "payload": {"k": "v"}, "ttl_seconds": 5,
    }, headers=auth_headers)
    assert resp.status_code == 422


# ── Cubbyhole ─────────────────────────────────────────────────────────────────

async def test_cubbyhole_write_and_read(client: AsyncClient, auth_headers: dict):
    await client.put("/api/v2/cubbyhole/", json={"key": "temp_cred", "value": "my-temp-secret"},
                     headers=auth_headers)
    resp = await client.get("/api/v2/cubbyhole/temp_cred", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["value"] == "my-temp-secret"


async def test_cubbyhole_list_keys(client: AsyncClient, auth_headers: dict):
    await client.put("/api/v2/cubbyhole/", json={"key": "cbk1", "value": "v1"},
                     headers=auth_headers)
    await client.put("/api/v2/cubbyhole/", json={"key": "cbk2", "value": "v2"},
                     headers=auth_headers)
    resp = await client.get("/api/v2/cubbyhole/", headers=auth_headers)
    assert resp.status_code == 200
    assert "cbk1" in resp.json()["data"]["keys"]
    assert "cbk2" in resp.json()["data"]["keys"]


async def test_cubbyhole_delete(client: AsyncClient, auth_headers: dict):
    await client.put("/api/v2/cubbyhole/", json={"key": "del_key", "value": "v"},
                     headers=auth_headers)
    await client.delete("/api/v2/cubbyhole/del_key", headers=auth_headers)
    resp = await client.get("/api/v2/cubbyhole/del_key", headers=auth_headers)
    assert resp.status_code == 404


async def test_cubbyhole_upsert(client: AsyncClient, auth_headers: dict):
    await client.put("/api/v2/cubbyhole/", json={"key": "upsert_key", "value": "v1"},
                     headers=auth_headers)
    await client.put("/api/v2/cubbyhole/", json={"key": "upsert_key", "value": "v2"},
                     headers=auth_headers)
    resp = await client.get("/api/v2/cubbyhole/upsert_key", headers=auth_headers)
    assert resp.json()["data"]["value"] == "v2"


async def test_cubbyhole_isolation(client: AsyncClient, auth_headers: dict):
    """Cubbyhole key not found for wrong user — 404 on missing key."""
    # Write alice's entry
    await client.put("/api/v2/cubbyhole/", json={"key": "iso_secret", "value": "iso-value"},
                     headers=auth_headers)
    # Register and login as carol (fresh unique name)
    import uuid as _uuid
    carol = f"carol_{_uuid.uuid4().hex[:8]}"
    reg = await client.post("/api/v1/auth/register", json={
        "username": carol, "email": f"{carol}@example.com", "password": "CarolPass1!"
    })
    assert reg.status_code == 201, reg.text
    login = await client.post("/api/v1/auth/login", json={
        "username": carol, "password": "CarolPass1!"
    })
    assert login.status_code == 200, login.text
    carol_headers = {"Authorization": f"Bearer {login.json()['data']['access_token']}"}
    # Carol cannot see Alice's cubbyhole entry
    resp = await client.get("/api/v2/cubbyhole/iso_secret", headers=carol_headers)
    assert resp.status_code == 404
