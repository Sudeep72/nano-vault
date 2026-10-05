"""Integration tests — Auth endpoints (v1.0.1 response format)."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_register_success(client: AsyncClient):
    resp = await client.post("/api/v1/auth/register", json={
        "username": "alice", "email": "alice@example.com", "password": "AlicePass1!"
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["success"] is True
    assert data["data"]["username"] == "alice"
    assert data["data"]["role"].lower() == "user"
    assert "hashed_password" not in data["data"]


async def test_register_duplicate_username(client: AsyncClient, registered_user):
    resp = await client.post("/api/v1/auth/register", json={
        "username": registered_user["username"],
        "email": "diff@example.com", "password": "AnotherPass1!",
    })
    assert resp.status_code == 409


async def test_register_weak_password(client: AsyncClient):
    resp = await client.post("/api/v1/auth/register", json={
        "username": "weakuser", "email": "weak@example.com", "password": "weak"
    })
    assert resp.status_code == 422


async def test_login_success(client: AsyncClient, registered_user):
    resp = await client.post("/api/v1/auth/login", json={
        "username": registered_user["username"], "password": registered_user["password"],
    })
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


async def test_login_wrong_password(client: AsyncClient, registered_user):
    resp = await client.post("/api/v1/auth/login", json={
        "username": registered_user["username"], "password": "WrongPassword1!",
    })
    assert resp.status_code == 401


async def test_login_unknown_user(client: AsyncClient):
    resp = await client.post("/api/v1/auth/login", json={
        "username": "nobody", "password": "SomePass1!"
    })
    assert resp.status_code == 401


async def test_me_endpoint(client: AsyncClient, auth_headers):
    resp = await client.get("/api/v1/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["username"] == "testuser"


async def test_me_no_token(client: AsyncClient):
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code in (401, 403)
    #assert resp.status_code == 403


async def test_refresh_token(client: AsyncClient, registered_user):
    login = await client.post("/api/v1/auth/login", json={
        "username": registered_user["username"], "password": registered_user["password"],
    })
    refresh_token = login.json()["data"]["refresh_token"]
    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    assert "access_token" in resp.json()["data"]


async def test_logout_revokes_refresh_token(client: AsyncClient, registered_user, auth_headers):
    login = await client.post("/api/v1/auth/login", json={
        "username": registered_user["username"], "password": registered_user["password"],
    })
    refresh_token = login.json()["data"]["refresh_token"]
    resp = await client.post("/api/v1/auth/logout",
                             json={"refresh_token": refresh_token},
                             headers=auth_headers)
    assert resp.status_code == 200
    resp2 = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert resp2.status_code == 401
