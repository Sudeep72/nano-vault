"""Integration tests — Auth endpoints."""
import pytest
import pytest_asyncio
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_register_success(client: AsyncClient):
    resp = await client.post("/api/v1/auth/register", json={
        "username": "alice", "email": "alice@example.com", "password": "AlicePass1!"
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["username"] == "alice"
    assert data["role"] == "user"
    assert "hashed_password" not in data


async def test_register_duplicate_username(client: AsyncClient, registered_user: dict):
    resp = await client.post("/api/v1/auth/register", json={
        "username": registered_user["username"],
        "email": "different@example.com",
        "password": "AnotherPass1!",
    })
    assert resp.status_code == 409


async def test_register_weak_password(client: AsyncClient):
    resp = await client.post("/api/v1/auth/register", json={
        "username": "weakuser", "email": "weak@example.com", "password": "weak"
    })
    assert resp.status_code == 422


async def test_login_success(client: AsyncClient, registered_user: dict):
    resp = await client.post("/api/v1/auth/login", json={
        "username": registered_user["username"],
        "password": registered_user["password"],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


async def test_login_wrong_password(client: AsyncClient, registered_user: dict):
    resp = await client.post("/api/v1/auth/login", json={
        "username": registered_user["username"],
        "password": "WrongPassword1!",
    })
    assert resp.status_code == 401


async def test_login_unknown_user(client: AsyncClient):
    resp = await client.post("/api/v1/auth/login", json={
        "username": "nobody", "password": "SomePass1!"
    })
    assert resp.status_code == 401


async def test_me_endpoint(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/v1/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["username"] == "testuser"


async def test_me_no_token(client: AsyncClient):
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 403


async def test_refresh_token(client: AsyncClient, registered_user: dict):
    login = await client.post("/api/v1/auth/login", json={
        "username": registered_user["username"],
        "password": registered_user["password"],
    })
    refresh_token = login.json()["refresh_token"]
    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


async def test_logout_revokes_refresh_token(client: AsyncClient, registered_user: dict, auth_headers: dict):
    login = await client.post("/api/v1/auth/login", json={
        "username": registered_user["username"],
        "password": registered_user["password"],
    })
    refresh_token = login.json()["refresh_token"]

    # Logout
    resp = await client.post("/api/v1/auth/logout",
                             json={"refresh_token": refresh_token},
                             headers=auth_headers)
    assert resp.status_code == 200

    # Refresh after logout must fail
    resp2 = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert resp2.status_code == 401
