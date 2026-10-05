"""Integration tests — Interactive API Playground (real in-process request execution)."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_playground_execute_health_check(client: AsyncClient, auth_headers):
    r = await client.post("/api/v4/playground/execute", json={
        "method": "GET", "path": "/api/v3/health/live",
    }, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()["data"]
    assert data["response"]["status_code"] == 200
    assert data["execution_time_ms"] > 0


async def test_playground_execute_real_secret_create(client: AsyncClient, auth_headers):
    """The playground should genuinely create a real secret, not simulate it."""
    token = auth_headers["Authorization"].replace("Bearer ", "")
    r = await client.post("/api/v4/playground/execute", json={
        "method": "POST", "path": "/api/v1/secrets", "token": token,
        "body": {"key": "playground/real-test", "value": "real-value"},
    }, headers=auth_headers)
    assert r.status_code == 200
    result = r.json()["data"]
    assert result["response"]["status_code"] == 201

    # Verify it's really there
    check = await client.get("/api/v1/secrets", headers=auth_headers)
    keys = [s["key"] for s in check.json()["data"]["items"]]
    assert "playground/real-test" in keys


async def test_playground_surfaces_generated_audit_event(client: AsyncClient, auth_headers):
    token = auth_headers["Authorization"].replace("Bearer ", "")
    r = await client.post("/api/v4/playground/execute", json={
        "method": "POST", "path": "/api/v1/secrets", "token": token,
        "body": {"key": "playground/audit-check", "value": "v1"},
    }, headers=auth_headers)
    assert r.json()["data"]["generated_audit_event"] is not None


async def test_playground_examples(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/playground/examples", headers=auth_headers)
    assert "POST /api/v1/auth/login" in r.json()["data"]


async def test_playground_namespaces(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/playground/namespaces", headers=auth_headers)
    assert r.status_code == 200
