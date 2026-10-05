"""Integration tests — Health and Metrics endpoints."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_health_returns_all_components(client: AsyncClient):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["status"] in ("healthy", "degraded")
    assert "database" in data["components"]
    assert "encryption" in data["components"]
    assert "authentication" in data["components"]
    assert "audit_engine" in data["components"]
    assert "uptime_seconds" in data
    assert data["uptime_seconds"] >= 0


async def test_health_encryption_component(client: AsyncClient):
    resp = await client.get("/health")
    enc = resp.json()["data"]["components"]["encryption"]
    assert enc["status"] == "healthy"


async def test_metrics_structure(client: AsyncClient, registered_user: dict, auth_headers: dict):
    # Generate some activity
    await client.post("/api/v1/secrets", json={"key": "m/key", "value": "mval"}, headers=auth_headers)
    resp = await client.get("/metrics")
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["total_users"] >= 1
    assert data["total_secrets"] >= 1
    assert data["active_secrets"] >= 1
    assert "total_audit_events" in data
    assert "secret_reads" in data
    assert "secret_writes" in data
    assert "failed_logins" in data
    assert "successful_logins" in data
    assert "_meta" in data


async def test_metrics_increments_on_activity(client: AsyncClient, auth_headers: dict):
    before = (await client.get("/metrics")).json()["data"]
    await client.post("/api/v1/secrets", json={"key": "incr/key", "value": "v"}, headers=auth_headers)
    after = (await client.get("/metrics")).json()["data"]
    assert after["total_secrets"] == before["total_secrets"] + 1
    assert after["secret_writes"] == before["secret_writes"] + 1
