"""Integration tests — Completion pass: Marketplace, Storage, Prometheus, Agent, K8s status, Benchmarks."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio

async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"compadm_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "CompAdmin123!"})
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "CompAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}


async def test_marketplace_list(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/marketplace/engines", headers=auth_headers)
    assert r.status_code == 200
    names = [e["name"] for e in r.json()["data"]]
    assert "kv" in names
    assert "transit" in names


async def test_marketplace_shows_installed_flag(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/marketplace/engines", headers=auth_headers)
    kv = next(e for e in r.json()["data"] if e["name"] == "kv")
    assert kv["installed"] is True


async def test_marketplace_upgrade(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v3/marketplace/engines/kv/upgrade", headers=admin)
    assert r.status_code == 200
    assert r.json()["data"]["upgraded"] is True


async def test_storage_backends_list(client: AsyncClient):
    admin = await _admin(client)
    r = await client.get("/api/v3/storage/backends", headers=admin)
    assert r.status_code == 200
    names = [b["name"] for b in r.json()["data"]]
    assert any("sqlite" in n or "postgresql" in n for n in names)
    assert "mysql" in names  # reserved future backend


async def test_storage_validate(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v3/storage/validate", headers=admin)
    assert r.status_code == 200
    assert r.json()["data"]["valid"] is True


async def test_prometheus_metrics_endpoint(client: AsyncClient):
    r = await client.get("/api/v3/metrics")
    assert r.status_code == 200
    assert "nanovault_secrets_total" in r.text
    assert "nanovault_transit_keys_total" in r.text


async def test_agent_render_template(client: AsyncClient, auth_headers):
    create = await client.post("/api/v1/secrets", json={"key": "agent/test", "value": "agent-secret-value"}, headers=auth_headers)
    sid = create.json()["data"]["id"]
    r = await client.post(f"/api/v3/agent/render?secret_id={sid}&template=DB_PASS={{{{value}}}}", headers=auth_headers)
    assert r.status_code == 200
    assert "agent-secret-value" in r.json()["data"]["rendered"]


async def test_agent_cache_status(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/agent/cache/status", headers=auth_headers)
    assert "cached_secrets" in r.json()["data"]


async def test_kubernetes_status(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/kubernetes/status", headers=auth_headers)
    assert r.json()["data"]["helm_chart_available"] is True
    assert "deployment" in r.json()["data"]["manifests_available"]


async def test_benchmark_run(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v3/benchmark/run", headers=admin)
    assert r.status_code == 200
    assert "encryption_100_ops_ms" in r.json()["data"]
    assert "db_roundtrip_20_ops_ms" in r.json()["data"]


async def test_live_scheduler_jobs(client: AsyncClient):
    admin = await _admin(client)
    r = await client.get("/api/v3/scheduler/live-jobs", headers=admin)
    assert r.status_code == 200
