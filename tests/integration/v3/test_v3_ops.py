"""Integration tests — Scheduler, Backup, Cluster, Health, Dashboard v3 extensions."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio

async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"opsadm_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "OpsAdmin123!"})
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "OpsAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}

async def test_dashboard_transit(client: AsyncClient):
    admin = await _admin(client)
    r = await client.get("/api/v3/dashboard/transit", headers=admin)
    assert "active_keys" in r.json()["data"]

async def test_dashboard_pki(client: AsyncClient):
    admin = await _admin(client)
    r = await client.get("/api/v3/dashboard/pki", headers=admin)
    assert "total_certificates" in r.json()["data"]

async def test_dashboard_seal(client: AsyncClient):
    admin = await _admin(client)
    r = await client.get("/api/v3/dashboard/seal", headers=admin)
    assert "initialized" in r.json()["data"]

async def test_dashboard_identity(client: AsyncClient):
    admin = await _admin(client)
    r = await client.get("/api/v3/dashboard/identity", headers=admin)
    assert "total_providers" in r.json()["data"]

async def test_dashboard_cluster(client: AsyncClient):
    admin = await _admin(client)
    r = await client.get("/api/v3/dashboard/cluster", headers=admin)
    assert r.json()["data"]["is_leader"] is True

async def test_scheduler_run_lease_cleanup(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v3/scheduler/run/lease-cleanup", headers=admin)
    assert r.json()["data"]["job_type"] == "lease_cleanup"

async def test_scheduler_run_rotation(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v3/scheduler/run/secret-rotation", headers=admin)
    assert r.json()["data"]["job_type"] == "secret_rotation"

async def test_scheduler_jobs_history(client: AsyncClient):
    admin = await _admin(client)
    await client.post("/api/v3/scheduler/run/lease-cleanup", headers=admin)
    r = await client.get("/api/v3/scheduler/jobs", headers=admin)
    assert len(r.json()["data"]) >= 1

async def test_scheduler_stats(client: AsyncClient):
    admin = await _admin(client)
    r = await client.get("/api/v3/scheduler/stats", headers=admin)
    assert "job_types" in r.json()["data"]

async def test_backup_create_list_validate(client: AsyncClient):
    admin = await _admin(client)
    create = await client.post("/api/v3/backup", json={"backup_type": "full"}, headers=admin)
    assert create.status_code == 200
    bid = create.json()["data"]["id"]
    lst = await client.get("/api/v3/backup", headers=admin)
    assert bid in [b["id"] for b in lst.json()["data"]]
    val = await client.post(f"/api/v3/backup/{bid}/validate", headers=admin)
    assert val.json()["data"]["valid"] is True

async def test_backup_restore(client: AsyncClient):
    admin = await _admin(client)
    create = await client.post("/api/v3/backup", json={"backup_type": "full"}, headers=admin)
    bid = create.json()["data"]["id"]
    r = await client.post(f"/api/v3/backup/{bid}/restore", headers=admin)
    assert r.json()["data"]["restored"] is True

async def test_cluster_status(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/cluster/status", headers=auth_headers)
    assert r.json()["data"]["is_leader"] is True

async def test_region_status(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/cluster/regions", headers=auth_headers)
    assert "primary_region" in r.json()["data"]

async def test_replication_status(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/cluster/replication", headers=auth_headers)
    assert "conflicts_detected" in r.json()["data"]

async def test_module_health(client: AsyncClient):
    r = await client.get("/api/v3/health/modules")
    assert r.json()["data"]["status"] in ("healthy", "degraded")

async def test_readiness_and_liveness(client: AsyncClient):
    r1 = await client.get("/api/v3/health/ready")
    assert r1.json()["data"]["ready"] is True
    r2 = await client.get("/api/v3/health/live")
    assert r2.json()["data"]["alive"] is True

async def test_prometheus_metrics(client: AsyncClient):
    r = await client.get("/api/v3/metrics/prometheus")
    assert "nanovault_" in r.text
