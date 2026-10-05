"""Integration tests — Benchmark Suite API."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"benchadm_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "BenchAdmin123!"})
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "BenchAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}


async def test_individual_aes_benchmark(client: AsyncClient, auth_headers):
    r = await client.post("/api/v4/benchmarks/crypto/aes", params={"n": 20}, headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["data"]["algorithm"] == "AES-256-GCM"


async def test_individual_ed25519_benchmark(client: AsyncClient, auth_headers):
    r = await client.post("/api/v4/benchmarks/crypto/ed25519", params={"n": 20}, headers=auth_headers)
    assert r.json()["data"]["algorithm"] == "Ed25519"


async def test_full_crypto_run_saves_history(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v4/benchmarks/crypto/run", headers=admin)
    assert r.status_code == 201
    assert "run_id" in r.json()["data"]

    history = await client.get("/api/v4/benchmarks/history", params={"benchmark_type": "crypto"}, headers=admin)
    assert len(history.json()["data"]) >= 1


async def test_subsystem_benchmark(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v4/benchmarks/subsystem/run", headers=admin)
    assert r.status_code == 201
    assert "database_roundtrip_ms" in r.json()["data"]["subsystem_results"]


async def test_compare_runs(client: AsyncClient):
    admin = await _admin(client)
    r1 = await client.post("/api/v4/benchmarks/crypto/run", headers=admin)
    r2 = await client.post("/api/v4/benchmarks/crypto/run", headers=admin)
    id1, id2 = r1.json()["data"]["run_id"], r2.json()["data"]["run_id"]
    cmp = await client.get("/api/v4/benchmarks/compare", params={"run_a": id1, "run_b": id2}, headers=admin)
    assert cmp.status_code == 200
    assert "delta_ms" in cmp.json()["data"]


async def test_non_admin_cannot_run_full_benchmark(client: AsyncClient, auth_headers):
    r = await client.post("/api/v4/benchmarks/crypto/run", headers=auth_headers)
    assert r.status_code == 403
