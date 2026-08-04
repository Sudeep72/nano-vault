"""Integration tests — Shamir Seal + Auto-Unseal."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio

async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"sealadm_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "SealAdmin123!"})
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "SealAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}

async def test_seal_status(client: AsyncClient):
    r = await client.get("/api/v3/seal/status")
    assert "sealed" in r.json()["data"]

async def test_initialize_vault(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v3/seal/initialize", json={"total_shares": 3, "threshold": 2}, headers=admin)
    assert r.status_code == 201
    d = r.json()["data"]
    assert len(d["shares"]) == 3

async def test_threshold_exceeds_total(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v3/seal/initialize", json={"total_shares": 3, "threshold": 5}, headers=admin)
    assert r.status_code == 400

async def test_unseal_flow(client: AsyncClient):
    admin = await _admin(client)
    init = await client.post("/api/v3/seal/initialize", json={"total_shares": 3, "threshold": 2}, headers=admin)
    shares = init.json()["data"]["shares"]
    r1 = await client.post("/api/v3/seal/unseal", json={"share": shares[0]})
    assert r1.json()["data"]["sealed"] is True
    r2 = await client.post("/api/v3/seal/unseal", json={"share": shares[1]})
    assert r2.json()["data"]["sealed"] is False

async def test_invalid_share(client: AsyncClient):
    admin = await _admin(client)
    await client.post("/api/v3/seal/initialize", json={"total_shares": 3, "threshold": 2}, headers=admin)
    r = await client.post("/api/v3/seal/unseal", json={"share": "invalid:bad"})
    assert r.status_code == 400

async def test_seal_vault(client: AsyncClient):
    admin = await _admin(client)
    init = await client.post("/api/v3/seal/initialize", json={"total_shares": 3, "threshold": 2}, headers=admin)
    shares = init.json()["data"]["shares"]
    await client.post("/api/v3/seal/unseal", json={"share": shares[0]})
    await client.post("/api/v3/seal/unseal", json={"share": shares[1]})
    r = await client.post("/api/v3/seal/seal", headers=admin)
    assert r.json()["data"]["sealed"] is True

async def test_double_init_rejected(client: AsyncClient):
    admin = await _admin(client)
    await client.post("/api/v3/seal/initialize", json={"total_shares": 3, "threshold": 2}, headers=admin)
    r = await client.post("/api/v3/seal/initialize", json={"total_shares": 5, "threshold": 3}, headers=admin)
    assert r.status_code == 400

async def test_configure_aws_kms(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v3/seal/auto-unseal/providers", json={"name": "aws1", "provider_type": "aws_kms", "config": {"region": "us-east-1", "key_id": "arn:test"}}, headers=admin)
    assert r.status_code == 201

async def test_configure_all_providers(client: AsyncClient):
    admin = await _admin(client)
    configs = [
        ("azure1", "azure_key_vault", {"vault_url": "https://x.vault.azure.net", "key_name": "k"}),
        ("gcp1", "gcp_kms", {"project_id": "p", "key_ring": "r", "crypto_key": "c"}),
        ("hsm1", "local_hsm", {}),
    ]
    for name, ptype, cfg in configs:
        r = await client.post("/api/v3/seal/auto-unseal/providers", json={"name": name, "provider_type": ptype, "config": cfg}, headers=admin)
        assert r.status_code == 201, r.text

async def test_health_check_provider(client: AsyncClient):
    admin = await _admin(client)
    c = await client.post("/api/v3/seal/auto-unseal/providers", json={"name": "hp1", "provider_type": "local_hsm", "config": {}}, headers=admin)
    pid = c.json()["data"]["id"]
    r = await client.post(f"/api/v3/seal/auto-unseal/providers/{pid}/health", headers=admin)
    assert r.json()["data"]["healthy"] is True

async def test_auto_unseal_trigger(client: AsyncClient):
    admin = await _admin(client)
    await client.post("/api/v3/seal/initialize", json={"total_shares": 3, "threshold": 2}, headers=admin)
    await client.post("/api/v3/seal/seal", headers=admin)
    c = await client.post("/api/v3/seal/auto-unseal/providers", json={"name": "auto1", "provider_type": "local_hsm", "config": {}}, headers=admin)
    pid = c.json()["data"]["id"]
    await client.post(f"/api/v3/seal/auto-unseal/providers/{pid}/enable", headers=admin)
    r = await client.post("/api/v3/seal/auto-unseal/trigger", headers=admin)
    assert r.json()["data"]["sealed"] is False
