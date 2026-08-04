"""Integration tests — Final completion API endpoints."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio

async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"finadm_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "FinAdmin123!"})
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "FinAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}


async def test_otel_status_endpoint(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/otel/status", headers=auth_headers)
    assert "enabled" in r.json()["data"]

async def test_otel_trace_context_endpoint(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/otel/trace-context", headers=auth_headers)
    assert "trace_id" in r.json()["data"]

async def test_cache_health_endpoint(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/cache/health", headers=auth_headers)
    assert "available" in r.json()["data"]

async def test_cache_stats_endpoint(client: AsyncClient):
    admin = await _admin(client)
    r = await client.get("/api/v3/cache/stats", headers=admin)
    assert "hit_rate" in r.json()["data"]

async def test_cache_invalidate_endpoint(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v3/cache/invalidate/policy", headers=admin)
    assert r.status_code == 200

async def test_oidc_pkce_endpoint(client: AsyncClient, auth_headers):
    r = await client.post("/api/v3/identity/oidc/pkce", headers=auth_headers)
    data = r.json()["data"]
    assert "code_verifier" in data
    assert "code_challenge" in data

async def test_saml_parse_endpoint(client: AsyncClient):
    admin = await _admin(client)
    xml = '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.test"><IDPSSODescriptor><SingleSignOnService Location="https://idp.test/sso" Binding="x"/></IDPSSODescriptor></EntityDescriptor>'
    r = await client.post("/api/v3/identity/saml/parse-metadata", json={"xml_content": xml}, headers=admin)
    assert r.json()["data"]["entity_id"] == "https://idp.test"

async def test_replication_topology_endpoint(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/replication/topology", headers=auth_headers)
    assert r.json()["data"]["primary"] == "us-east-1"

async def test_replication_write_and_conflicts(client: AsyncClient):
    admin = await _admin(client)
    await client.post("/api/v3/replication/write/us-east-1", headers=admin)
    r = await client.get("/api/v3/replication/conflicts", headers=admin)
    assert r.json()["data"]["count"] == 0

async def test_replication_health_endpoint(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/replication/health", headers=auth_headers)
    assert "us-east-1" in r.json()["data"]

async def test_backup_v2_create_validate(client: AsyncClient, auth_headers):
    admin = await _admin(client)
    await client.post("/api/v1/secrets", json={"key": "backup2/test", "value": "backup-value"}, headers=auth_headers)
    create = await client.post("/api/v3/backup/v2", json={"backup_type": "full"}, headers=admin)
    assert create.status_code == 201
    bid = create.json()["data"]["id"]
    assert create.json()["data"]["record_counts"]["secrets"] >= 1

    val = await client.post(f"/api/v3/backup/v2/{bid}/validate", headers=admin)
    assert val.json()["data"]["valid"] is True
    assert val.json()["data"]["checksum_match"] is True

async def test_backup_v2_restore(client: AsyncClient, auth_headers):
    admin = await _admin(client)
    await client.post("/api/v1/secrets", json={"key": "backup2/restore", "value": "restore-value"}, headers=auth_headers)
    create = await client.post("/api/v3/backup/v2", json={"backup_type": "full"}, headers=admin)
    bid = create.json()["data"]["id"]
    restore = await client.post(f"/api/v3/backup/v2/{bid}/restore", headers=admin)
    assert restore.json()["data"]["restored"] is True
    assert restore.json()["data"]["secrets_recovered"] >= 1

async def test_backup_v2_list(client: AsyncClient):
    admin = await _admin(client)
    await client.post("/api/v3/backup/v2", json={"backup_type": "full"}, headers=admin)
    r = await client.get("/api/v3/backup/v2", headers=admin)
    assert len(r.json()["data"]) >= 1

async def test_lockout_status_endpoint(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/security/lockout-status/nonexistent-user", headers=auth_headers)
    assert r.json()["data"]["locked"] is False

async def test_redact_endpoint(client: AsyncClient, auth_headers):
    r = await client.post("/api/v3/security/redact", json={"text": 'password="secret123value"'}, headers=auth_headers)
    assert "REDACTED" in r.json()["data"]["redacted"]
    assert "secret123value" not in r.json()["data"]["redacted"]
