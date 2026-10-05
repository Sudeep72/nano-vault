"""Integration tests — Pass 2 completion API endpoints."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio

async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"p2adm_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "P2Admin123!"})
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "P2Admin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}


async def test_role_mapping_endpoint(client: AsyncClient, auth_headers):
    r = await client.post("/api/v3/identity/role-mapping/apply", json={
        "claims": {"groups": ["eng"], "role": "admin"},
        "group_mappings": {"eng": "developer"},
        "role_mappings": {"admin": "ADMIN"},
        "namespace_mappings": {},
    }, headers=auth_headers)
    assert r.json()["data"]["mapped_role"] == "ADMIN"

async def test_list_sessions_empty_ok(client: AsyncClient):
    admin = await _admin(client)
    r = await client.get("/api/v3/identity/sessions", headers=admin)
    assert r.status_code == 200

async def test_ldap_sync_unreachable_returns_502(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v3/identity/ldap/sync-now", json={
        "provider_name": "test", "ldap_url": "ldap.invalid.nonexistent",
        "bind_dn": "cn=a", "bind_password": "p",
        "user_search_base": "ou=u", "group_search_base": "ou=g",
    }, headers=admin)
    assert r.status_code == 502

async def test_ldap_sync_status_empty(client: AsyncClient):
    admin = await _admin(client)
    r = await client.get("/api/v3/identity/ldap/sync-status", headers=admin)
    assert r.status_code == 200

async def test_replication_queue_replicate(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v3/replication/queue/replicate", params={"from_node": "us-east-1", "resource": "secret/x"}, json={"v": 1}, headers=admin)
    assert r.status_code == 200
    assert r.json()["data"]["replicated_from"] == "us-east-1"

async def test_replication_queue_metrics(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/replication/queue/metrics", headers=auth_headers)
    assert "us-east-1" in r.json()["data"]

async def test_replication_queue_audit(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/replication/queue/audit/us-east-1", headers=auth_headers)
    assert r.status_code == 200

async def test_dry_run_restore(client: AsyncClient, auth_headers):
    admin = await _admin(client)
    await client.post("/api/v1/secrets", json={"key": "p2/dryrun", "value": "v1"}, headers=auth_headers)
    backup = await client.post("/api/v3/backup/v2", json={"backup_type": "full"}, headers=admin)
    bid = backup.json()["data"]["id"]
    r = await client.post(f"/api/v3/backup/v2/{bid}/dry-run", headers=admin)
    assert r.status_code == 200
    assert "would_create" in r.json()["data"] or "unchanged" in r.json()["data"]

async def test_partial_restore_preview(client: AsyncClient, auth_headers):
    admin = await _admin(client)
    await client.post("/api/v1/secrets", json={"key": "p2/partial", "value": "v1"}, headers=auth_headers)
    backup = await client.post("/api/v3/backup/v2", json={"backup_type": "full"}, headers=admin)
    bid = backup.json()["data"]["id"]
    r = await client.post("/api/v3/backup/v2/partial-restore", json={
        "backup_id": bid, "resource_types": ["secrets"], "confirm": False,
    }, headers=admin)
    assert r.status_code == 201
    assert r.json()["data"]["confirmed_write"] is False

async def test_partial_restore_confirmed_writes(client: AsyncClient, auth_headers):
    admin = await _admin(client)
    create = await client.post("/api/v1/secrets", json={"key": "p2/confirmed", "value": "original"}, headers=auth_headers)
    backup = await client.post("/api/v3/backup/v2", json={"backup_type": "full"}, headers=admin)
    bid = backup.json()["data"]["id"]
    r = await client.post("/api/v3/backup/v2/partial-restore", json={
        "backup_id": bid, "resource_types": ["secrets"], "confirm": True,
    }, headers=admin)
    assert r.json()["data"]["confirmed_write"] is True

async def test_validate_before_restore(client: AsyncClient):
    admin = await _admin(client)
    backup = await client.post("/api/v3/backup/v2", json={"backup_type": "full"}, headers=admin)
    bid = backup.json()["data"]["id"]
    r = await client.post(f"/api/v3/backup/v2/{bid}/validate-before-restore", headers=admin)
    assert r.json()["data"]["safe_to_restore"] is True

async def test_alert_fire_history_suppress(client: AsyncClient):
    admin = await _admin(client)
    sup = await client.post("/api/v3/alerts/suppress", json={
        "alert_name": "integration_test_alert", "duration_minutes": 5, "reason": "test",
    }, headers=admin)
    assert sup.status_code == 200

    suppressions = await client.get("/api/v3/alerts/suppressions", headers=admin)
    names = [s["alert_name"] for s in suppressions.json()["data"]]
    assert "integration_test_alert" in names

    unsup = await client.post("/api/v3/alerts/unsuppress/integration_test_alert", headers=admin)
    assert unsup.json()["data"]["was_active"] is True

async def test_alerts_webhook_receiver(client: AsyncClient):
    r = await client.post("/api/v3/alerts/webhook", json={
        "alerts": [{"labels": {"alertname": "TestAlert", "severity": "warning"}, "annotations": {"summary": "test"}}]
    })
    assert r.json()["data"]["processed"] == 1

async def test_dependency_health(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/health/dependencies", headers=auth_headers)
    assert "dependencies" in r.json()["data"]
    assert "database" in r.json()["data"]["dependencies"]
