"""Integration tests — Enterprise Identity Providers."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio

async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"idpadm_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "IdpAdmin123!"})
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "IdpAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}

async def test_get_oidc_template(client: AsyncClient, auth_headers):
    r = await client.get("/api/v3/identity/providers/templates/oidc", headers=auth_headers)
    assert "issuer_url" in r.json()["data"]["required_fields"]

async def test_configure_oidc(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v3/identity/providers", json={
        "name": "goidc", "provider_type": "oidc",
        "config": {"issuer_url": "https://accounts.google.com", "client_id": "x", "client_secret": "y"},
    }, headers=admin)
    assert r.status_code == 201

async def test_configure_all_provider_types(client: AsyncClient):
    admin = await _admin(client)
    cases = [
        ("ldap1", "ldap", {"ldap_url": "ldap://x", "bind_dn": "cn=a", "bind_password": "p", "user_dn": "ou=u", "group_dn": "ou=g"}),
        ("ad1", "active_directory", {"domain": "corp.com", "server_url": "ldaps://x", "bind_dn": "cn=a", "bind_password": "p"}),
        ("jwt1", "jwt", {"jwks_url": "https://x/jwks.json", "issuer": "https://x", "audience": "vault"}),
        ("saml1", "saml", {"idp_metadata_url": "https://x/md", "sp_entity_id": "https://y", "acs_url": "https://y/acs"}),
    ]
    for name, ptype, cfg in cases:
        r = await client.post("/api/v3/identity/providers", json={"name": name, "provider_type": ptype, "config": cfg}, headers=admin)
        assert r.status_code == 201, r.text

async def test_missing_config_rejected(client: AsyncClient):
    admin = await _admin(client)
    r = await client.post("/api/v3/identity/providers", json={"name": "bad1", "provider_type": "oidc", "config": {"client_id": "x"}}, headers=admin)
    assert r.status_code == 422

async def test_duplicate_rejected(client: AsyncClient):
    admin = await _admin(client)
    payload = {"name": "dup1", "provider_type": "jwt", "config": {"jwks_url": "https://x", "issuer": "https://x", "audience": "v"}}
    await client.post("/api/v3/identity/providers", json=payload, headers=admin)
    r = await client.post("/api/v3/identity/providers", json=payload, headers=admin)
    assert r.status_code == 409

async def test_enable_disable(client: AsyncClient):
    admin = await _admin(client)
    c = await client.post("/api/v3/identity/providers", json={"name": "tog1", "provider_type": "jwt", "config": {"jwks_url": "https://x", "issuer": "https://x", "audience": "v"}}, headers=admin)
    pid = c.json()["data"]["id"]
    assert (await client.post(f"/api/v3/identity/providers/{pid}/enable", headers=admin)).json()["data"]["is_enabled"] is True
    assert (await client.post(f"/api/v3/identity/providers/{pid}/disable", headers=admin)).json()["data"]["is_enabled"] is False

async def test_test_connection(client: AsyncClient):
    admin = await _admin(client)
    c = await client.post("/api/v3/identity/providers", json={"name": "conn1", "provider_type": "jwt", "config": {"jwks_url": "https://x", "issuer": "https://x", "audience": "v"}}, headers=admin)
    pid = c.json()["data"]["id"]
    r = await client.post(f"/api/v3/identity/providers/{pid}/test", headers=admin)
    assert r.json()["data"]["connected"] is True

async def test_update_mappings(client: AsyncClient):
    admin = await _admin(client)
    c = await client.post("/api/v3/identity/providers", json={"name": "map1", "provider_type": "jwt", "config": {"jwks_url": "https://x", "issuer": "https://x", "audience": "v"}}, headers=admin)
    pid = c.json()["data"]["id"]
    r = await client.patch(f"/api/v3/identity/providers/{pid}/mappings", json={"group_mappings": {"eng": "dev"}}, headers=admin)
    assert r.json()["data"]["group_mappings"] == {"eng": "dev"}

async def test_sync(client: AsyncClient):
    admin = await _admin(client)
    c = await client.post("/api/v3/identity/providers", json={"name": "sync1", "provider_type": "jwt", "config": {"jwks_url": "https://x", "issuer": "https://x", "audience": "v"}}, headers=admin)
    pid = c.json()["data"]["id"]
    await client.post(f"/api/v3/identity/providers/{pid}/enable", headers=admin)
    r = await client.post(f"/api/v3/identity/providers/{pid}/sync", headers=admin)
    assert "synced_at" in r.json()["data"]
