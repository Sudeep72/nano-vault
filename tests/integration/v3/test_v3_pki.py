"""Integration tests — PKI Secrets Engine."""
import pytest
from httpx import AsyncClient
import pytest_asyncio

pytestmark = pytest.mark.asyncio

@pytest_asyncio.fixture
async def unsealed_vault(client):
    admin = await _admin(client)
    r = await client.post("/api/v3/seal/initialize", json={"total_shares":3,"threshold":2}, headers=admin)
    assert r.status_code == 201, r.text
    shares = r.json()["data"]["shares"]
    await client.post("/api/v3/seal/unseal", json={"share": shares[0]}, headers=admin)
    await client.post("/api/v3/seal/unseal", json={"share": shares[1]}, headers=admin)


async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"pkiadm_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "PkiAdmin123!"})
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "PkiAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}

async def _root_ca(client, admin, name="root1"):
    r = await client.post("/api/v3/pki/ca/root", json={"name": name, "subject_dn": f"CN={name},O=Test,C=US", "ttl_days": 3650, "key_size": 2048}, headers=admin)
    assert r.status_code == 201, r.text
    return r.json()["data"]

async def test_create_root_ca(client: AsyncClient, unsealed_vault):
    admin = await _admin(client)
    d = await _root_ca(client, admin, "rca1")
    assert d["type"] == "root_ca"
    assert "BEGIN CERTIFICATE" in d["certificate_pem"]

async def test_duplicate_ca_rejected(client: AsyncClient, unsealed_vault):
    admin = await _admin(client)
    await _root_ca(client, admin, "dupca")
    r = await client.post("/api/v3/pki/ca/root", json={"name": "dupca", "subject_dn": "CN=dupca,C=US", "ttl_days": 3650, "key_size": 2048}, headers=admin)
    assert r.status_code == 409

async def test_create_intermediate_ca(client: AsyncClient, unsealed_vault):
    admin = await _admin(client)
    root = await _root_ca(client, admin, "introot")
    r = await client.post("/api/v3/pki/ca/intermediate", json={"name": "intca1", "subject_dn": "CN=intca1,C=US", "parent_ca_id": root["id"], "ttl_days": 1825, "key_size": 2048}, headers=admin)
    assert r.status_code == 201
    assert r.json()["data"]["chain_pem"].count("BEGIN CERTIFICATE") == 2

async def test_issue_server_cert(client: AsyncClient, auth_headers, unsealed_vault):
    admin = await _admin(client)
    ca = await _root_ca(client, admin, "issca")
    r = await client.post("/api/v3/pki/issue", json={"ca_id": ca["id"], "common_name": "api.test.com", "cert_type": "server", "ttl_days": 365, "san_dns": ["api.test.com"]}, headers=auth_headers)
    assert r.status_code == 201, r.text
    d = r.json()["data"]
    assert d["common_name"] == "api.test.com"
    assert d["chain_pem"].count("BEGIN CERTIFICATE") == 2

async def test_revoke_cert(client: AsyncClient, auth_headers, unsealed_vault):
    admin = await _admin(client)
    ca = await _root_ca(client, admin, "revca")
    issue = await client.post("/api/v3/pki/issue", json={"ca_id": ca["id"], "common_name": "rev.test.com", "cert_type": "server", "ttl_days": 365}, headers=auth_headers)
    cid = issue.json()["data"]["id"]
    r = await client.post(f"/api/v3/pki/certificates/{cid}/revoke", json={"reason": "key_compromise"}, headers=auth_headers)
    assert r.json()["data"]["status"] == "revoked"

async def test_renew_cert(client: AsyncClient, auth_headers, unsealed_vault):
    admin = await _admin(client)
    ca = await _root_ca(client, admin, "renca")
    issue = await client.post("/api/v3/pki/issue", json={"ca_id": ca["id"], "common_name": "ren.test.com", "cert_type": "server", "ttl_days": 30}, headers=auth_headers)
    old_id = issue.json()["data"]["id"]
    r = await client.post(f"/api/v3/pki/certificates/{old_id}/renew", json={"ttl_days": 365}, headers=auth_headers)
    assert r.status_code == 201
    assert r.json()["data"]["id"] != old_id

async def test_generate_crl(client: AsyncClient, auth_headers, unsealed_vault):
    admin = await _admin(client)
    ca = await _root_ca(client, admin, "crlca")
    issue = await client.post("/api/v3/pki/issue", json={"ca_id": ca["id"], "common_name": "crl.test.com", "cert_type": "server", "ttl_days": 365}, headers=auth_headers)
    cid = issue.json()["data"]["id"]
    await client.post(f"/api/v3/pki/certificates/{cid}/revoke", json={"reason": "superseded"}, headers=auth_headers)
    crl = await client.get(f"/api/v3/pki/ca/{ca['id']}/crl", headers=auth_headers)
    assert "BEGIN X509 CRL" in crl.json()["data"]["crl_pem"]

async def test_list_certs(client: AsyncClient, auth_headers, unsealed_vault):
    admin = await _admin(client)
    ca = await _root_ca(client, admin, "listca")
    await client.post("/api/v3/pki/issue", json={"ca_id": ca["id"], "common_name": "l1.test.com", "cert_type": "server", "ttl_days": 365}, headers=auth_headers)
    r = await client.get(f"/api/v3/pki/certificates?ca_id={ca['id']}", headers=auth_headers)
    assert len(r.json()["data"]) >= 1
