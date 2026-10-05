"""Integration tests — Transit Secrets Engine API."""
import base64, pytest
from httpx import AsyncClient
import pytest_asyncio
import uuid
from sqlalchemy import select
from app.db.session import AsyncSessionLocal
from app.models.models import User, UserRole

pytestmark = pytest.mark.asyncio

async def _admin(client):
    uname = f"transadm_{uuid.uuid4().hex[:6]}"

    await client.post(
        "/api/v1/auth/register",
        json={
            "username": uname,
            "email": f"{uname}@nano.com",
            "password": "TransAdmin123!"
        },
    )

    async with AsyncSessionLocal() as db:
        u = (
            await db.execute(
                select(User).where(User.username == uname)
            )
        ).scalar_one()

        u.role = UserRole.ADMIN
        await db.commit()

    resp = await client.post(
        "/api/v1/auth/login",
        json={
            "username": uname,
            "password": "TransAdmin123!"
        },
    )

    return {
        "Authorization": f"Bearer {resp.json()['data']['access_token']}"
    }

@pytest_asyncio.fixture
async def unsealed_vault(client):
    admin = await _admin(client)

    r = await client.post(
        "/api/v3/seal/initialize",
        json={"total_shares": 3, "threshold": 2},
        headers=admin,
    )

    assert r.status_code == 201, r.text

    shares = r.json()["data"]["shares"]

    await client.post(
        "/api/v3/seal/unseal",
        json={"share": shares[0]},
        headers=admin,
    )

    await client.post(
        "/api/v3/seal/unseal",
        json={"share": shares[1]},
        headers=admin,
    )

def b64(s):
    return base64.b64encode(s.encode()).decode()

async def _key(client, headers, name, kt="aes-256-gcm", exportable=False):
    r = await client.post("/api/v3/transit/keys", json={"name": name, "key_type": kt, "exportable": exportable}, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()["data"]

async def test_create_and_list_keys(client: AsyncClient, auth_headers, unsealed_vault):
    await _key(client, auth_headers, "k1")
    resp = await client.get("/api/v3/transit/keys", headers=auth_headers)
    assert "k1" in [k["name"] for k in resp.json()["data"]]

async def test_duplicate_key_rejected(client: AsyncClient, auth_headers, unsealed_vault):
    await _key(client, auth_headers, "dupk")
    r = await client.post("/api/v3/transit/keys", json={"name": "dupk", "key_type": "aes-256-gcm"}, headers=auth_headers)
    assert r.status_code == 409

async def test_rotate_key(client: AsyncClient, auth_headers, unsealed_vault):
    await _key(client, auth_headers, "rotk")
    r = await client.post("/api/v3/transit/keys/rotk/rotate", headers=auth_headers)
    assert r.json()["data"]["new_version"] == 2

async def test_aes_encrypt_decrypt(client: AsyncClient, auth_headers, unsealed_vault):
    await _key(client, auth_headers, "enck")
    pt = b64("secret value")
    enc = await client.post("/api/v3/transit/encrypt/enck", json={"plaintext": pt}, headers=auth_headers)
    ct = enc.json()["data"]["ciphertext"]
    assert ct.startswith("vault:v1:")
    dec = await client.post("/api/v3/transit/decrypt/enck", json={"ciphertext": ct}, headers=auth_headers)
    assert dec.json()["data"]["plaintext"] == pt

async def test_decrypt_old_version_after_rotate(client: AsyncClient, auth_headers, unsealed_vault):
    await _key(client, auth_headers, "overk")
    pt = b64("original")
    ct1 = (await client.post("/api/v3/transit/encrypt/overk", json={"plaintext": pt}, headers=auth_headers)).json()["data"]["ciphertext"]
    await client.post("/api/v3/transit/keys/overk/rotate", headers=auth_headers)
    dec = await client.post("/api/v3/transit/decrypt/overk", json={"ciphertext": ct1}, headers=auth_headers)
    assert dec.json()["data"]["plaintext"] == pt

async def test_ed25519_sign_verify(client: AsyncClient, auth_headers, unsealed_vault):
    await _key(client, auth_headers, "signk", "ed25519")
    data = b64("sign this")
    sig = (await client.post("/api/v3/transit/sign/signk", json={"input": data}, headers=auth_headers)).json()["data"]["signature"]
    v = await client.post("/api/v3/transit/verify/signk", json={"input": data, "signature": sig}, headers=auth_headers)
    assert v.json()["data"]["valid"] is True

async def test_symmetric_cannot_sign(client: AsyncClient, auth_headers, unsealed_vault):
    await _key(client, auth_headers, "nosignk")
    r = await client.post("/api/v3/transit/sign/nosignk", json={"input": b64("x")}, headers=auth_headers)
    assert r.status_code == 400

async def test_hash_sha256_sha512(client: AsyncClient, auth_headers, unsealed_vault):
    r1 = await client.post("/api/v3/transit/hash", json={"input": b64("h"), "algorithm": "sha2-256"}, headers=auth_headers)
    assert len(r1.json()["data"]["sum"]) == 64
    r2 = await client.post("/api/v3/transit/hash", json={"input": b64("h"), "algorithm": "sha2-512"}, headers=auth_headers)
    assert len(r2.json()["data"]["sum"]) == 128

async def test_hmac_generation(client: AsyncClient, auth_headers, unsealed_vault):
    await _key(client, auth_headers, "hmack")
    r = await client.post("/api/v3/transit/hmac/hmack", json={"input": b64("msg")}, headers=auth_headers)
    assert r.json()["data"]["hmac"].startswith("vault:v1:")

async def test_random_bytes(client: AsyncClient, auth_headers, unsealed_vault):
    r = await client.post("/api/v3/transit/random", json={"bytes": 32}, headers=auth_headers)
    data = r.json()["data"]
    assert data["length"] == 32
    assert len(base64.b64decode(data["random_bytes"])) == 32

#async def _admin(client):
#    from app.db.session import AsyncSessionLocal
#    from app.models.models import User, UserRole
#    from sqlalchemy import select
#    import uuid
#    uname = f"transadm_{uuid.uuid4().hex[:6]}"
#    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "TransAdmin123!"})
#    async with AsyncSessionLocal() as db:
#        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
#        u.role = UserRole.ADMIN
#        await db.commit()
#    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "TransAdmin123!"})
#    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}

async def test_exportable_key_export(client: AsyncClient, auth_headers, unsealed_vault):
    admin = await _admin(client)
    await _key(client, auth_headers, "expk", exportable=True)
    r = await client.get("/api/v3/transit/keys/expk/export", headers=admin)
    assert r.status_code == 200
    assert "key_material" in r.json()["data"]

async def test_non_exportable_key_rejected(client: AsyncClient, auth_headers, unsealed_vault):
    admin = await _admin(client)
    await _key(client, auth_headers, "noexpk", exportable=False)
    r = await client.get("/api/v3/transit/keys/noexpk/export", headers=admin)
    assert r.status_code == 403
