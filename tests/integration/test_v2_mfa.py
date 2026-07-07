"""Integration tests — MFA (TOTP)."""
import pytest
import pyotp
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_mfa_status_default_disabled(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/v2/mfa/status", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["mfa_enabled"] is False


async def test_mfa_setup_returns_secret(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/v2/mfa/setup", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert "totp_secret" in data
    assert "provisioning_uri" in data
    assert "recovery_codes" in data
    assert len(data["recovery_codes"]) == 8


async def test_mfa_verify_and_enable(client: AsyncClient, auth_headers: dict):
    setup = await client.post("/api/v2/mfa/setup", headers=auth_headers)
    secret = setup.json()["data"]["totp_secret"]
    totp = pyotp.TOTP(secret)
    code = totp.now()

    resp = await client.post("/api/v2/mfa/verify", json={"totp_code": code}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["mfa_enabled"] is True

    status = await client.get("/api/v2/mfa/status", headers=auth_headers)
    assert status.json()["data"]["mfa_enabled"] is True


async def test_mfa_invalid_code_rejected(client: AsyncClient, auth_headers: dict):
    await client.post("/api/v2/mfa/setup", headers=auth_headers)
    resp = await client.post("/api/v2/mfa/verify", json={"totp_code": "000000"}, headers=auth_headers)
    assert resp.status_code == 400


async def test_mfa_double_setup_rejected(client: AsyncClient, auth_headers: dict):
    setup = await client.post("/api/v2/mfa/setup", headers=auth_headers)
    secret = setup.json()["data"]["totp_secret"]
    code = pyotp.TOTP(secret).now()
    await client.post("/api/v2/mfa/verify", json={"totp_code": code}, headers=auth_headers)
    resp = await client.post("/api/v2/mfa/setup", headers=auth_headers)
    assert resp.status_code == 400


async def test_use_recovery_code(client: AsyncClient, auth_headers: dict):
    setup = await client.post("/api/v2/mfa/setup", headers=auth_headers)
    data = setup.json()["data"]
    code = pyotp.TOTP(data["totp_secret"]).now()
    await client.post("/api/v2/mfa/verify", json={"totp_code": code}, headers=auth_headers)

    recovery_code = data["recovery_codes"][0]
    resp = await client.post("/api/v2/mfa/recovery", json={"recovery_code": recovery_code}, headers=auth_headers)
    assert resp.status_code == 200

    # Same code cannot be used twice
    resp2 = await client.post("/api/v2/mfa/recovery", json={"recovery_code": recovery_code}, headers=auth_headers)
    assert resp2.status_code == 400
