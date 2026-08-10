"""Integration tests — Threat Modeling Dashboard API."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_get_flow(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/threat-model/flow", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["data"]["stages"][0] == "User"


async def test_get_all_threats(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/threat-model/threats", headers=auth_headers)
    assert len(r.json()["data"]) > 0


async def test_get_specific_threat(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/threat-model/threats/pki_ca_compromise", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["data"]["stage"] == "PKI"


async def test_get_threat_404(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/threat-model/threats/nonexistent", headers=auth_headers)
    assert r.status_code == 404


async def test_by_stage(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/threat-model/stage/Transit", headers=auth_headers)
    assert len(r.json()["data"]) >= 1


async def test_by_stride(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/threat-model/stride/Tampering", headers=auth_headers)
    assert len(r.json()["data"]) >= 1


async def test_coverage(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/threat-model/coverage", headers=auth_headers)
    assert r.json()["data"]["total_threats"] > 0


async def test_export_markdown(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/threat-model/export/markdown", headers=auth_headers)
    assert r.status_code == 200
    assert "STRIDE" in r.text
