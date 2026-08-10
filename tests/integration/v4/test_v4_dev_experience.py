"""Integration tests — Developer Experience: Diagnostics, Doc Generator, API Collections."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_config_diagnostics(client: AsyncClient):
    r = await client.get("/api/v4/diagnostics/config")
    assert r.status_code == 200
    assert r.json()["data"]["all_passed"] is True  # test env is fully configured


async def test_environment_diagnostics(client: AsyncClient):
    r = await client.get("/api/v4/diagnostics/environment")
    assert r.json()["data"]["python_ok"] is True


async def test_dependencies_diagnostics(client: AsyncClient):
    r = await client.get("/api/v4/diagnostics/dependencies")
    assert r.json()["data"]["all_required_installed"] is True


async def test_full_diagnostics(client: AsyncClient):
    r = await client.get("/api/v4/diagnostics/full")
    assert r.json()["data"]["overall_healthy"] is True
    assert r.json()["data"]["database"]["connected"] is True


async def test_sample_env(client: AsyncClient):
    r = await client.get("/api/v4/diagnostics/sample-env")
    assert "SECRET_KEY" in r.text


# ── Documentation Generator ──────────────────────────────────────────────────

async def test_gen_architecture_diagram(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/docs-generator/architecture", headers=auth_headers)
    assert "graph LR" in r.text


async def test_gen_er_diagram_from_real_schema(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/docs-generator/er-diagram", headers=auth_headers)
    assert "erDiagram" in r.text
    assert "secrets" in r.text or "users" in r.text  # real table names appear


async def test_gen_deployment_diagram(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/docs-generator/deployment", headers=auth_headers)
    assert "Kubernetes" in r.text


async def test_gen_sequence_auth(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/docs-generator/sequence/auth", headers=auth_headers)
    assert "sequenceDiagram" in r.text
    assert "AuthService" in r.text


async def test_gen_sequence_unknown_flow(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/docs-generator/sequence/nonexistent", headers=auth_headers)
    assert "Unknown flow" in r.text


async def test_available_diagrams(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/docs-generator/available", headers=auth_headers)
    assert "architecture" in r.json()["data"]


# ── API Collection Generator ──────────────────────────────────────────────────

async def test_endpoint_count(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/collections/endpoint-count", headers=auth_headers)
    assert r.json()["data"]["total_endpoints"] > 100  # real live schema, large surface


async def test_postman_collection_from_live_schema(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/collections/postman", headers=auth_headers)
    assert r.status_code == 200
    assert len(r.json()["data"]["item"]) > 0


async def test_curl_examples(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/collections/curl", headers=auth_headers)
    examples = r.json()["data"]
    assert any("/api/v1/secrets" in e["path"] for e in examples)


async def test_python_examples(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/collections/python", headers=auth_headers)
    assert any("httpx" in e["python"] for e in r.json()["data"])


async def test_javascript_examples(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/collections/javascript", headers=auth_headers)
    assert any("fetch" in e["javascript"] for e in r.json()["data"])


async def test_bruno_collection(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/collections/bruno", headers=auth_headers)
    files = r.json()["data"]
    assert len(files) > 0
    assert all(f["filename"].endswith(".bru") for f in files)
