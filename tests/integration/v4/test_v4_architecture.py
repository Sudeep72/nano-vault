"""Integration tests — Architecture Explorer + Dependency Graph API."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_get_graph(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/architecture/graph", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["data"]["node_count"] > 0


async def test_get_node(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/architecture/nodes/pki_engine", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["data"]["label"] == "PKI Secrets Engine"


async def test_get_node_404(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/architecture/nodes/nonexistent", headers=auth_headers)
    assert r.status_code == 404


async def test_node_dependencies(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/architecture/nodes/transit_engine/dependencies", headers=auth_headers)
    assert r.status_code == 200
    assert "depends_on" in r.json()["data"]


async def test_by_category(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/architecture/category/engine", headers=auth_headers)
    assert len(r.json()["data"]) >= 4


async def test_search(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/architecture/search", params={"q": "shamir"}, headers=auth_headers)
    assert len(r.json()["data"]) >= 1


async def test_export_dot(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/architecture/export/dot", headers=auth_headers)
    assert r.status_code == 200
    assert "digraph" in r.text


async def test_export_mermaid(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/architecture/export/mermaid", headers=auth_headers)
    assert r.status_code == 200
    assert "graph LR" in r.text


async def test_dependency_graph_real_data(client: AsyncClient, auth_headers):
    await client.post("/api/v1/secrets", json={"key": "depgraph/test", "value": "v1"}, headers=auth_headers)
    r = await client.get("/api/v4/dependency-graph", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["data"]["summary"]["secrets"] >= 1


async def test_secret_impact_analysis(client: AsyncClient, auth_headers):
    create = await client.post("/api/v1/secrets", json={"key": "depgraph/impact", "value": "v1"}, headers=auth_headers)
    sid = create.json()["data"]["id"]
    r = await client.get(f"/api/v4/dependency-graph/secrets/{sid}/impact", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["data"]["key"] == "depgraph/impact"


async def test_ownership_map(client: AsyncClient, auth_headers):
    r = await client.get("/api/v4/dependency-graph/ownership", headers=auth_headers)
    assert r.status_code == 200
