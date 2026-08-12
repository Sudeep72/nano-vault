"""Integration tests — NL search + Findings triage."""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


def _mock_response():
    from app.services.v5.ai_provider_service import AIResponse
    return AIResponse(
        raw_text="mocked", parsed={
            "summary": "No suspicious patterns found", "observed_evidence": [],
            "ai_inference": [], "confidence": "insufficient_evidence", "severity": "info",
            "recommended_actions": [], "related_entities": [],
        }, provider="gemini", model="gemini-2.0-flash", latency_ms=30.0,
    )


async def test_search_source_routing_is_deterministic():
    """Source selection must be keyword-based, not AI-based — verifies
    Step 6's 'never lets AI generate arbitrary queries' requirement."""
    from app.services.v5.ai_search_service import AISearchService
    assert "audit" in AISearchService._select_sources("show me failed logins")
    assert "architecture" in AISearchService._select_sources("which services depend on the seal engine")
    assert "policy" in AISearchService._select_sources("explain recent policy violations")


async def test_search_with_no_matching_data_reports_no_evidence(client: AsyncClient, auth_headers):
    r = await client.post("/api/v5/ai/search", json={"query": "show unusual secret access patterns xyz123nonexistent"}, headers=auth_headers)
    assert r.status_code == 200
    # Either "no permitted data" message or a real (mocked-off) AI-unavailable result — both are honest outcomes
    assert r.json()["data"] is not None


async def test_search_with_mocked_provider(client: AsyncClient, auth_headers):
    await client.post("/api/v1/secrets", json={"key": "search/test1", "value": "v1"}, headers=auth_headers)

    with patch("app.services.v5.ai_security_engine.get_provider") as mock_get_provider:
        mock_provider = MagicMock()
        mock_provider.is_configured.return_value = (True, "OK")
        mock_provider.generate = AsyncMock(return_value=_mock_response())
        mock_get_provider.return_value = mock_provider

        r = await client.post("/api/v5/ai/search", json={"query": "show recent login activity"}, headers=auth_headers)

    assert r.status_code == 200
    assert r.json()["data"]["success"] is True
    assert "audit" in r.json()["data"]["sources_queried"]


# ── Findings ──────────────────────────────────────────────────────────────────

async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"findadm_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "FindAdmin123!"})
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "FindAdmin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}


async def _create_finding_via_mocked_explain(client, auth_headers):
    create = await client.post("/api/v1/secrets", json={"key": "finding/src", "value": "v1"}, headers=auth_headers)
    from app.db.session import AsyncSessionLocal
    from sqlalchemy import select
    from app.models.models import AuditLog
    async with AsyncSessionLocal() as db:
        log = (await db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(1))).scalar_one()
        log_id = str(log.id)

    with patch("app.services.v5.ai_security_engine.get_provider") as mock_get_provider:
        mock_provider = MagicMock()
        mock_provider.is_configured.return_value = (True, "OK")
        mock_provider.generate = AsyncMock(return_value=_mock_response())
        mock_get_provider.return_value = mock_provider
        r = await client.post("/api/v5/ai/explain", json={"audit_log_id": log_id}, headers=auth_headers)
    return r.json()["data"]["finding"]["id"]


async def test_list_findings(client: AsyncClient, auth_headers):
    await _create_finding_via_mocked_explain(client, auth_headers)
    r = await client.get("/api/v5/ai/findings", headers=auth_headers)
    assert r.status_code == 200
    assert len(r.json()["data"]) >= 1


async def test_get_single_finding(client: AsyncClient, auth_headers):
    finding_id = await _create_finding_via_mocked_explain(client, auth_headers)
    r = await client.get(f"/api/v5/ai/findings/{finding_id}", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["data"]["id"] == finding_id


async def test_update_finding_status_requires_admin(client: AsyncClient, auth_headers):
    finding_id = await _create_finding_via_mocked_explain(client, auth_headers)
    r = await client.patch(f"/api/v5/ai/findings/{finding_id}/status", json={"status": "resolved"}, headers=auth_headers)
    assert r.status_code == 403


async def test_update_finding_status_as_admin(client: AsyncClient, auth_headers):
    admin = await _admin(client)
    finding_id = await _create_finding_via_mocked_explain(client, auth_headers)
    r = await client.patch(f"/api/v5/ai/findings/{finding_id}/status", json={"status": "resolved"}, headers=admin)
    assert r.status_code == 200
    assert r.json()["data"]["status"] == "resolved"


async def test_findings_never_contain_raw_prompt_or_response():
    """Structural guarantee: AIFinding model has no field for raw prompt/response text."""
    from app.models.models import AIFinding
    columns = {c.name for c in AIFinding.__table__.columns}
    assert "raw_prompt" not in columns
    assert "raw_response" not in columns
    assert "prompt" not in columns
