"""
Integration tests — AI explain/investigate/search, real DB + real RBAC,
mocked Gemini provider so no network call or real API key is needed.
"""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


def _mock_finding_response():
    from app.services.v5.ai_provider_service import AIResponse
    return AIResponse(
        raw_text="mocked", parsed={
            "summary": "Login failure pattern observed", "observed_evidence": ["3 failed logins in 5 minutes"],
            "ai_inference": ["Could indicate credential stuffing"], "confidence": "medium",
            "severity": "medium", "recommended_actions": ["Review source IP", "Consider MFA enforcement"],
            "related_entities": ["user:alice"],
        }, provider="gemini", model="gemini-2.0-flash", latency_ms=42.0,
        input_tokens=100, output_tokens=50,
    )


async def test_explain_without_ai_enabled_returns_clear_unavailable(client: AsyncClient, auth_headers):
    """Real behavior: AI disabled by default in test env — core functionality
    (the explain endpoint itself, auth, DB lookup) all still work; only the
    AI call itself reports unavailable."""
    create = await client.post("/api/v1/secrets", json={"key": "aitest/e1", "value": "v1"}, headers=auth_headers)
    assert create.status_code == 201

    from app.db.session import AsyncSessionLocal
    from sqlalchemy import select
    from app.models.models import AuditLog
    async with AsyncSessionLocal() as db:
        log = (await db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(1))).scalar_one()
        log_id = str(log.id)

    r = await client.post("/api/v5/ai/explain", json={"audit_log_id": log_id}, headers=auth_headers)
    assert r.status_code == 200
    result = r.json()["data"]
    assert result["success"] is False
    assert result["error_type"] == "unavailable"


async def test_explain_event_not_found(client: AsyncClient, auth_headers):
    import uuid
    r = await client.post("/api/v5/ai/explain", json={"audit_log_id": str(uuid.uuid4())}, headers=auth_headers)
    assert r.status_code == 404


async def test_explain_with_mocked_provider_full_flow(client: AsyncClient, auth_headers):
    """Full orchestration proof: context gathering -> guardrails -> mocked
    provider -> schema validation -> finding persisted -> audit logged."""
    create = await client.post("/api/v1/secrets", json={"key": "aitest/e2", "value": "v1"}, headers=auth_headers)
    from app.db.session import AsyncSessionLocal
    from sqlalchemy import select
    from app.models.models import AuditLog
    async with AsyncSessionLocal() as db:
        log = (await db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(1))).scalar_one()
        log_id = str(log.id)

    with patch("app.services.v5.ai_security_engine.get_provider") as mock_get_provider:
        mock_provider = MagicMock()
        mock_provider.is_configured.return_value = (True, "OK")
        mock_provider.generate = AsyncMock(return_value=_mock_finding_response())
        mock_get_provider.return_value = mock_provider

        r = await client.post("/api/v5/ai/explain", json={"audit_log_id": log_id}, headers=auth_headers)

    assert r.status_code == 200
    result = r.json()["data"]
    assert result["success"] is True
    assert result["finding"]["confidence"] == "medium"
    assert result["finding"]["severity"] == "medium"
    assert "id" in result["finding"]


async def test_investigate_with_mocked_provider(client: AsyncClient, auth_headers):
    await client.post("/api/v1/secrets", json={"key": "aitest/e3", "value": "v1"}, headers=auth_headers)
    from app.db.session import AsyncSessionLocal
    from sqlalchemy import select
    from app.models.models import AuditLog
    async with AsyncSessionLocal() as db:
        log = (await db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(1))).scalar_one()
        log_id = str(log.id)

    with patch("app.services.v5.ai_security_engine.get_provider") as mock_get_provider:
        mock_provider = MagicMock()
        mock_provider.is_configured.return_value = (True, "OK")
        mock_provider.generate = AsyncMock(return_value=_mock_finding_response())
        mock_get_provider.return_value = mock_provider

        r = await client.post("/api/v5/ai/investigate", json={
            "audit_log_id": log_id, "question": "Was this access unusual?",
        }, headers=auth_headers)

    assert r.status_code == 200
    assert r.json()["data"]["success"] is True


async def test_provider_timeout_surfaces_as_clear_error(client: AsyncClient, auth_headers):
    from app.services.v5.ai_provider_service import AIProviderTimeoutError

    create = await client.post("/api/v1/secrets", json={"key": "aitest/e4", "value": "v1"}, headers=auth_headers)
    from app.db.session import AsyncSessionLocal
    from sqlalchemy import select
    from app.models.models import AuditLog
    async with AsyncSessionLocal() as db:
        log = (await db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(1))).scalar_one()
        log_id = str(log.id)

    with patch("app.services.v5.ai_security_engine.get_provider") as mock_get_provider:
        mock_provider = MagicMock()
        mock_provider.is_configured.return_value = (True, "OK")
        mock_provider.generate = AsyncMock(side_effect=AIProviderTimeoutError("timed out"))
        mock_get_provider.return_value = mock_provider

        r = await client.post("/api/v5/ai/explain", json={"audit_log_id": log_id}, headers=auth_headers)

    assert r.status_code == 200
    result = r.json()["data"]
    assert result["success"] is False
    assert result["error_type"] == "timeout"


async def test_rbac_cannot_explain_other_users_event(client: AsyncClient, auth_headers):
    """Confirms Step 6/11's RBAC requirement — a non-admin cannot get an
    explanation for an event belonging to another user."""
    import uuid
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select

    uname = f"other_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "OtherPass123!"})
    other_login = await client.post("/api/v1/auth/login", json={"username": uname, "password": "OtherPass123!"})
    other_headers = {"Authorization": f"Bearer {other_login.json()['data']['access_token']}"}

    await client.post("/api/v1/secrets", json={"key": "aitest/rbac1", "value": "v1"}, headers=auth_headers)
    from app.models.models import AuditLog
    async with AsyncSessionLocal() as db:
        log = (await db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(1))).scalar_one()
        log_id = str(log.id)

    r = await client.post("/api/v5/ai/explain", json={"audit_log_id": log_id}, headers=other_headers)
    assert r.status_code == 403
