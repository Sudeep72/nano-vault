"""Integration tests — v6 Phases 1-5. Real DB, real RBAC, mocked Gemini."""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _admin(client):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole
    from sqlalchemy import select
    import uuid
    uname = f"v6adm_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@nano.com", "password": "V6Admin123!"})
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User).where(User.username == uname))).scalar_one()
        u.role = UserRole.ADMIN
        await db.commit()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "V6Admin123!"})
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}


async def _create_risk_finding(client, admin, registered_user):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.username == registered_user["username"]))).scalar_one()
    r = await client.post(f"/api/v6/security/risk/users/{user.id}/assess", headers=admin)
    return r.json()["data"]["finding_id"]


def _mock_ai_response():
    from app.services.v5.ai_provider_service import AIResponse
    return AIResponse(raw_text="mocked", parsed={"summary": "s", "observed_evidence": ["e"], "ai_inference": ["credential guessing pattern"], "confidence": "high", "severity": "high", "recommended_actions": ["rotate token"], "related_entities": []}, provider="gemini", model="gemini-2.0-flash", latency_ms=10.0)


async def test_list_risk_rules(client: AsyncClient, auth_headers):
    r = await client.get("/api/v6/security/risk/rules", headers=auth_headers)
    assert r.status_code == 200 and len(r.json()["data"]) == 6

async def test_repeated_login_failures_produce_risk(client: AsyncClient):
    import uuid
    admin = await _admin(client)
    uname = f"target_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@x.com", "password": "RealPass123!"})
    for _ in range(5):
        await client.post("/api/v1/auth/login", json={"username": uname, "password": "Wrong!"})
    from app.db.session import AsyncSessionLocal
    from app.models.models import User
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        target = (await db.execute(select(User).where(User.username == uname))).scalar_one()
    r = await client.post(f"/api/v6/security/risk/users/{target.id}/assess", headers=admin)
    assert r.json()["data"]["assessment"]["risk_score"] >= 30

async def test_user_cannot_preview_others_risk(client: AsyncClient, auth_headers):
    import uuid
    r = await client.get(f"/api/v6/security/risk/users/{uuid.uuid4()}", headers=auth_headers)
    assert r.status_code == 403

async def test_non_admin_cannot_assess_and_record(client: AsyncClient, auth_headers, registered_user):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.username == registered_user["username"]))).scalar_one()
    r = await client.post(f"/api/v6/security/risk/users/{user.id}/assess", headers=auth_headers)
    assert r.status_code == 403

async def test_failed_login_audit_events_persisted(client: AsyncClient):
    import uuid
    from app.db.session import AsyncSessionLocal
    from app.models.models import AuditLog, AuditAction
    from sqlalchemy import select, func
    uname = f"audittest_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@x.com", "password": "RealPass123!"})
    async with AsyncSessionLocal() as db:
        before = (await db.execute(select(func.count()).select_from(AuditLog).where(AuditLog.action == AuditAction.USER_LOGIN_FAILED))).scalar_one()
    resp = await client.post("/api/v1/auth/login", json={"username": uname, "password": "Wrong!"})
    assert resp.status_code == 401
    async with AsyncSessionLocal() as db:
        after = (await db.execute(select(func.count()).select_from(AuditLog).where(AuditLog.action == AuditAction.USER_LOGIN_FAILED))).scalar_one()
    assert after == before + 1

async def test_list_correlation_rules(client: AsyncClient, auth_headers):
    r = await client.get("/api/v6/security/correlation/rules", headers=auth_headers)
    assert r.status_code == 200 and len(r.json()["data"]) == 3

async def test_credential_guessing_chain_detected(client: AsyncClient):
    import uuid
    admin = await _admin(client)
    uname = f"guess_{uuid.uuid4().hex[:6]}"
    await client.post("/api/v1/auth/register", json={"username": uname, "email": f"{uname}@x.com", "password": "RealPass123!"})
    for _ in range(3):
        await client.post("/api/v1/auth/login", json={"username": uname, "password": "Wrong!"})
    login = await client.post("/api/v1/auth/login", json={"username": uname, "password": "RealPass123!"})
    token = login.json()["data"]["access_token"]
    await client.post("/api/v2/tokens/create", json={"token_type": "service"}, headers={"Authorization": f"Bearer {token}"})

    from app.db.session import AsyncSessionLocal
    from app.models.models import User
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        target = (await db.execute(select(User).where(User.username == uname))).scalar_one()
    r = await client.post(f"/api/v6/security/correlation/users/{target.id}/assess", headers=admin)
    result = r.json()["data"]["correlation"]
    assert "failed_burst_success_sensitive_op" in result["triggered_chain_ids"]

async def test_explain_without_ai_configured(client: AsyncClient, registered_user):
    admin = await _admin(client)
    finding_id = await _create_risk_finding(client, admin, registered_user)
    r = await client.post(f"/api/v6/security/findings/{finding_id}/explain", json={}, headers=admin)
    assert r.json()["data"]["success"] is False
    assert r.json()["data"]["error_type"] == "unavailable"

async def test_explain_with_mocked_provider_preserves_deterministic_fields(client: AsyncClient, registered_user):
    admin = await _admin(client)
    finding_id = await _create_risk_finding(client, admin, registered_user)
    before = (await client.get(f"/api/v6/security/findings/{finding_id}", headers=admin)).json()["data"]

    with patch("app.services.v6.security_analyst_v6.get_provider") as mock_gp:
        mp = MagicMock(); mp.is_configured.return_value = (True, "OK"); mp.generate = AsyncMock(return_value=_mock_ai_response())
        mock_gp.return_value = mp
        r = await client.post(f"/api/v6/security/findings/{finding_id}/explain", json={}, headers=admin)

    assert r.json()["data"]["success"] is True
    after = r.json()["data"]["finding"]
    for field in ("risk_score", "risk_level", "triggered_rules", "evidence", "severity", "confidence"):
        assert before[field] == after[field]
    assert after["ai_provider"] == "gemini"

async def test_explain_rejects_wrong_category(client: AsyncClient, auth_headers):
    from app.db.session import AsyncSessionLocal
    from app.services.v5.findings_service import findings_service
    from app.models.models import User
    from sqlalchemy import select
    admin = await _admin(client)
    async with AsyncSessionLocal() as db:
        u = (await db.execute(select(User))).scalars().first()
        f = await findings_service.create_finding(db, u, category="event_explanation", severity="low", confidence="medium", summary="s", evidence=["e"], explanation=["i"], recommended_actions=["a"], related_entities=[], provider="gemini", model="m", latency_ms=1.0)
        await db.commit()
        fid = str(f.id)
    r = await client.post(f"/api/v6/security/findings/{fid}/explain", json={}, headers=admin)
    assert r.status_code == 400

async def test_full_lifecycle(client: AsyncClient, registered_user):
    admin = await _admin(client)
    finding_id = await _create_risk_finding(client, admin, registered_user)

    assert (await client.get(f"/api/v6/security/findings/{finding_id}", headers=admin)).json()["data"]["status"] == "open"
    assert (await client.post(f"/api/v6/security/findings/{finding_id}/investigate", headers=admin)).json()["data"]["status"] == "investigating"
    assert (await client.post(f"/api/v6/security/findings/{finding_id}/acknowledge", headers=admin)).json()["data"]["status"] == "acknowledged"
    res = await client.post(f"/api/v6/security/findings/{finding_id}/resolve", json={"resolution_note": "confirmed benign"}, headers=admin)
    assert res.json()["data"]["status"] == "resolved"

async def test_dismiss_from_each_valid_state(client: AsyncClient, registered_user):
    admin = await _admin(client)
    for path in [[], ["investigate"], ["investigate", "acknowledge"]]:
        finding_id = await _create_risk_finding(client, admin, registered_user)
        for step in path:
            await client.post(f"/api/v6/security/findings/{finding_id}/{step}", headers=admin)
        r = await client.post(f"/api/v6/security/findings/{finding_id}/dismiss", headers=admin)
        assert r.status_code == 200 and r.json()["data"]["status"] == "dismissed"

async def test_invalid_transitions_rejected(client: AsyncClient, registered_user):
    admin = await _admin(client)
    finding_id = await _create_risk_finding(client, admin, registered_user)
    assert (await client.post(f"/api/v6/security/findings/{finding_id}/acknowledge", headers=admin)).status_code == 409
    assert (await client.post(f"/api/v6/security/findings/{finding_id}/resolve", headers=admin)).status_code == 409

async def test_terminal_states_reject_all_transitions(client: AsyncClient, registered_user):
    admin = await _admin(client)
    finding_id = await _create_risk_finding(client, admin, registered_user)
    await client.post(f"/api/v6/security/findings/{finding_id}/investigate", headers=admin)
    await client.post(f"/api/v6/security/findings/{finding_id}/acknowledge", headers=admin)
    await client.post(f"/api/v6/security/findings/{finding_id}/resolve", headers=admin)
    assert (await client.post(f"/api/v6/security/findings/{finding_id}/investigate", headers=admin)).status_code == 409
    assert (await client.post(f"/api/v6/security/findings/{finding_id}/dismiss", headers=admin)).status_code == 409

async def test_non_creator_non_admin_forbidden(client: AsyncClient, auth_headers, registered_user):
    admin = await _admin(client)
    finding_id = await _create_risk_finding(client, admin, registered_user)
    assert (await client.get(f"/api/v6/security/findings/{finding_id}", headers=auth_headers)).status_code == 403
    assert (await client.post(f"/api/v6/security/findings/{finding_id}/investigate", headers=auth_headers)).status_code == 403
    assert (await client.post(f"/api/v6/security/findings/{finding_id}/dismiss", headers=auth_headers)).status_code == 403

async def test_admin_can_act_on_any_finding(client: AsyncClient, registered_user):
    admin1 = await _admin(client); admin2 = await _admin(client)
    finding_id = await _create_risk_finding(client, admin1, registered_user)
    r = await client.post(f"/api/v6/security/findings/{finding_id}/investigate", headers=admin2)
    assert r.status_code == 200

async def test_list_scoped_to_non_admin(client: AsyncClient, auth_headers, registered_user):
    admin = await _admin(client)
    await _create_risk_finding(client, admin, registered_user)
    from app.db.session import AsyncSessionLocal
    from app.models.models import User
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.username == "testuser"))).scalar_one()
    r = await client.get("/api/v6/security/findings", headers=auth_headers)
    for f in r.json()["data"]:
        assert f.get("created_by") == str(user.id)

async def test_every_transition_audited(client: AsyncClient, registered_user):
    admin = await _admin(client)
    finding_id = await _create_risk_finding(client, admin, registered_user)
    await client.post(f"/api/v6/security/findings/{finding_id}/investigate", headers=admin)
    await client.post(f"/api/v6/security/findings/{finding_id}/acknowledge", headers=admin)
    await client.post(f"/api/v6/security/findings/{finding_id}/resolve", headers=admin)
    from app.db.session import AsyncSessionLocal
    from app.models.models import AuditLog, AuditAction
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        entries = (await db.execute(select(AuditLog).where(AuditLog.action == AuditAction.AI_FINDING_STATUS_CHANGE, AuditLog.resource_id == finding_id))).scalars().all()
    assert len(entries) == 3

async def test_rejected_transition_not_audited(client: AsyncClient, registered_user):
    admin = await _admin(client)
    finding_id = await _create_risk_finding(client, admin, registered_user)
    await client.post(f"/api/v6/security/findings/{finding_id}/resolve", headers=admin)
    from app.db.session import AsyncSessionLocal
    from app.models.models import AuditLog, AuditAction
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        entries = (await db.execute(select(AuditLog).where(AuditLog.action == AuditAction.AI_FINDING_STATUS_CHANGE, AuditLog.resource_id == finding_id))).scalars().all()
    assert len(entries) == 0

async def test_v5_patch_endpoint_still_admin_only_unconstrained(client: AsyncClient, registered_user):
    admin = await _admin(client)
    finding_id = await _create_risk_finding(client, admin, registered_user)
    r = await client.patch(f"/api/v5/ai/findings/{finding_id}/status", json={"status": "resolved"}, headers=admin)
    assert r.status_code == 200 and r.json()["data"]["status"] == "resolved"
