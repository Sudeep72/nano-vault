"""Unit tests — v6 Risk Engine, Correlation Engine, Investigation state machine. Pure logic, no DB."""
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from app.models.models import AuditAction, AIFindingStatus, UserRole
from app.services.v6.risk_engine import (
    _rule_repeated_auth_failures, _rule_ip_churn, _rule_failed_then_success,
    _rule_high_volume_reads, _rule_priv_ops, _rule_unusual_timing, RiskEngine,
)
from app.services.v6.correlation_service import (
    _rule_login_secret_lifecycle, _rule_failed_burst_sensitive, _rule_new_ip_secret, CorrelationEngine,
)
from app.services.v6.investigation_service import VALID_TRANSITIONS, _is_authorized

_now = lambda: datetime.now(timezone.utc)


def _log(action, ip=None, user_id=None, hour=None, resource_id=None, offset_minutes=0):
    ts = _now() + timedelta(minutes=offset_minutes)
    if hour is not None:
        ts = ts.replace(hour=hour)
    return SimpleNamespace(id=uuid.uuid4(), action=action, ip_address=ip, user_id=user_id or uuid.uuid4(), created_at=ts, resource_id=resource_id)


# ── Risk Engine rules ─────────────────────────────────────────────────────────

def test_repeated_auth_failures_thresholds():
    assert _rule_repeated_auth_failures([_log(AuditAction.USER_LOGIN_FAILED) for _ in range(2)]).triggered is False
    r = _rule_repeated_auth_failures([_log(AuditAction.USER_LOGIN_FAILED) for _ in range(3)])
    assert r.triggered and r.points == 15
    r2 = _rule_repeated_auth_failures([_log(AuditAction.USER_LOGIN_FAILED) for _ in range(6)])
    assert r2.triggered and r2.points == 30

def test_ip_churn_thresholds():
    assert _rule_ip_churn([_log(AuditAction.USER_LOGIN, ip="10.0.0.1")]).triggered is False
    r = _rule_ip_churn([_log(AuditAction.USER_LOGIN, ip=f"10.0.0.{i}") for i in range(4)])
    assert r.triggered and r.points == 20

def test_failed_then_success_pattern():
    uid = uuid.uuid4()
    logs = [_log(AuditAction.USER_LOGIN_FAILED, user_id=uid, offset_minutes=i) for i in range(3)] + [_log(AuditAction.USER_LOGIN, user_id=uid, offset_minutes=3)]
    r = _rule_failed_then_success(logs)
    assert r.triggered and r.points == 35

def test_high_volume_reads():
    r = _rule_high_volume_reads([_log(AuditAction.SECRET_READ, resource_id=str(i)) for i in range(25)])
    assert r.triggered and r.points == 25

def test_priv_ops():
    logs = [_log(AuditAction.VAULT_TOKEN_CREATE), _log(AuditAction.POLICY_CREATE), _log(AuditAction.ORG_CREATE)]
    r = _rule_priv_ops(logs)
    assert r.triggered and r.points == 20

def test_unusual_timing():
    r = _rule_unusual_timing([_log(AuditAction.SECRET_READ, hour=2) for _ in range(5)])
    assert r.triggered is True

def test_run_rules_empty():
    result = RiskEngine._run([], "user", "x", 24)
    assert result["risk_score"] == 0 and result["risk_level"] == "low"

def test_run_rules_capped_at_100():
    uid = uuid.uuid4()
    logs = ([_log(AuditAction.USER_LOGIN_FAILED, user_id=uid) for _ in range(6)]
           + [_log(AuditAction.SECRET_READ, resource_id=str(i)) for i in range(25)]
           + [_log(AuditAction.VAULT_TOKEN_CREATE), _log(AuditAction.POLICY_CREATE), _log(AuditAction.ORG_CREATE)])
    result = RiskEngine._run(logs, "user", str(uid), 24)
    assert result["risk_score"] <= 100 and result["risk_level"] == "critical"

def test_list_rules():
    assert len(RiskEngine.list_rules()) == 6


# ── Correlation Engine rules ────────────────────────────────────────────────

def test_login_secret_lifecycle_matches():
    uid = uuid.uuid4()
    logs = [_log(AuditAction.USER_LOGIN, user_id=uid, offset_minutes=0),
            _log(AuditAction.SECRET_READ, user_id=uid, offset_minutes=5),
            _log(AuditAction.SECRET_CREATE, user_id=uid, offset_minutes=10)]
    matches = _rule_login_secret_lifecycle(logs)
    assert len(matches) == 1 and len(matches[0].event_ids) == 3

def test_login_secret_lifecycle_no_match_without_create():
    uid = uuid.uuid4()
    logs = [_log(AuditAction.USER_LOGIN, user_id=uid), _log(AuditAction.SECRET_READ, user_id=uid, offset_minutes=5)]
    assert _rule_login_secret_lifecycle(logs) == []

def test_failed_burst_sensitive_matches():
    uid = uuid.uuid4()
    logs = ([_log(AuditAction.USER_LOGIN_FAILED, user_id=uid, offset_minutes=i) for i in range(3)]
           + [_log(AuditAction.USER_LOGIN, user_id=uid, offset_minutes=3)]
           + [_log(AuditAction.VAULT_TOKEN_CREATE, user_id=uid, offset_minutes=5)])
    matches = _rule_failed_burst_sensitive(logs)
    assert len(matches) == 1 and matches[0].points == 40

def test_failed_burst_no_sensitive_op_no_match():
    uid = uuid.uuid4()
    logs = [_log(AuditAction.USER_LOGIN_FAILED, user_id=uid, offset_minutes=i) for i in range(3)] + [_log(AuditAction.USER_LOGIN, user_id=uid, offset_minutes=3)]
    assert _rule_failed_burst_sensitive(logs) == []

def test_new_ip_secret_access_matches():
    logs = [_log(AuditAction.USER_LOGIN, ip="10.0.0.1"), _log(AuditAction.SECRET_READ, ip="10.0.0.1", offset_minutes=2)]
    matches = _rule_new_ip_secret(logs)
    assert len(matches) == 1

def test_run_correlations_empty():
    result = CorrelationEngine._run([], "user", "x", 24)
    assert result["chains_found"] == 0 and result["correlation_score"] == 0

def test_correlation_list_rules():
    assert len(CorrelationEngine.list_rules()) == 3


# ── Investigation Workflow state machine ────────────────────────────────────

def test_state_machine_shape():
    assert VALID_TRANSITIONS[AIFindingStatus.OPEN] == {AIFindingStatus.INVESTIGATING, AIFindingStatus.DISMISSED}
    assert VALID_TRANSITIONS[AIFindingStatus.INVESTIGATING] == {AIFindingStatus.ACKNOWLEDGED, AIFindingStatus.DISMISSED}
    assert VALID_TRANSITIONS[AIFindingStatus.ACKNOWLEDGED] == {AIFindingStatus.RESOLVED, AIFindingStatus.DISMISSED}
    assert VALID_TRANSITIONS[AIFindingStatus.RESOLVED] == set()
    assert VALID_TRANSITIONS[AIFindingStatus.DISMISSED] == set()

def test_cannot_skip_states():
    assert AIFindingStatus.ACKNOWLEDGED not in VALID_TRANSITIONS[AIFindingStatus.OPEN]
    assert AIFindingStatus.RESOLVED not in VALID_TRANSITIONS[AIFindingStatus.OPEN]
    assert AIFindingStatus.RESOLVED not in VALID_TRANSITIONS[AIFindingStatus.INVESTIGATING]

def test_every_status_has_transition_entry():
    for status in AIFindingStatus:
        assert status in VALID_TRANSITIONS

def test_authorization_helper():
    uid = uuid.uuid4()
    creator_finding = SimpleNamespace(created_by=uid)
    assert _is_authorized(creator_finding, SimpleNamespace(id=uid, role=UserRole.USER)) is True
    assert _is_authorized(creator_finding, SimpleNamespace(id=uuid.uuid4(), role=UserRole.USER)) is False
    assert _is_authorized(creator_finding, SimpleNamespace(id=uuid.uuid4(), role=UserRole.ADMIN)) is True
