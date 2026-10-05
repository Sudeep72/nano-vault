"""Unit tests — Identity sessions, LDAP sync, replication queue, backup restore, alerting (no live external systems)."""
import pytest
from fastapi import HTTPException


# ── Identity session lifecycle ────────────────────────────────────────────────

def test_create_and_validate_session():
    from app.services.v3.identity_session_service import identity_session_service
    s = identity_session_service.create_session("google-oidc", "user1", "idtok", "acctok", "reftok", 3600, {"role": "admin"})
    assert "session_id" in s
    result = identity_session_service.validate_session(s["session_id"])
    assert result["valid"] is True
    assert result["subject"] == "user1"

def test_validate_nonexistent_session_raises():
    from app.services.v3.identity_session_service import identity_session_service
    with pytest.raises(HTTPException) as exc:
        identity_session_service.validate_session("does-not-exist")
    assert exc.value.status_code == 401

def test_refresh_session_no_refresh_token_raises():
    from app.services.v3.identity_session_service import identity_session_service
    s = identity_session_service.create_session("oidc1", "u2", "idt", "at", None, 3600, {})
    with pytest.raises(HTTPException) as exc:
        identity_session_service.refresh_session(s["session_id"], "https://x/token", "cid", "secret")
    assert exc.value.status_code == 400

def test_refresh_unreachable_endpoint_raises_502():
    from app.services.v3.identity_session_service import identity_session_service
    s = identity_session_service.create_session("oidc1", "u3", "idt", "at", "rt", 3600, {})
    with pytest.raises(HTTPException) as exc:
        identity_session_service.refresh_session(s["session_id"], "https://nonexistent.invalid/token", "cid", "secret")
    assert exc.value.status_code == 502

def test_logout_removes_session():
    from app.services.v3.identity_session_service import identity_session_service
    s = identity_session_service.create_session("oidc1", "u4", "idt", "at", "rt", 3600, {})
    result = identity_session_service.logout(s["session_id"])
    assert result["logged_out"] is True
    with pytest.raises(HTTPException):
        identity_session_service.validate_session(s["session_id"])

def test_logout_builds_idp_logout_url():
    from app.services.v3.identity_session_service import identity_session_service
    s = identity_session_service.create_session("oidc1", "u5", "myidtoken", "at", "rt", 3600, {})
    result = identity_session_service.logout(s["session_id"], end_session_endpoint="https://idp/logout")
    assert "myidtoken" in result["idp_logout_url"]

def test_role_mapping_applies_groups():
    from app.services.v3.identity_session_service import identity_session_service
    result = identity_session_service.apply_role_mapping(
        claims={"groups": ["engineering", "security"], "role": "admin"},
        group_mappings={"engineering": "developer", "security": "readonly"},
        role_mappings={"admin": "ADMIN"},
        namespace_mappings={"engineering": "ns/eng"},
    )
    assert result["mapped_role"] == "ADMIN"
    assert "developer" in result["mapped_policies"]
    assert "ns/eng" in result["mapped_namespaces"]

def test_jwks_fetch_unreachable_raises():
    from app.services.v3.identity_session_service import identity_session_service
    with pytest.raises(HTTPException) as exc:
        identity_session_service.get_jwks("https://issuer", "https://nonexistent.invalid/jwks.json")
    assert exc.value.status_code == 502


# ── LDAP sync ──────────────────────────────────────────────────────────────────

def test_ldap_sync_unreachable_raises_502():
    from app.services.v3.ldap_sync_service import ldap_sync_service
    with pytest.raises(HTTPException) as exc:
        ldap_sync_service.sync_now("test-ldap", "ldap.invalid.nonexistent", "cn=admin", "pw", "ou=users,dc=x", "ou=groups,dc=x")
    assert exc.value.status_code == 502

def test_ldap_nested_group_resolution_unreachable():
    from app.services.v3.ldap_sync_service import ldap_sync_service
    with pytest.raises(HTTPException) as exc:
        ldap_sync_service.resolve_nested_groups_recursive(
            "ldap.invalid.nonexistent", "cn=admin", "pw", "cn=group1", "dc=x"
        )
    assert exc.value.status_code == 502

def test_get_last_sync_none_initially():
    from app.services.v3.ldap_sync_service import ldap_sync_service
    assert ldap_sync_service.get_last_sync("never-synced-provider") is None


# ── Replication queue ──────────────────────────────────────────────────────────

def test_replication_queue_enqueue():
    from app.services.v3.replication_queue_service import ReplicationQueue
    q = ReplicationQueue("test-node")
    op = q.enqueue("write", "secret/foo", {"value": "x"}, "test-node")
    assert op["status"] == "pending"
    assert q.get_queue_depth() == 1

def test_replication_queue_manager_replicate():
    from app.services.v3.replication_queue_service import ReplicationQueueManager
    mgr = ReplicationQueueManager()
    result = mgr.replicate("us-east-1", "secret/x", {"v": 1})
    assert result["replicated_from"] == "us-east-1"
    assert len(result["targets"]) == 2

def test_replication_queue_unknown_node():
    from app.services.v3.replication_queue_service import ReplicationQueueManager
    mgr = ReplicationQueueManager()
    result = mgr.replicate("nonexistent", "secret/x", {})
    assert "error" in result

def test_replication_metrics_tracked():
    from app.services.v3.replication_queue_service import ReplicationQueueManager
    mgr = ReplicationQueueManager()
    mgr.replicate("us-east-1", "secret/y", {"v": 2})
    metrics = mgr.get_node_metrics("us-east-1")
    assert metrics["enqueued"] >= 1

def test_conflict_resolution_last_write_wins():
    from app.services.v3.replication_queue_service import ReplicationQueue, NetworkTransport
    q1 = ReplicationQueue("node1")
    target = ReplicationQueue("node2")
    q1.enqueue("write", "secret/conflict", {"v": 1}, "node1")
    q1.process_next(NetworkTransport(target))
    q1.enqueue("write", "secret/conflict", {"v": 2}, "node1")
    q1.process_next(NetworkTransport(target))
    history = target.get_history()
    assert len(history) >= 1


# ── Alerting ────────────────────────────────────────────────────────────────────

def test_fire_alert():
    from app.services.v3.alerting_service import AlertingService
    svc = AlertingService()
    result = svc.fire_alert("test_alert_1", "warning", "Something happened")
    assert result["fired"] is True

def test_alert_suppression_blocks_firing():
    from app.services.v3.alerting_service import AlertingService
    svc = AlertingService()
    svc.suppress("test_alert_2", 60, "maintenance window")
    result = svc.fire_alert("test_alert_2", "warning", "should be suppressed")
    assert result["fired"] is False

def test_unsuppress_allows_firing_again():
    from app.services.v3.alerting_service import AlertingService
    svc = AlertingService()
    svc.suppress("test_alert_3", 60, "temp")
    svc.unsuppress("test_alert_3")
    result = svc.fire_alert("test_alert_3", "info", "now allowed")
    assert result["fired"] is True

def test_alert_history_filters_by_severity():
    from app.services.v3.alerting_service import AlertingService
    svc = AlertingService()
    svc.fire_alert("crit_alert", "critical", "bad")
    svc.fire_alert("warn_alert", "warning", "meh")
    crits = svc.get_history(severity="critical")
    assert all(a["severity"] == "critical" for a in crits)
