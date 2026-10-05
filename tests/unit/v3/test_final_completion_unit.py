"""Unit tests — OTel, Redis fallback, real identity protocols, replication, backup logic (no DB/server)."""
import base64
import pytest
from fastapi import HTTPException


# ── OTel ──────────────────────────────────────────────────────────────────────

def test_otel_status_disabled_by_default():
    from app.services.v3.otel_service import status
    s = status()
    assert s["enabled"] is False
    assert "jaeger" in s["supported_collectors"]

def test_otel_trace_context_disabled():
    from app.services.v3.otel_service import get_trace_context
    ctx = get_trace_context()
    assert ctx["enabled"] is False
    assert ctx["trace_id"] is None

def test_otel_init_noop_without_endpoint():
    from app.services.v3.otel_service import init_tracing
    result = init_tracing("test-service", otlp_endpoint="")
    assert result is None


# ── Redis cache fallback ──────────────────────────────────────────────────────

def test_cache_health_fallback_when_no_redis():
    from app.services.v3 import cache_service
    cache_service._available = False
    h = cache_service.health()
    assert h["available"] is False

def test_cache_get_returns_none_when_unavailable():
    from app.services.v3 import cache_service
    cache_service._available = False
    assert cache_service.cache_get("policy", "somekey") is None

def test_cache_set_returns_false_when_unavailable():
    from app.services.v3 import cache_service
    cache_service._available = False
    assert cache_service.cache_set("policy", "k", {"a": 1}) is False

def test_cache_stats_structure():
    from app.services.v3.cache_service import get_stats, CACHE_NAMESPACES
    stats = get_stats()
    assert "hit_rate" in stats
    assert "secret_metadata" in CACHE_NAMESPACES


# ── Real identity protocols ────────────────────────────────────────────────────

def test_pkce_pair_generation():
    from app.services.v3.real_identity_service import OIDCFlow
    pair = OIDCFlow.generate_pkce_pair()
    assert "code_verifier" in pair
    assert "code_challenge" in pair
    assert pair["code_challenge_method"] == "S256"
    assert len(pair["code_verifier"]) > 20

def test_pkce_challenge_is_deterministic_from_verifier():
    import hashlib
    from app.services.v3.real_identity_service import OIDCFlow
    pair = OIDCFlow.generate_pkce_pair()
    recomputed = base64.urlsafe_b64encode(
        hashlib.sha256(pair["code_verifier"].encode()).digest()
    ).rstrip(b"=").decode()
    assert recomputed == pair["code_challenge"]

def test_build_authorization_url():
    from app.services.v3.real_identity_service import OIDCFlow
    url = OIDCFlow.build_authorization_url(
        "https://accounts.google.com", "client123", "https://app/cb",
        ["openid", "email"], "challenge123", state="s1",
    )
    assert "client_id=client123" in url
    assert "code_challenge=challenge123" in url
    assert "state=s1" in url

def test_jwt_validate_with_bad_jwks_url_raises():
    from app.services.v3.real_identity_service import JWTValidator
    with pytest.raises(HTTPException) as exc:
        JWTValidator.validate_with_jwks("fake.token.here", "https://nonexistent.invalid/jwks.json", "iss", "aud")
    assert exc.value.status_code in (401, 502)

def test_jwt_decode_unverified():
    import jwt as pyjwt
    from app.services.v3.real_identity_service import JWTValidator
    token = pyjwt.encode({"sub": "user1", "role": "admin"}, "secret", algorithm="HS256")
    payload = JWTValidator.decode_unverified(token)
    assert payload["sub"] == "user1"

def test_map_claims():
    from app.services.v3.real_identity_service import JWTValidator
    claims = JWTValidator.map_claims({"sub": "u1", "role": "admin", "groups": ["eng"]})
    assert claims["subject"] == "u1"
    assert claims["role"] == "admin"

def test_ldap_authenticate_unreachable_server_raises():
    from app.services.v3.real_identity_service import LDAPAuthenticator
    with pytest.raises(HTTPException) as exc:
        LDAPAuthenticator.authenticate(
            "ldap.invalid.nonexistent", "cn=admin", "pass",
            "ou=users,dc=x", "someuser", "pw",
        )
    assert exc.value.status_code == 502

def test_ldap_nested_group_dedup():
    from app.services.v3.real_identity_service import LDAPAuthenticator
    result = LDAPAuthenticator.resolve_nested_groups(["cn=a", "cn=b", "cn=a"])
    assert result == ["cn=a", "cn=b"]

def test_saml_parse_valid_metadata():
    from app.services.v3.real_identity_service import SAMLHelper
    xml = '''<?xml version="1.0"?>
    <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
      <IDPSSODescriptor>
        <SingleSignOnService Location="https://idp.example.com/sso" Binding="x"/>
      </IDPSSODescriptor>
    </EntityDescriptor>'''
    result = SAMLHelper.parse_metadata(xml)
    assert result["entity_id"] == "https://idp.example.com"

def test_saml_parse_invalid_xml_raises():
    from app.services.v3.real_identity_service import SAMLHelper
    with pytest.raises(HTTPException):
        SAMLHelper.parse_metadata("not valid xml <<<")


# ── Replication ────────────────────────────────────────────────────────────────

def test_replication_topology_has_primary():
    from app.services.v3.replication_service import ReplicationService
    svc = ReplicationService()
    topo = svc.get_topology()
    assert topo["primary"] == "us-east-1"
    assert len(topo["regions"]) == 3

def test_replication_write_on_non_primary_fails():
    from app.services.v3.replication_service import ReplicationService
    svc = ReplicationService()
    result = svc.simulate_write("us-west-2")
    assert "error" in result

def test_replication_write_propagates():
    from app.services.v3.replication_service import ReplicationService
    svc = ReplicationService()
    result = svc.simulate_write("us-east-1")
    assert result["primary_version"] == 1
    assert "us-west-2" in result["propagated_to"]

def test_replication_no_conflicts_after_sync():
    from app.services.v3.replication_service import ReplicationService
    svc = ReplicationService()
    svc.simulate_write("us-east-1")
    conflicts = svc.detect_conflicts()
    assert conflicts == []

def test_replication_failover_promotes_new_primary():
    from app.services.v3.replication_service import ReplicationService
    svc = ReplicationService()
    result = svc.failover("us-west-2")
    assert result["new_primary"] == "us-west-2"
    assert result["old_primary"] == "us-east-1"
    topo = svc.get_topology()
    assert topo["primary"] == "us-west-2"

def test_replication_promote_read_replica():
    from app.services.v3.replication_service import ReplicationService
    svc = ReplicationService()
    result = svc.promote("eu-west-1")
    assert result["new_role"] == "secondary"

def test_replication_promote_already_primary_errors():
    from app.services.v3.replication_service import ReplicationService
    svc = ReplicationService()
    result = svc.promote("us-east-1")
    assert "error" in result


# ── Security hardening ──────────────────────────────────────────────────────────

def test_csrf_token_generation_and_validation():
    from app.middleware.hardening import CSRFService
    svc = CSRFService("test-secret-key")
    token = svc.generate_token("session123")
    assert svc.validate_token(token) is True

def test_csrf_token_tampered_fails():
    from app.middleware.hardening import CSRFService
    svc = CSRFService("test-secret-key")
    token = svc.generate_token("session123")
    tampered = token[:-4] + "xxxx"
    assert svc.validate_token(tampered) is False

def test_brute_force_lockout_tracking():
    from app.middleware.hardening import record_failed_login, is_locked_out, clear_failed_logins, get_lockout_status
    identifier = "test-user-bf"
    clear_failed_logins(identifier)
    for _ in range(5):
        record_failed_login(identifier)
    assert is_locked_out(identifier) is True
    status = get_lockout_status(identifier)
    assert status["locked"] is True
    clear_failed_logins(identifier)
    assert is_locked_out(identifier) is False

def test_secret_redaction():
    from app.middleware.hardening import secure_redaction
    text = 'password="supersecret123" and token: abc123XYZlong'
    redacted = secure_redaction(text)
    assert "supersecret123" not in redacted
    assert "REDACTED" in redacted
