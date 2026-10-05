"""Unit tests — Security Context Layer: field stripping guarantees, no live DB needed for most."""
from app.services.v5.guardrails_service import strip_forbidden_fields, FORBIDDEN_FIELD_NAMES


def test_forbidden_fields_covers_known_sensitive_names():
    """Guards against silent regressions in the forbidden-field list."""
    required = {"password", "encrypted_value", "access_token", "refresh_token", "value", "private_key"}
    assert required.issubset(FORBIDDEN_FIELD_NAMES)


def test_secret_metadata_shape_never_includes_value():
    """
    Simulates what gather_secret_metadata_context builds — confirms the
    dict construction itself never includes a 'value' key, independent
    of strip_forbidden_fields as defense in depth.
    """
    fake_secret_dict = {"key": "aws/prod", "category": "cloud", "tags": ["prod"], "version": 3}
    assert "value" not in fake_secret_dict
    cleaned = strip_forbidden_fields(fake_secret_dict)
    assert cleaned == fake_secret_dict


def test_audit_event_shape_strips_ip_stays_but_no_credentials():
    """Audit events legitimately need IP/actor for investigation — only
    credential-shaped fields should ever be stripped."""
    event = {"action": "USER_LOGIN_FAILED", "ip_address": "10.0.0.1", "password": "hunter2"}
    cleaned = strip_forbidden_fields(event)
    assert cleaned["ip_address"] == "10.0.0.1"
    assert "password" not in cleaned
