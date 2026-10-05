"""Unit tests — AI Security Engine finding-shape validation (pure logic, no DB/network)."""
from app.services.v5.ai_security_engine import AISecurityEngine


def test_validate_finding_shape_accepts_valid():
    valid = {
        "summary": "test", "observed_evidence": ["a"], "ai_inference": ["b"],
        "confidence": "medium", "severity": "low", "recommended_actions": ["c"],
    }
    assert AISecurityEngine._validate_finding_shape(valid) is not None


def test_validate_finding_shape_rejects_missing_field():
    invalid = {"summary": "test", "confidence": "medium"}
    assert AISecurityEngine._validate_finding_shape(invalid) is None


def test_validate_finding_shape_rejects_bad_confidence_enum():
    invalid = {
        "summary": "test", "observed_evidence": [], "ai_inference": [],
        "confidence": "super-duper-sure", "severity": "low", "recommended_actions": [],
    }
    assert AISecurityEngine._validate_finding_shape(invalid) is None


def test_validate_finding_shape_rejects_bad_severity_enum():
    invalid = {
        "summary": "test", "observed_evidence": [], "ai_inference": [],
        "confidence": "low", "severity": "apocalyptic", "recommended_actions": [],
    }
    assert AISecurityEngine._validate_finding_shape(invalid) is None


def test_validate_finding_shape_rejects_none():
    assert AISecurityEngine._validate_finding_shape(None) is None


def test_validate_finding_shape_rejects_non_dict():
    assert AISecurityEngine._validate_finding_shape("not a dict") is None


def test_validate_finding_shape_accepts_insufficient_evidence_confidence():
    valid = {
        "summary": "test", "observed_evidence": [], "ai_inference": [],
        "confidence": "insufficient_evidence", "severity": "info", "recommended_actions": [],
    }
    assert AISecurityEngine._validate_finding_shape(valid) is not None
