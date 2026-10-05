"""Unit tests — Policy Engine path matching and permission logic."""
import pytest
from app.services.policy_service import _path_matches


def test_exact_match():
    assert _path_matches("aws/prod/key", "aws/prod/key") is True


def test_wildcard_match():
    assert _path_matches("aws/*", "aws/prod/key") is True
    assert _path_matches("aws/*", "aws/dev/secret") is True


def test_wildcard_no_match_other_prefix():
    assert _path_matches("aws/*", "gcp/prod/key") is False


def test_global_wildcard():
    assert _path_matches("*", "anything/at/all") is True
    assert _path_matches("*", "single") is True


def test_nested_path_wildcard():
    assert _path_matches("database/*", "database/prod/password") is True
    assert _path_matches("database/*", "database/dev/host") is True
    assert _path_matches("database/*", "aws/key") is False


def test_no_match_empty_key():
    assert _path_matches("aws/*", "") is False


def test_case_sensitive():
    assert _path_matches("AWS/*", "aws/key") is False
    assert _path_matches("aws/*", "AWS/key") is False


def test_production_path():
    assert _path_matches("production/*", "production/db/password") is True
    assert _path_matches("production/*", "dev/db/password") is False
