"""Unit tests — JWT + Password hashing."""
import pytest
from app.core.security import (
    hash_password, verify_password, create_access_token,
    create_refresh_token, decode_token, CREDENTIALS_EXCEPTION
)
from fastapi import HTTPException


def test_hash_password_not_plaintext():
    h = hash_password("MyPassword1!")
    assert h != "MyPassword1!"
    assert len(h) > 20


def test_verify_password_correct():
    h = hash_password("MyPassword1!")
    assert verify_password("MyPassword1!", h) is True


def test_verify_password_wrong():
    h = hash_password("MyPassword1!")
    assert verify_password("WrongPassword", h) is False


def test_access_token_decode():
    token = create_access_token("user-123", "user")
    payload = decode_token(token, "access")
    assert payload["sub"] == "user-123"
    assert payload["role"] == "user"
    assert payload["type"] == "access"


def test_refresh_token_decode():
    token = create_refresh_token("user-456")
    payload = decode_token(token, "refresh")
    assert payload["sub"] == "user-456"
    assert payload["type"] == "refresh"


def test_wrong_token_type_raises():
    access = create_access_token("u1", "user")
    with pytest.raises(HTTPException) as exc_info:
        decode_token(access, expected_type="refresh")
    assert exc_info.value.status_code == 401


def test_invalid_token_raises():
    with pytest.raises(HTTPException):
        decode_token("not.a.valid.token", "access")


def test_tampered_token_raises():
    token = create_access_token("u1", "user")
    parts = token.split(".")
    parts[1] = parts[1][::-1]  # flip payload
    with pytest.raises(HTTPException):
        decode_token(".".join(parts), "access")
