"""Unit tests — Encryption Service (AES-256-GCM)."""
import base64
import os
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _direct_enc(key32: bytes, plaintext: str) -> bytes:
    """Encrypt directly via AESGCM without going through settings."""
    nonce = os.urandom(12)
    ct = AESGCM(key32).encrypt(nonce, plaintext.encode(), None)
    return nonce + ct


def _direct_dec(key32: bytes, blob: bytes) -> str:
    return AESGCM(key32).decrypt(blob[:12], blob[12:], None).decode()


# -- EncryptionService tests (via module-level singleton, key set in conftest) --

def test_encrypt_returns_string():
    from app.core.encryption import encryption_service
    blob = encryption_service.encrypt("hello world")
    assert isinstance(blob, str) and len(blob) > 0


def test_decrypt_roundtrip():
    from app.core.encryption import encryption_service
    assert encryption_service.decrypt(encryption_service.encrypt("super-secret-api-key")) == "super-secret-api-key"


def test_unique_ciphertext_per_call():
    from app.core.encryption import encryption_service
    assert encryption_service.encrypt("same") != encryption_service.encrypt("same")


def test_different_plaintexts():
    from app.core.encryption import encryption_service
    assert encryption_service.encrypt("a") != encryption_service.encrypt("b")


def test_tampered_blob_raises():
    from app.core.encryption import encryption_service
    blob = encryption_service.encrypt("sensitive")
    tampered = blob[:-4] + "XXXX"
    with pytest.raises(Exception):
        encryption_service.decrypt(tampered)


def test_wrong_key_raises():
    """Different AES key must not decrypt ciphertext from another key."""
    key1, key2 = os.urandom(32), os.urandom(32)
    blob = _direct_enc(key1, "secret")
    with pytest.raises(Exception):
        _direct_dec(key2, blob)


def test_generate_key_length():
    from app.core.encryption import EncryptionService
    assert len(base64.b64decode(EncryptionService.generate_key_b64())) == 32


def test_unicode_roundtrip():
    from app.core.encryption import encryption_service
    text = "密码: top secret"
    assert encryption_service.decrypt(encryption_service.encrypt(text)) == text


def test_invalid_key_length_raises():
    with pytest.raises((ValueError, Exception)):
        AESGCM(b"tooshort")
