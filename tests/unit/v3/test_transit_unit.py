"""Unit tests — Transit Engine crypto primitives (no DB)."""
import base64, pytest
from app.engines.transit.engine import (
    _aes_enc, _aes_dec, _chacha_enc, _chacha_dec,
    _rsa_sign, _rsa_verify, _ed_sign, _ed_verify,
    _sha256, _sha512, _hmac_sha256,
    _gen_aes, _gen_chacha, _gen_rsa, _gen_ed25519,
)

def test_aes_roundtrip():
    k = _gen_aes(); pt = b"hello"
    assert _aes_dec(k, _aes_enc(k, pt)) == pt

def test_aes_unique_ciphertext():
    k = _gen_aes()
    assert _aes_enc(k, b"same") != _aes_enc(k, b"same")

def test_aes_wrong_key_fails():
    k1, k2 = _gen_aes(), _gen_aes()
    with pytest.raises(Exception): _aes_dec(k2, _aes_enc(k1, b"secret"))

def test_chacha_roundtrip():
    k = _gen_chacha(); pt = b"chacha data"
    assert _chacha_dec(k, _chacha_enc(k, pt)) == pt

def test_rsa_sign_verify():
    priv, pub = _gen_rsa()
    sig = _rsa_sign(priv, b"data")
    assert _rsa_verify(pub, b"data", sig) is True
    assert _rsa_verify(pub, b"other", sig) is False

def test_ed25519_sign_verify():
    priv, pub = _gen_ed25519()
    sig = _ed_sign(priv, b"data")
    assert _ed_verify(pub, b"data", sig) is True
    assert _ed_verify(pub, b"tampered", sig) is False

def test_sha256_sha512_deterministic():
    assert _sha256(b"x") == _sha256(b"x")
    assert len(_sha256(b"x")) == 64
    assert len(_sha512(b"x")) == 128
    assert _sha256(b"x") != _sha512(b"x")

def test_hmac_deterministic():
    k = _gen_aes()
    assert _hmac_sha256(k, b"msg") == _hmac_sha256(k, b"msg")
    assert _hmac_sha256(k, b"msg") != _hmac_sha256(k, b"other")
