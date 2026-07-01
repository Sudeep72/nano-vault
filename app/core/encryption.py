"""
Encryption Service — AES-256-GCM
Every secret value is encrypted at rest. Each encryption call generates a
fresh 96-bit nonce; nonce + ciphertext + tag are stored together (base64).
"""
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.config import settings


class EncryptionService:
    """
    AES-256-GCM symmetric encryption.

    Storage format (base64-encoded):
        [12-byte nonce][16-byte GCM tag][N-byte ciphertext]
    The GCM tag is appended by cryptography automatically after the ciphertext,
    so the raw bytes layout after decrypt is transparent to callers.
    """

    def __init__(self) -> None:
        raw_key = base64.b64decode(settings.ENCRYPTION_KEY)
        if len(raw_key) != 32:
            raise ValueError("ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256).")
        self._aesgcm = AESGCM(raw_key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext string, return base64-encoded blob."""
        nonce = os.urandom(12)  # 96-bit nonce — NIST recommended for GCM
        data = plaintext.encode("utf-8")
        # cryptography appends 16-byte tag to ciphertext automatically
        ciphertext_with_tag = self._aesgcm.encrypt(nonce, data, associated_data=None)
        blob = nonce + ciphertext_with_tag
        return base64.b64encode(blob).decode("utf-8")

    def decrypt(self, blob_b64: str) -> str:
        """Decrypt base64-encoded blob, return plaintext string."""
        blob = base64.b64decode(blob_b64)
        nonce = blob[:12]
        ciphertext_with_tag = blob[12:]
        data = self._aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
        return data.decode("utf-8")

    @staticmethod
    def generate_key_b64() -> str:
        """Helper: generate a fresh AES-256 key, base64-encoded. Use once at bootstrap."""
        return base64.b64encode(os.urandom(32)).decode("utf-8")


# Module-level singleton
encryption_service = EncryptionService()
