from __future__ import annotations
import base64, hashlib, hmac as _hmac, os, secrets, uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException
from app.engines.base import BaseSecretsEngine, engine_registry
from app.models.models import TransitKey, TransitKeyVersion, TransitKeyType, TransitKeyStatus
from app.core.encryption import encryption_service

def _now(): return datetime.now(timezone.utc)
def _b64e(b): return base64.b64encode(b).decode()
def _b64d(s): return base64.b64decode(s)

def _gen_aes(): return os.urandom(32)
def _gen_chacha(): return os.urandom(32)
def _gen_rsa():
    k = rsa.generate_private_key(65537, 4096, default_backend())
    return (k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
def _gen_ed25519():
    k = Ed25519PrivateKey.generate()
    return (k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

def _aes_enc(key, pt):
    n = os.urandom(12); return _b64e(n + AESGCM(key).encrypt(n, pt, None))
def _aes_dec(key, ct): b=_b64d(ct); return AESGCM(key).decrypt(b[:12], b[12:], None)
def _chacha_enc(key, pt):
    n = os.urandom(12); return _b64e(n + ChaCha20Poly1305(key).encrypt(n, pt, None))
def _chacha_dec(key, ct): b=_b64d(ct); return ChaCha20Poly1305(key).decrypt(b[:12], b[12:], None)
def _rsa_enc(pub, pt):
    return _b64e(serialization.load_pem_public_key(pub).encrypt(pt, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)))
def _rsa_dec(priv, ct):
    return serialization.load_pem_private_key(priv, None).decrypt(_b64d(ct), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
def _rsa_sign(priv, data):
    return _b64e(serialization.load_pem_private_key(priv, None).sign(data, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256()))
def _rsa_verify(pub, data, sig):
    try: serialization.load_pem_public_key(pub).verify(_b64d(sig), data, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256()); return True
    except: return False
def _ed_sign(priv, data): return _b64e(serialization.load_pem_private_key(priv, None).sign(data))
def _ed_verify(pub, data, sig):
    try: serialization.load_pem_public_key(pub).verify(_b64d(sig), data); return True
    except: return False
def _sha256(d): return hashlib.sha256(d).hexdigest()
def _sha512(d): return hashlib.sha512(d).hexdigest()
def _hmac_sha256(key, data): return _b64e(_hmac.new(key, data, hashlib.sha256).digest())

@engine_registry.register("transit")
class TransitEngine(BaseSecretsEngine):
    engine_name = "transit"; engine_version = "3.0"
    description = "Transit Engine — encryption-as-a-service"
    async def read(self, path, **kw): raise NotImplementedError
    async def write(self, path, data, **kw): raise NotImplementedError
    async def delete(self, path, **kw): raise NotImplementedError
    async def list(self, path, **kw): raise NotImplementedError

    @staticmethod
    async def create_key(db, name, key_type, exportable=False, description=None, rotation_policy_days=None, created_by=None, labels=None):
        if (await db.execute(select(TransitKey).where(TransitKey.name == name))).scalar_one_or_none():
            raise HTTPException(409, f"Transit key '{name}' already exists")
        key = TransitKey(name=name, key_type=key_type, exportable=exportable, description=description,
                         rotation_policy_days=rotation_policy_days, created_by=created_by, labels=labels or {})
        if rotation_policy_days: key.next_rotation_at = _now() + timedelta(days=rotation_policy_days)
        db.add(key); await db.flush()
        await TransitEngine._gen_version(db, key, 1)
        return key

    @staticmethod
    async def _gen_version(db, key, vnum):
        kt = key.key_type; pub = None
        if kt == TransitKeyType.AES_256_GCM:
            enc = encryption_service.encrypt(_b64e(_gen_aes())); algo = "AES-256-GCM"
        elif kt == TransitKeyType.CHACHA20_POLY1305:
            enc = encryption_service.encrypt(_b64e(_gen_chacha())); algo = "ChaCha20-Poly1305"
        elif kt == TransitKeyType.RSA_4096:
            priv, pub_b = _gen_rsa(); enc = encryption_service.encrypt(_b64e(priv)); pub = pub_b.decode(); algo = "RSA-4096"
        elif kt == TransitKeyType.ED25519:
            priv, pub_b = _gen_ed25519(); enc = encryption_service.encrypt(_b64e(priv)); pub = pub_b.decode(); algo = "Ed25519"
        else: raise HTTPException(400, f"Unsupported: {kt}")
        for v in (await db.execute(select(TransitKeyVersion).where(TransitKeyVersion.key_id==key.id, TransitKeyVersion.is_current==True))).scalars().all():
            v.is_current = False
        kv = TransitKeyVersion(key_id=key.id, version_number=vnum, encrypted_key_material=enc, public_key_pem=pub, algorithm=algo, is_current=True)
        db.add(kv); await db.flush(); return kv

    @staticmethod
    def _raw(kv): return base64.b64decode(encryption_service.decrypt(kv.encrypted_key_material))

    @staticmethod
    async def _get_key(db, name):
        key = (await db.execute(select(TransitKey).where(TransitKey.name==name))).scalar_one_or_none()
        if not key: raise HTTPException(404, f"Transit key '{name}' not found")
        if key.status == TransitKeyStatus.DESTROYED: raise HTTPException(410, "Key destroyed")
        if key.status == TransitKeyStatus.DISABLED: raise HTTPException(403, "Key disabled")
        return key

    @staticmethod
    async def _get_ver(db, key, version=None):
        vnum = version or key.current_version
        kv = (await db.execute(select(TransitKeyVersion).where(TransitKeyVersion.key_id==key.id, TransitKeyVersion.version_number==vnum))).scalar_one_or_none()
        if not kv: raise HTTPException(404, f"Version {vnum} not found")
        if kv.destroyed_at: raise HTTPException(410, f"Version {vnum} destroyed")
        return kv

    @staticmethod
    async def rotate_key(db, name):
        key = await TransitEngine._get_key(db, name)
        key.current_version += 1; key.last_rotated_at = _now()
        if key.rotation_policy_days: key.next_rotation_at = _now() + timedelta(days=key.rotation_policy_days)
        await TransitEngine._gen_version(db, key, key.current_version); await db.flush(); return key

    @staticmethod
    async def list_keys(db):
        return (await db.execute(select(TransitKey).order_by(TransitKey.name))).scalars().all()

    @staticmethod
    async def get_key_info(db, name):
        key = (await db.execute(select(TransitKey).where(TransitKey.name==name))).scalar_one_or_none()
        if not key: raise HTTPException(404, f"'{name}' not found")
        versions = (await db.execute(select(TransitKeyVersion).where(TransitKeyVersion.key_id==key.id).order_by(TransitKeyVersion.version_number))).scalars().all()
        return {"name": key.name, "type": key.key_type.value, "status": key.status.value,
                "current_version": key.current_version, "min_decryption_version": key.min_decryption_version,
                "exportable": key.exportable, "deletion_allowed": key.deletion_allowed,
                "description": key.description, "labels": key.labels or {},
                "rotation_policy_days": key.rotation_policy_days,
                "last_rotated_at": key.last_rotated_at.isoformat() if key.last_rotated_at else None,
                "next_rotation_at": key.next_rotation_at.isoformat() if key.next_rotation_at else None,
                "created_at": key.created_at.isoformat(),
                "versions": [{"version": v.version_number, "algorithm": v.algorithm, "is_current": v.is_current,
                               "archived": v.archived, "public_key": v.public_key_pem,
                               "created_at": v.created_at.isoformat(), "destroyed": v.destroyed_at is not None} for v in versions]}

    @staticmethod
    async def archive_key_version(db, name, version):
        key = await TransitEngine._get_key(db, name)
        if version == key.current_version: raise HTTPException(400, "Cannot archive current version")
        kv = await TransitEngine._get_ver(db, key, version); kv.archived = True; await db.flush()

    @staticmethod
    async def destroy_key_version(db, name, version):
        key = await TransitEngine._get_key(db, name)
        if not key.deletion_allowed: raise HTTPException(403, "Set deletion_allowed=true first")
        if version == key.current_version: raise HTTPException(400, "Cannot destroy current version")
        kv = await TransitEngine._get_ver(db, key, version)
        kv.encrypted_key_material = ""; kv.destroyed_at = _now()
        key.min_decryption_version = version + 1; await db.flush()

    @staticmethod
    async def disable_key(db, name):
        key = (await db.execute(select(TransitKey).where(TransitKey.name==name))).scalar_one_or_none()
        if not key: raise HTTPException(404, f"'{name}' not found")
        key.status = TransitKeyStatus.DISABLED; await db.flush(); return key

    @staticmethod
    async def export_key(db, name, version=None):
        key = (await db.execute(select(TransitKey).where(TransitKey.name==name))).scalar_one_or_none()
        if not key: raise HTTPException(404, f"'{name}' not found")
        if not key.exportable: raise HTTPException(403, "Key is not exportable")
        kv = await TransitEngine._get_ver(db, key, version)
        return {"name": name, "version": kv.version_number, "algorithm": kv.algorithm,
                "key_material": _b64e(TransitEngine._raw(kv)), "warning": "Handle with extreme care."}

    @staticmethod
    async def encrypt(db, key_name, plaintext_b64, context=None):
        key = await TransitEngine._get_key(db, key_name)
        kv = await TransitEngine._get_ver(db, key); raw = TransitEngine._raw(kv)
        pt = _b64d(plaintext_b64)
        if key.key_type == TransitKeyType.AES_256_GCM: ct = _aes_enc(raw, pt)
        elif key.key_type == TransitKeyType.CHACHA20_POLY1305: ct = _chacha_enc(raw, pt)
        elif key.key_type == TransitKeyType.RSA_4096: ct = _rsa_enc(kv.public_key_pem.encode(), pt)
        else: raise HTTPException(400, f"{key.key_type.value} does not support encrypt")
        return {"ciphertext": f"vault:v{kv.version_number}:{ct}", "key_version": kv.version_number}

    @staticmethod
    async def decrypt(db, key_name, ciphertext_token, context=None):
        key = await TransitEngine._get_key(db, key_name)
        try:
            parts = ciphertext_token.split(":", 2)
            assert parts[0] == "vault" and parts[1].startswith("v")
            version = int(parts[1][1:]); ct = parts[2]
        except: raise HTTPException(400, "Invalid ciphertext token. Expected: vault:vN:...")
        if version < key.min_decryption_version:
            raise HTTPException(400, f"Version {version} below min_decryption_version")
        kv = await TransitEngine._get_ver(db, key, version); raw = TransitEngine._raw(kv)
        if key.key_type == TransitKeyType.AES_256_GCM: pt = _aes_dec(raw, ct)
        elif key.key_type == TransitKeyType.CHACHA20_POLY1305: pt = _chacha_dec(raw, ct)
        elif key.key_type == TransitKeyType.RSA_4096: pt = _rsa_dec(raw, ct)
        else: raise HTTPException(400, f"{key.key_type.value} does not support decrypt")
        return {"plaintext": _b64e(pt), "key_version": version}

    @staticmethod
    async def sign(db, key_name, input_b64, hash_algorithm="sha2-256"):
        key = await TransitEngine._get_key(db, key_name)
        if key.key_type not in (TransitKeyType.RSA_4096, TransitKeyType.ED25519):
            raise HTTPException(400, "Signing requires RSA-4096 or Ed25519")
        kv = await TransitEngine._get_ver(db, key); raw = TransitEngine._raw(kv)
        data = _b64d(input_b64)
        sig = _rsa_sign(raw, data) if key.key_type == TransitKeyType.RSA_4096 else _ed_sign(raw, data)
        return {"signature": f"vault:v{kv.version_number}:{sig}", "key_version": kv.version_number}

    @staticmethod
    async def verify_signature(db, key_name, input_b64, signature_token):
        key = await TransitEngine._get_key(db, key_name)
        try: parts = signature_token.split(":", 2); version = int(parts[1][1:]); sig = parts[2]
        except: raise HTTPException(400, "Invalid signature token")
        kv = await TransitEngine._get_ver(db, key, version); data = _b64d(input_b64)
        if key.key_type == TransitKeyType.RSA_4096: valid = _rsa_verify(kv.public_key_pem.encode(), data, sig)
        elif key.key_type == TransitKeyType.ED25519: valid = _ed_verify(kv.public_key_pem.encode(), data, sig)
        else: raise HTTPException(400, "Key type does not support verification")
        return {"valid": valid, "key_version": version}

    @staticmethod
    async def hash_data(algorithm, input_b64):
        data = _b64d(input_b64)
        if algorithm == "sha2-256": result = _sha256(data)
        elif algorithm == "sha2-512": result = _sha512(data)
        else: raise HTTPException(400, f"Unsupported: {algorithm}. Use sha2-256 or sha2-512")
        return {"sum": result, "algorithm": algorithm}

    @staticmethod
    async def generate_hmac(db, key_name, input_b64, algorithm="sha2-256"):
        key = await TransitEngine._get_key(db, key_name)
        if key.key_type not in (TransitKeyType.AES_256_GCM, TransitKeyType.CHACHA20_POLY1305):
            raise HTTPException(400, "HMAC requires symmetric key")
        kv = await TransitEngine._get_ver(db, key); raw = TransitEngine._raw(kv)
        return {"hmac": f"vault:v{kv.version_number}:{_hmac_sha256(raw, _b64d(input_b64))}", "key_version": kv.version_number}

    @staticmethod
    async def generate_random(length_bytes=32):
        if not 1 <= length_bytes <= 4096: raise HTTPException(400, "length_bytes must be 1-4096")
        return {"random_bytes": _b64e(secrets.token_bytes(length_bytes)), "length": length_bytes}

transit_engine = TransitEngine()
