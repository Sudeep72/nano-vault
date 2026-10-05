from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin, require_unsealed
from app.core.responses import ok, created
from app.engines.transit.engine import TransitEngine
from app.models.models import TransitKeyType, AuditAction
from app.services.audit_service import audit_service
from app.services.v2.engine_service import engine_service

router = APIRouter(prefix="/transit", tags=["Transit Secrets Engine"], dependencies=[Depends(require_unsealed)])

class CreateKeyRequest(BaseModel):
    name: str; key_type: TransitKeyType; exportable: bool = False
    description: Optional[str] = None; rotation_policy_days: Optional[int] = None; labels: Optional[dict] = None
class EncryptRequest(BaseModel):
    plaintext: str; context: Optional[str] = None
class DecryptRequest(BaseModel):
    ciphertext: str; context: Optional[str] = None
class SignRequest(BaseModel):
    input: str; hash_algorithm: str = "sha2-256"
class VerifyRequest(BaseModel):
    input: str; signature: str
class HashRequest(BaseModel):
    input: str; algorithm: str = "sha2-256"
class HMACRequest(BaseModel):
    input: str; algorithm: str = "sha2-256"
class RandomRequest(BaseModel):
    bytes: int = Field(32, ge=1, le=4096)

@router.post("/keys", summary="Create a named transit key")
async def create_key(body: CreateKeyRequest, request: Request, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    await engine_service.ensure_enabled(db, "transit")
    key = await TransitEngine.create_key(db, body.name, body.key_type, body.exportable, body.description, body.rotation_policy_days, current_user.id, body.labels)
    await audit_service.log(db, AuditAction.SECRET_CREATE, user_id=current_user.id, resource_type="transit_key", resource_id=key.name, request=request)
    return created({"name": key.name, "type": key.key_type.value, "version": key.current_version, "exportable": key.exportable, "created_at": key.created_at.isoformat()}, f"Transit key '{key.name}' created")

@router.get("/keys", summary="List all transit keys")
async def list_keys(db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    await engine_service.ensure_enabled(db, "transit")
    keys = await TransitEngine.list_keys(db)
    return ok([{"name": k.name, "type": k.key_type.value, "status": k.status.value, "current_version": k.current_version, "exportable": k.exportable, "created_at": k.created_at.isoformat()} for k in keys], f"{len(keys)} transit keys")

@router.get("/keys/{name}", summary="Get key info and version history")
async def get_key(name: str, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    await engine_service.ensure_enabled(db, "transit")
    return ok(await TransitEngine.get_key_info(db, name), f"Key '{name}' info")

@router.post("/keys/{name}/rotate", summary="Rotate a transit key")
async def rotate_key(name: str, request: Request, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    await engine_service.ensure_enabled(db, "transit")
    key = await TransitEngine.rotate_key(db, name)
    await audit_service.log(db, AuditAction.SECRET_ROTATE, user_id=current_user.id, resource_type="transit_key", resource_id=name, request=request, metadata={"new_version": key.current_version})
    return ok({"name": name, "new_version": key.current_version, "rotated_at": key.last_rotated_at.isoformat()}, f"Key '{name}' rotated")

@router.post("/keys/{name}/disable", summary="Disable a transit key [Admin]")
async def disable_key(name: str, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    await engine_service.ensure_enabled(db, "transit")
    key = await TransitEngine.disable_key(db, name)
    return ok({"name": name, "status": key.status.value}, f"Key '{name}' disabled")

@router.post("/keys/{name}/archive/{version}", summary="Archive a key version")
async def archive_version(name: str, version: int, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    await engine_service.ensure_enabled(db, "transit")
    await TransitEngine.archive_key_version(db, name, version)
    return ok(message=f"Key '{name}' v{version} archived")

@router.delete("/keys/{name}/versions/{version}", summary="Destroy a key version [Admin]")
async def destroy_version(name: str, version: int, request: Request, db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    await engine_service.ensure_enabled(db, "transit")
    await TransitEngine.destroy_key_version(db, name, version)
    await audit_service.log(db, AuditAction.SECRET_PURGE, user_id=admin.id, resource_type="transit_key_version", resource_id=f"{name}:v{version}", request=request)
    return ok(message=f"Key '{name}' v{version} destroyed")

@router.get("/keys/{name}/export", summary="Export key material (exportable keys only)")
async def export_key(name: str, version: Optional[int] = None, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    await engine_service.ensure_enabled(db, "transit")
    return ok(await TransitEngine.export_key(db, name, version), "Key exported")

@router.post("/encrypt/{key_name}", summary="Encrypt data using a transit key")
async def encrypt(key_name: str, body: EncryptRequest, request: Request, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    await engine_service.ensure_enabled(db, "transit")
    result = await TransitEngine.encrypt(db, key_name, body.plaintext, body.context)
    await audit_service.log(db, AuditAction.SECRET_READ, user_id=current_user.id, resource_type="transit_encrypt", resource_id=key_name, request=request)
    return ok(result, "Data encrypted")

@router.post("/decrypt/{key_name}", summary="Decrypt data using a transit key")
async def decrypt(key_name: str, body: DecryptRequest, request: Request, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    await engine_service.ensure_enabled(db, "transit")
    result = await TransitEngine.decrypt(db, key_name, body.ciphertext, body.context)
    await audit_service.log(db, AuditAction.SECRET_READ, user_id=current_user.id, resource_type="transit_decrypt", resource_id=key_name, request=request)
    return ok(result, "Data decrypted")

@router.post("/sign/{key_name}", summary="Sign data using an asymmetric transit key")
async def sign(key_name: str, body: SignRequest, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    await engine_service.ensure_enabled(db, "transit")
    return ok(await TransitEngine.sign(db, key_name, body.input, body.hash_algorithm), "Data signed")

@router.post("/verify/{key_name}", summary="Verify a signature")
async def verify(key_name: str, body: VerifyRequest, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    await engine_service.ensure_enabled(db, "transit")
    result = await TransitEngine.verify_signature(db, key_name, body.input, body.signature)
    return ok(result, "Signature verified" if result["valid"] else "Signature invalid")

@router.post("/hash", summary="Hash data with SHA-256 or SHA-512")
async def hash_data(body: HashRequest, _=Depends(get_current_user)):
    return ok(await TransitEngine.hash_data(body.algorithm, body.input), "Data hashed")

@router.post("/hmac/{key_name}", summary="Generate HMAC for data")
async def generate_hmac(key_name: str, body: HMACRequest, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    await engine_service.ensure_enabled(db, "transit")
    return ok(await TransitEngine.generate_hmac(db, key_name, body.input, body.algorithm), "HMAC generated")

@router.post("/random", summary="Generate cryptographically secure random bytes")
async def generate_random(body: RandomRequest, _=Depends(get_current_user)):
    return ok(await TransitEngine.generate_random(body.bytes), f"{body.bytes} random bytes generated")
