from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok, created
from app.services.v3.policy_compiler_service import policy_compiler_service
from app.models.models import PolicyFileFormat, PolicyFile, PolicyFileVersion

router = APIRouter(prefix="/policy-as-code", tags=["Policy as Code"])

class UploadPolicyRequest(BaseModel):
    name: str; content: str; format: PolicyFileFormat = PolicyFileFormat.YAML
    description: Optional[str] = None; apply: bool = False
class ValidateRequest(BaseModel):
    content: str; format: PolicyFileFormat = PolicyFileFormat.YAML
class SimulateRequest(BaseModel):
    policy_name: str; secret_key: str; action: str
class DiffRequest(BaseModel):
    policy_name: str; version_a: int; version_b: int
class RollbackRequest(BaseModel):
    target_version: int

@router.post("/upload", summary="Upload a policy file (YAML / JSON / HCL)")
async def upload_policy(body: UploadPolicyRequest, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    result = await policy_compiler_service.upload(db, body.name, body.content, body.format, body.description, current_user.id, body.apply)
    status_word = "created" if result["version"] == 1 else "updated"
    return created(result, f"Policy '{body.name}' {status_word} (v{result['version']})")

@router.post("/validate", summary="Validate a policy file without storing")
async def validate_policy(body: ValidateRequest, _=Depends(get_current_user)):
    result = await policy_compiler_service.validate(body.content, body.format)
    return ok(result, "Validation complete" if result["valid"] else "Validation failed")

@router.post("/simulate", summary="Simulate whether a policy would allow an action")
async def simulate_policy(body: SimulateRequest, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    result = await policy_compiler_service.simulate(db, body.policy_name, body.secret_key, body.action)
    return ok(result, "Access ALLOWED" if result["allowed"] else "Access DENIED")

@router.post("/diff", summary="Compare two versions of a policy file")
async def diff_policy(body: DiffRequest, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    result = await policy_compiler_service.diff(db, body.policy_name, body.version_a, body.version_b)
    return ok(result, f"Diff: {result['total_changes']} change(s)")

@router.post("/{policy_name}/rollback", summary="Roll back a named policy to a previous version")
async def rollback_named_policy(policy_name: str, body: RollbackRequest, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    result = await policy_compiler_service.rollback(db, policy_name, body.target_version)
    return ok(result, f"Policy '{policy_name}' rolled back to v{body.target_version}")

@router.post("/{policy_name}/apply", summary="Apply current version to the policy engine [Admin]")
async def apply_policy(policy_name: str, db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    pf = (await db.execute(select(PolicyFile).where(PolicyFile.name==policy_name))).scalar_one_or_none()
    if not pf: raise HTTPException(404, f"'{policy_name}' not found")
    ver = (await db.execute(select(PolicyFileVersion).where(PolicyFileVersion.policy_file_id==pf.id, PolicyFileVersion.is_current==True))).scalar_one_or_none()
    if not ver or not ver.is_valid: raise HTTPException(400, "No valid current version")
    await policy_compiler_service._apply_to_engine(db, policy_name, ver.parsed_permissions or [], admin.id)
    ver.applied_at = datetime.now(timezone.utc); await db.flush()
    return ok({"policy": policy_name, "version": ver.version_number, "applied": True}, "Policy applied")

@router.get("/files", summary="List all policy files")
async def list_files(db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    files = await policy_compiler_service.list_files(db)
    return ok(files, f"{len(files)} policy files")

@router.get("/{policy_name}/versions", summary="Get version history of a policy file")
async def get_versions(policy_name: str, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    versions = await policy_compiler_service.get_versions(db, policy_name)
    return ok(versions, f"{len(versions)} versions for '{policy_name}'")
