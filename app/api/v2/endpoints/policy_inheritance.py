"""Policy Inheritance API — NanoVault v2.0 Enterprise Hardening"""
from __future__ import annotations
import uuid
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok
from app.services.v2.policy_inheritance_service import policy_inheritance_service

router = APIRouter(prefix="/policies", tags=["Policy Inheritance"])


@router.get("/effective", summary="Get effective permissions for current user")
async def effective_permissions(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    perms = await policy_inheritance_service.compute_effective(db, current_user)
    return ok({
        "user_id": str(current_user.id),
        "username": current_user.username,
        "role": current_user.role.value,
        **perms.to_dict(),
    }, "Effective permissions calculated")


@router.get("/{policy_id}/inheritance", summary="View policy inheritance tree")
async def inheritance_tree(
    policy_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    tree = await policy_inheritance_service.get_inheritance_tree(db, policy_id)
    return ok(tree, "Policy inheritance tree")


@router.post("/check", summary="Check if current user can perform action on path")
async def check_permission(
    secret_key: str,
    action: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    allowed = await policy_inheritance_service.check(db, current_user, secret_key, action)
    return ok({
        "allowed": allowed,
        "secret_key": secret_key,
        "action": action,
        "user": current_user.username,
    }, "Permission check complete")
