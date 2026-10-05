"""Policy Engine endpoints — NanoVault v1.0.1"""
import uuid
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.schemas.schemas import (
    PolicyCreateRequest, PolicyUpdateRequest, PolicyResponse, PolicyAssignRequest,
)
from app.services.policy_service import policy_service
from app.services.audit_service import audit_service
from app.models.models import AuditAction
from app.core.dependencies import require_admin, get_current_user
from app.core.responses import ok, created

router = APIRouter(prefix="/policies", tags=["Policy Engine"])


@router.get("", summary="List all policies")
async def list_policies(
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    policies = await policy_service.list_all(db)
    data = [PolicyResponse.model_validate(p).model_dump(mode="json") for p in policies]
    return ok(data, "Policies retrieved")


@router.post("", summary="Create a named policy [Admin]")
async def create_policy(
    body: PolicyCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin),
):
    policy = await policy_service.create(db, body)
    await audit_service.log(db, AuditAction.POLICY_CREATE, user_id=admin.id,
                            resource_type="policy", resource_id=str(policy.id), request=request)
    return created(PolicyResponse.model_validate(policy).model_dump(mode="json"), "Policy created")


@router.patch("/{policy_id}", summary="Update a policy [Admin]")
async def update_policy(
    policy_id: uuid.UUID,
    body: PolicyUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin),
):
    policy = await policy_service.update(db, policy_id, body)
    await audit_service.log(db, AuditAction.POLICY_UPDATE, user_id=admin.id,
                            resource_type="policy", resource_id=str(policy_id), request=request)
    return ok(PolicyResponse.model_validate(policy).model_dump(mode="json"), "Policy updated")


@router.delete("/{policy_id}", summary="Delete a policy [Admin]")
async def delete_policy(
    policy_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin),
):
    await policy_service.delete(db, policy_id)
    await audit_service.log(db, AuditAction.POLICY_DELETE, user_id=admin.id,
                            resource_type="policy", resource_id=str(policy_id), request=request)
    return ok(message="Policy deleted")


@router.post("/assign", summary="Assign policy to user [Admin]")
async def assign_policy(
    body: PolicyAssignRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin),
):
    await policy_service.assign(db, body.user_id, body.policy_id)
    await audit_service.log(db, AuditAction.POLICY_ASSIGN, user_id=admin.id,
                            resource_type="user", resource_id=str(body.user_id),
                            request=request, metadata={"policy_id": str(body.policy_id)})
    return ok(message="Policy assigned to user")


@router.post("/revoke", summary="Revoke policy from user [Admin]")
async def revoke_policy(
    body: PolicyAssignRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin),
):
    await policy_service.revoke(db, body.user_id, body.policy_id)
    await audit_service.log(db, AuditAction.POLICY_REVOKE, user_id=admin.id,
                            resource_type="user", resource_id=str(body.user_id),
                            request=request, metadata={"policy_id": str(body.policy_id)})
    return ok(message="Policy revoked from user")


@router.get("/user/{user_id}", summary="Get policies assigned to a user [Admin]")
async def user_policies(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_admin),
):
    policies = await policy_service.get_user_policies(db, user_id)
    data = [PolicyResponse.model_validate(p).model_dump(mode="json") for p in policies]
    return ok(data, f"Policies for user {user_id}")
