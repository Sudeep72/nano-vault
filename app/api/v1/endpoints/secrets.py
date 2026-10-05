"""KV Secrets endpoints — NanoVault v1.0.1"""
import uuid
from fastapi import APIRouter, Depends, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.schemas.schemas import (
    SecretCreateRequest, SecretUpdateRequest, SecretSearchRequest,
    SecretResponse, SecretMetaResponse,
)
from app.services.secret_service import secret_service
from app.services.policy_service import policy_service
from app.services.audit_service import audit_service
from app.models.models import AuditAction
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok, created, paginated

router = APIRouter(prefix="/secrets", tags=["KV Secrets Engine"])


@router.post(
    "",
    summary="Create a secret",
    description="Value is encrypted with AES-256-GCM before storage. Policy check: `create` on path.",
)
async def create_secret(
    body: SecretCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    await policy_service.require_permission(db, current_user, body.key, "create")
    secret = await secret_service.create(
        db, current_user, key=body.key, value=body.value,
        description=body.description, category=body.category, tags=body.tags,
    )
    await audit_service.log(db, AuditAction.SECRET_CREATE, user_id=current_user.id,
                            resource_type="secret", resource_id=str(secret.id), request=request)
    return created(SecretMetaResponse.model_validate(secret).model_dump(mode="json"), "Secret created")


@router.post(
    "/search",
    summary="Search and filter secrets",
    description="Advanced search with filtering, sorting, and pagination. Policy check: `list`.",
)
async def search_secrets(
    body: SecretSearchRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    secrets, total = await secret_service.search(db, current_user, body)
    items = [SecretMetaResponse.model_validate(s).model_dump(mode="json") for s in secrets]
    return paginated(items, total, body.page, body.page_size, "Secrets retrieved")


@router.get(
    "",
    summary="List active secrets (metadata only)",
    description="Returns metadata only — no values. Policy check: `list` on `*`.",
)
async def list_secrets(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
    category: str | None = Query(None),
    tag: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    req = SecretSearchRequest(category=category, tag=tag, page=page, page_size=page_size)
    secrets, total = await secret_service.search(db, current_user, req)
    items = [SecretMetaResponse.model_validate(s).model_dump(mode="json") for s in secrets]
    return paginated(items, total, page, page_size, "Secrets retrieved")


@router.get(
    "/{secret_id}",
    summary="Read a secret (decrypted)",
    description="Returns the decrypted value. Policy check: `read` on path. Access time updated.",
)
async def read_secret(
    secret_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    secret, decrypted = await secret_service.read(db, current_user, secret_id)
    await policy_service.require_permission(db, current_user, secret.key, "read")
    await audit_service.log(db, AuditAction.SECRET_READ, user_id=current_user.id,
                            resource_type="secret", resource_id=str(secret_id), request=request)
    data = SecretMetaResponse.model_validate(secret).model_dump(mode="json")
    data["value"] = decrypted
    return ok(data, "Secret retrieved")


@router.patch("/{secret_id}", summary="Update a secret")
async def update_secret(
    secret_id: uuid.UUID,
    body: SecretUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    # Need the key for policy check — fetch first
    secret_pre, _ = await secret_service.read(db, current_user, secret_id)
    await policy_service.require_permission(db, current_user, secret_pre.key, "update")
    secret = await secret_service.update(
        db, current_user, secret_id,
        value=body.value, description=body.description,
        category=body.category, tags=body.tags,
    )
    await audit_service.log(db, AuditAction.SECRET_UPDATE, user_id=current_user.id,
                            resource_type="secret", resource_id=str(secret_id), request=request,
                            metadata={"new_version": secret.version})
    return ok(SecretMetaResponse.model_validate(secret).model_dump(mode="json"), "Secret updated")


@router.delete("/{secret_id}", summary="Soft delete a secret")
async def delete_secret(
    secret_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    secret_pre, _ = await secret_service.read(db, current_user, secret_id)
    await policy_service.require_permission(db, current_user, secret_pre.key, "delete")
    await secret_service.delete(db, current_user, secret_id)
    await audit_service.log(db, AuditAction.SECRET_DELETE, user_id=current_user.id,
                            resource_type="secret", resource_id=str(secret_id), request=request)
    return ok(message="Secret deleted (soft). Use /restore to recover.")


@router.post("/{secret_id}/restore", summary="Restore a soft-deleted secret")
async def restore_secret(
    secret_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    secret = await secret_service.restore(db, current_user, secret_id)
    await audit_service.log(db, AuditAction.SECRET_RESTORE, user_id=current_user.id,
                            resource_type="secret", resource_id=str(secret_id), request=request)
    return ok(SecretMetaResponse.model_validate(secret).model_dump(mode="json"), "Secret restored")


# ── Admin routes ─────────────────────────────────────────────────────────────

@router.post("/admin/search", tags=["Admin"], summary="[Admin] Search all users' secrets")
async def admin_search(
    body: SecretSearchRequest,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin),
):
    secrets, total = await secret_service.admin_search(db, body)
    items = [SecretMetaResponse.model_validate(s).model_dump(mode="json") for s in secrets]
    return paginated(items, total, body.page, body.page_size, "Secrets retrieved")


@router.delete("/admin/{secret_id}/purge", tags=["Admin"], summary="[Admin] Permanently delete a secret")
async def purge_secret(
    secret_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin),
):
    await secret_service.purge(db, secret_id)
    await audit_service.log(db, AuditAction.SECRET_PURGE, user_id=admin.id,
                            resource_type="secret", resource_id=str(secret_id), request=request)
    return ok(message="Secret permanently deleted")
