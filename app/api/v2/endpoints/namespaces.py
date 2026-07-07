"""Namespace Management API — NanoVault v2.0 Enterprise Hardening"""
from __future__ import annotations
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok, created
from app.services.v2.namespace_service import namespace_service
from app.services.audit_service import audit_service
from app.models.models import AuditAction

router = APIRouter(prefix="/namespaces", tags=["Namespace Management"])


class NamespaceCreateRequest(BaseModel):
    org_id: uuid.UUID
    name: str
    path: str
    description: Optional[str] = None
    parent_id: Optional[uuid.UUID] = None


class NamespaceSwitchRequest(BaseModel):
    path: str


def _ns_dict(ns) -> dict:
    return {
        "id": str(ns.id),
        "org_id": str(ns.org_id),
        "name": ns.name,
        "path": ns.path,
        "description": ns.description,
        "parent_id": str(ns.parent_id) if ns.parent_id else None,
        "created_at": ns.created_at.isoformat(),
    }


@router.post("", summary="Create namespace [Admin]")
async def create_namespace(
    body: NamespaceCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin),
):
    ns = await namespace_service.create(
        db, body.org_id, body.name, body.path,
        body.description, body.parent_id, admin_id=admin.id,
    )
    await audit_service.log(db, AuditAction.NAMESPACE_CREATE, user_id=admin.id,
                            resource_type="namespace", resource_id=str(ns.id), request=request)
    return created(_ns_dict(ns), "Namespace created")


@router.delete("/{ns_id}", summary="Delete namespace [Admin]")
async def delete_namespace(
    ns_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_admin),
):
    await namespace_service.delete(db, ns_id)
    return ok(message=f"Namespace {ns_id} deleted")


@router.get("/{ns_id}/hierarchy", summary="Get namespace ancestry chain")
async def get_hierarchy(
    ns_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    chain = await namespace_service.get_hierarchy(db, ns_id)
    return ok(
        [_ns_dict(ns) for ns in chain],
        f"Namespace hierarchy ({len(chain)} levels)",
    )


@router.post("/switch", summary="Switch active namespace [Admin]")
async def switch_namespace(
    body: NamespaceSwitchRequest,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin),
):
    ns = await namespace_service.switch_namespace(db, admin, body.path)
    return ok({
        **_ns_dict(ns),
        "instruction": f"Set header: X-Vault-Namespace: {ns.path}",
    }, f"Switched to namespace '{ns.path}'")


@router.get("/resolve/active", summary="Resolve active namespace for current request")
async def resolve_active(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    ns = await namespace_service.resolve_active(db, request, current_user)
    if ns:
        return ok(_ns_dict(ns), f"Active namespace: {ns.path}")
    return ok({"path": "root", "description": "No namespace header — operating in root context"},
              "Active namespace: root")
