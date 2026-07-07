"""
Namespace Service — NanoVault v2.0 Enterprise Hardening

True logical isolation: every resource belongs to a namespace.
Users cannot access resources outside their active namespace.
Admins can switch namespaces.
"""
from __future__ import annotations
import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, Request
from app.models.models import Namespace, Organization, User, UserRole


_GLOBAL_NS_PATH = "root"
_ACTIVE_NS_HEADER = "X-Vault-Namespace"


class NamespaceService:

    @staticmethod
    async def get_by_path(db: AsyncSession, path: str) -> Optional[Namespace]:
        return (await db.execute(
            select(Namespace).where(Namespace.path == path)
        )).scalar_one_or_none()

    @staticmethod
    async def get_by_id(db: AsyncSession, ns_id: uuid.UUID) -> Namespace:
        ns = (await db.execute(
            select(Namespace).where(Namespace.id == ns_id)
        )).scalar_one_or_none()
        if not ns:
            raise HTTPException(status_code=404, detail="Namespace not found")
        return ns

    @staticmethod
    async def resolve_active(db: AsyncSession, request: Request, user: User) -> Optional[Namespace]:
        """
        Resolve the active namespace for a request.
        Priority: X-Vault-Namespace header > user's org default namespace > root
        Admins can switch to any namespace via header.
        Regular users are restricted to their org's namespaces.
        """
        header_path = request.headers.get(_ACTIVE_NS_HEADER)

        if header_path:
            ns = await NamespaceService.get_by_path(db, header_path)
            if not ns:
                raise HTTPException(status_code=404, detail=f"Namespace '{header_path}' not found")

            # Non-admins can only use namespaces within their org
            if user.role != UserRole.ADMIN and user.org_id:
                if ns.org_id != user.org_id:
                    raise HTTPException(
                        status_code=403,
                        detail="Access denied: namespace belongs to a different organization",
                    )
            return ns

        # Default: user's org first namespace or None (root access)
        return None

    @staticmethod
    async def create(
        db: AsyncSession,
        org_id: uuid.UUID,
        name: str,
        path: str,
        description: Optional[str] = None,
        parent_id: Optional[uuid.UUID] = None,
        admin_id: Optional[uuid.UUID] = None,
    ) -> Namespace:
        existing = (await db.execute(
            select(Namespace).where(Namespace.path == path)
        )).scalar_one_or_none()
        if existing:
            raise HTTPException(status_code=409, detail=f"Namespace path '{path}' already exists")

        ns = Namespace(
            org_id=org_id, name=name, path=path,
            description=description, parent_id=parent_id,
        )
        db.add(ns)
        await db.flush()
        return ns

    @staticmethod
    async def delete(db: AsyncSession, ns_id: uuid.UUID) -> None:
        ns = await NamespaceService.get_by_id(db, ns_id)
        # Check for child namespaces
        children = (await db.execute(
            select(Namespace).where(Namespace.parent_id == ns_id)
        )).scalars().all()
        if children:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete namespace with {len(children)} child namespace(s). Delete children first.",
            )
        await db.delete(ns)
        await db.flush()

    @staticmethod
    async def list_by_org(db: AsyncSession, org_id: uuid.UUID) -> list[Namespace]:
        result = await db.execute(
            select(Namespace).where(Namespace.org_id == org_id).order_by(Namespace.path)
        )
        return result.scalars().all()

    @staticmethod
    async def get_hierarchy(db: AsyncSession, ns_id: uuid.UUID) -> list[Namespace]:
        """Return the full ancestry chain from root to this namespace."""
        chain = []
        current_id = ns_id
        visited = set()
        while current_id and current_id not in visited:
            visited.add(current_id)
            ns = (await db.execute(
                select(Namespace).where(Namespace.id == current_id)
            )).scalar_one_or_none()
            if not ns:
                break
            chain.insert(0, ns)
            current_id = ns.parent_id
        return chain

    @staticmethod
    async def switch_namespace(
        db: AsyncSession,
        user: User,
        target_path: str,
    ) -> Namespace:
        """Admin-only: explicitly switch to a namespace."""
        if user.role != UserRole.ADMIN:
            raise HTTPException(status_code=403, detail="Only admins can switch namespaces")
        ns = await NamespaceService.get_by_path(db, target_path)
        if not ns:
            raise HTTPException(status_code=404, detail=f"Namespace '{target_path}' not found")
        return ns


namespace_service = NamespaceService()
