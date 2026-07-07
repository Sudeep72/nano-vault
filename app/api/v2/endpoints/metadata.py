"""Secret Metadata API — NanoVault v2.0 Enterprise Hardening"""
from __future__ import annotations
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.core.dependencies import get_current_user
from app.core.responses import ok, paginated
from app.services.v2.metadata_service import metadata_service
from app.services.secret_service import secret_service

router = APIRouter(prefix="/secrets", tags=["Secret Metadata"])


@router.get("/{secret_id}/metadata", summary="Get full metadata for a secret (no value)")
async def get_metadata(
    secret_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    # Fetch the secret (ownership check included), but don't decrypt
    secret, _ = await secret_service.read(db, current_user, secret_id)
    meta = await metadata_service.get_secret_metadata(db, secret, current_user)
    return ok(meta, "Secret metadata retrieved")


@router.get("/metadata/list", summary="List metadata for all owned secrets")
async def list_metadata(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
    namespace_id: Optional[uuid.UUID] = Query(None, description="Filter by namespace"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    items, total = await metadata_service.list_metadata(
        db, current_user, namespace_id=namespace_id, page=page, page_size=page_size
    )
    return paginated(items, total, page, page_size, "Metadata listing retrieved")
