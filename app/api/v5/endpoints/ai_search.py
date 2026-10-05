"""Natural-Language Security Search — NanoVault v5.0 (Step 6)"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.db.session import get_db
from app.core.dependencies import get_current_user
from app.core.responses import ok

router = APIRouter(prefix="/ai", tags=["AI Security Platform"])


class SearchRequest(BaseModel):
    query: str


@router.post("/search", summary="Natural-language security search — RBAC-scoped, sourced, sanitized")
async def ai_search(body: SearchRequest, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    from app.services.v5.ai_search_service import ai_search_service
    result = await ai_search_service.search(db, current_user, body.query)
    return ok(result, "Search complete")
