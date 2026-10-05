"""Vault Token Engine endpoints — NanoVault v2.0"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional
from app.db.session import get_db
from app.core.dependencies import get_current_user
from app.core.responses import ok, created
from app.services.v2.token_service import token_service
from app.services.audit_service import audit_service
from app.models.models import AuditAction, TokenType

router = APIRouter(prefix="/tokens", tags=["Vault Token Engine"])


class CreateTokenRequest(BaseModel):
    token_type: TokenType = TokenType.SERVICE
    ttl_seconds: int = Field(3600, ge=60, le=2592000)
    policies: list[str] = []
    max_renewals: int = Field(10, ge=0)
    metadata: dict = {}


class RenewTokenRequest(BaseModel):
    token: str
    increment_seconds: Optional[int] = None


class TokenActionRequest(BaseModel):
    token: str


@router.post("/create", summary="Create a vault token")
async def create_token(
    body: CreateTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    vault_token, raw = await token_service.create(
        db, current_user, body.token_type, body.ttl_seconds,
        body.policies, max_renewals=body.max_renewals, metadata=body.metadata,
    )
    await audit_service.log(db, AuditAction.VAULT_TOKEN_CREATE, user_id=current_user.id,
                            resource_type="vault_token", resource_id=vault_token.token_id, request=request)
    return created({
        "token": raw,
        "token_id": vault_token.token_id,
        "type": vault_token.token_type.value,
        "ttl_seconds": vault_token.ttl_seconds,
        "expires_at": vault_token.expires_at.isoformat(),
        "policies": vault_token.policies,
        "renewable": True,
        "max_renewals": vault_token.max_renewals,
    }, "Vault token created")


@router.post("/lookup", summary="Inspect a vault token")
async def lookup_token(
    body: TokenActionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    info = await token_service.lookup(db, body.token, current_user)
    await audit_service.log(db, AuditAction.VAULT_TOKEN_LOOKUP, user_id=current_user.id,
                            request=request)
    return ok(info, "Token details")


@router.post("/renew", summary="Renew a vault token")
async def renew_token(
    body: RenewTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    token = await token_service.renew(db, body.token, current_user, body.increment_seconds)
    await audit_service.log(db, AuditAction.VAULT_TOKEN_RENEW, user_id=current_user.id,
                            resource_type="vault_token", resource_id=token.token_id, request=request)
    return ok({
        "token_id": token.token_id,
        "expires_at": token.expires_at.isoformat(),
        "renewal_count": token.renewal_count,
    }, "Token renewed")


@router.post("/revoke", summary="Revoke a vault token")
async def revoke_token(
    body: TokenActionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    await token_service.revoke(db, body.token, current_user)
    await audit_service.log(db, AuditAction.VAULT_TOKEN_REVOKE, user_id=current_user.id,
                            request=request)
    return ok(message="Token revoked")


@router.get("/active", summary="List active vault tokens")
async def list_active_tokens(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    tokens = await token_service.list_active(db, current_user)
    data = [
        {
            "token_id": t.token_id,
            "type": t.token_type.value,
            "expires_at": t.expires_at.isoformat(),
            "policies": t.policies,
            "renewal_count": t.renewal_count,
        }
        for t in tokens
    ]
    return ok(data, f"{len(data)} active tokens")
