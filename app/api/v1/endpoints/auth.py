"""Auth endpoints: register, login, refresh, logout, me."""
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.schemas.schemas import (
    UserRegisterRequest, UserLoginRequest, TokenResponse,
    RefreshTokenRequest, AccessTokenResponse, UserResponse, MessageResponse,
)
from app.services.auth_service import auth_service
from app.services.audit_service import audit_service
from app.models.models import AuditAction
from app.core.dependencies import get_current_user
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(body: UserRegisterRequest, request: Request, db: AsyncSession = Depends(get_db)):
    user = await auth_service.register(db, body.username, body.email, body.password)
    await audit_service.log(db, AuditAction.USER_REGISTER, user_id=user.id, request=request,
                            resource_type="user", resource_id=str(user.id))
    return user


@router.post("/login", response_model=TokenResponse)
async def login(body: UserLoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    try:
        user = await auth_service.authenticate(db, body.username, body.password)
    except Exception as exc:
        await audit_service.log(db, AuditAction.USER_LOGIN_FAILED, request=request,
                                success=False, metadata={"username": body.username})
        raise exc

    access_token, refresh_token = await auth_service.issue_tokens(db, user)
    await audit_service.log(db, AuditAction.USER_LOGIN, user_id=user.id, request=request)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=AccessTokenResponse)
async def refresh(body: RefreshTokenRequest, request: Request, db: AsyncSession = Depends(get_db)):
    access_token = await auth_service.refresh(db, body.refresh_token)
    await audit_service.log(db, AuditAction.TOKEN_REFRESH, request=request)
    return AccessTokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout", response_model=MessageResponse)
async def logout(
    body: RefreshTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    await auth_service.revoke_refresh_token(db, body.refresh_token)
    await audit_service.log(db, AuditAction.USER_LOGOUT, user_id=current_user.id, request=request)
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
async def me(current_user=Depends(get_current_user)):
    return current_user
