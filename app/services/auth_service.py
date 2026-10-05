"""Authentication service — registration, login, token lifecycle."""
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status
from app.models.models import User, RefreshToken, UserRole
from app.core.security import hash_password, verify_password, create_access_token, create_refresh_token, decode_token
from app.core.config import settings


def _hash_token(token: str) -> str:
    """Store only a SHA-256 hash of the refresh token — never the raw value."""
    return hashlib.sha256(token.encode()).hexdigest()


class AuthService:
    @staticmethod
    async def register(
        db: AsyncSession,
        username: str,
        email: str,
        password: str,
        role: UserRole = UserRole.USER,
    ) -> User:
        # Check uniqueness
        existing = await db.execute(
            select(User).where((User.username == username) | (User.email == email))
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail="Username or email already registered")

        user = User(
            username=username,
            email=email,
            hashed_password=hash_password(password),
            role=role,
        )
        db.add(user)
        await db.flush()
        return user

    @staticmethod
    async def authenticate(db: AsyncSession, username: str, password: str) -> User:
        result = await db.execute(select(User).where(User.username == username))
        user: Optional[User] = result.scalar_one_or_none()

        if not user or not verify_password(password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )
        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

        user.last_login_at = datetime.now(timezone.utc)
        return user

    @staticmethod
    async def issue_tokens(db: AsyncSession, user: User) -> tuple[str, str]:
        access_token = create_access_token(str(user.id), user.role.value)
        refresh_token = create_refresh_token(str(user.id))

        rt = RefreshToken(
            user_id=user.id,
            token_hash=_hash_token(refresh_token),
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )
        db.add(rt)
        await db.flush()
        return access_token, refresh_token

    @staticmethod
    async def refresh(db: AsyncSession, raw_token: str) -> str:
        payload = decode_token(raw_token, expected_type="refresh")
        token_hash = _hash_token(raw_token)

        result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.revoked == False,  # noqa: E712
                RefreshToken.expires_at > datetime.now(timezone.utc),
            )
        )
        rt: Optional[RefreshToken] = result.scalar_one_or_none()
        if not rt:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token invalid or expired")

        user_result = await db.execute(select(User).where(User.id == uuid.UUID(payload["sub"])))
        user: Optional[User] = user_result.scalar_one_or_none()
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

        return create_access_token(str(user.id), user.role.value)

    @staticmethod
    async def revoke_refresh_token(db: AsyncSession, raw_token: str) -> None:
        token_hash = _hash_token(raw_token)
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        rt: Optional[RefreshToken] = result.scalar_one_or_none()
        if rt:
            rt.revoked = True
            rt.revoked_at = datetime.now(timezone.utc)

    @staticmethod
    async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> Optional[User]:
        result = await db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()


auth_service = AuthService()
