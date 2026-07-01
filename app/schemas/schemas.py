"""Pydantic v2 schemas for request/response validation."""
import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator, ConfigDict
from app.models.models import UserRole, AuditAction


# ── Auth ────────────────────────────────────────────────────────────────────

class UserRegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        v = v.strip()
        if not (3 <= len(v) <= 64):
            raise ValueError("Username must be 3–64 characters")
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username may only contain letters, digits, hyphens, underscores")
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 10:
            raise ValueError("Password must be at least 10 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class UserLoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime]


# ── Secrets ─────────────────────────────────────────────────────────────────

class SecretCreateRequest(BaseModel):
    key: str
    value: str
    description: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[list[str]] = None

    @field_validator("key")
    @classmethod
    def key_valid(cls, v: str) -> str:
        v = v.strip()
        if not (1 <= len(v) <= 255):
            raise ValueError("Key must be 1–255 characters")
        return v

    @field_validator("value")
    @classmethod
    def value_not_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("Secret value cannot be empty")
        return v

    @field_validator("tags")
    @classmethod
    def tags_limit(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v and len(v) > 20:
            raise ValueError("Maximum 20 tags per secret")
        return v


class SecretUpdateRequest(BaseModel):
    value: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[list[str]] = None


class SecretResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    key: str
    value: str  # decrypted value — only returned on explicit read
    description: Optional[str]
    category: Optional[str]
    tags: Optional[list[str]]
    version: int
    created_at: datetime
    updated_at: datetime


class SecretMetaResponse(BaseModel):
    """List view — does NOT include the decrypted value."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    key: str
    description: Optional[str]
    category: Optional[str]
    tags: Optional[list[str]]
    version: int
    created_at: datetime
    updated_at: datetime


# ── Audit ────────────────────────────────────────────────────────────────────

class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: Optional[uuid.UUID]
    action: AuditAction
    resource_type: Optional[str]
    resource_id: Optional[str]
    ip_address: Optional[str]
    success: bool
    extra_data: Optional[dict]
    created_at: datetime


# ── Generic ──────────────────────────────────────────────────────────────────

class MessageResponse(BaseModel):
    message: str


class PaginatedResponse(BaseModel):
    items: list
    total: int
    page: int
    page_size: int
    pages: int
