"""Pydantic v2 schemas — NanoVault v1.0.1"""
import uuid
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, EmailStr, field_validator, ConfigDict, Field
from app.models.models import UserRole, AuditAction, SecretStatus


# ── Auth ────────────────────────────────────────────────────────────────────

class UserRegisterRequest(BaseModel):
    username: str = Field(..., examples=["alice"])
    email: EmailStr = Field(..., examples=["alice@example.com"])
    password: str = Field(..., examples=["AlicePass1!"])

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
    username: str = Field(..., examples=["alice"])
    password: str = Field(..., examples=["AlicePass1!"])


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


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


# ── Policy Engine ────────────────────────────────────────────────────────────

class PolicyPermission(BaseModel):
    """A single path-based permission rule."""
    path: str = Field(..., examples=["aws/*"], description="Secret key path pattern. Supports * wildcard.")
    actions: list[str] = Field(..., examples=[["read", "list"]])

    @field_validator("actions")
    @classmethod
    def validate_actions(cls, v: list[str]) -> list[str]:
        valid = {"create", "read", "update", "delete", "list"}
        for a in v:
            if a not in valid:
                raise ValueError(f"Invalid action '{a}'. Must be one of: {valid}")
        return v


class PolicyCreateRequest(BaseModel):
    name: str = Field(..., examples=["developer"], description="Unique policy name")
    description: Optional[str] = Field(None, examples=["Developer read/write access to dev paths"])
    permissions: list[PolicyPermission] = Field(..., examples=[[
        {"path": "dev/*", "actions": ["create", "read", "update", "delete", "list"]},
        {"path": "aws/*", "actions": ["read", "list"]},
    ]])

    @field_validator("name")
    @classmethod
    def name_valid(cls, v: str) -> str:
        v = v.strip().lower()
        if not (2 <= len(v) <= 128):
            raise ValueError("Policy name must be 2–128 characters")
        return v


class PolicyUpdateRequest(BaseModel):
    description: Optional[str] = None
    permissions: Optional[list[PolicyPermission]] = None


class PolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    description: Optional[str]
    permissions: list
    is_builtin: bool
    created_at: datetime
    updated_at: datetime


class PolicyAssignRequest(BaseModel):
    user_id: uuid.UUID
    policy_id: uuid.UUID


# ── Secrets ─────────────────────────────────────────────────────────────────

class SecretCreateRequest(BaseModel):
    key: str = Field(..., examples=["aws/prod/access_key"], description="Secret key path (e.g. aws/prod/key)")
    value: str = Field(..., examples=["AKIAIOSFODNN7EXAMPLE"])
    description: Optional[str] = Field(None, max_length=2048, examples=["AWS production access key"])
    category: Optional[str] = Field(None, max_length=128, examples=["cloud"])
    tags: Optional[list[str]] = Field(None, examples=[["aws", "prod"]])

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
        if len(v.encode()) > 65536:
            raise ValueError("Secret value exceeds maximum size of 64KB")
        return v

    @field_validator("tags")
    @classmethod
    def tags_limit(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v and len(v) > 20:
            raise ValueError("Maximum 20 tags per secret")
        return v


class SecretUpdateRequest(BaseModel):
    value: Optional[str] = Field(None, examples=["NEWKEY_ROTATED"])
    description: Optional[str] = Field(None, max_length=2048)
    category: Optional[str] = Field(None, max_length=128)
    tags: Optional[list[str]] = None


class SecretMetaResponse(BaseModel):
    """List view — value never included."""
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    key: str
    description: Optional[str]
    category: Optional[str]
    tags: Optional[list[str]]
    version: int
    status: SecretStatus
    encryption_algorithm: str
    key_version: int
    owner_id: uuid.UUID
    last_accessed_at: Optional[datetime]
    access_count: int
    created_at: datetime
    updated_at: datetime
    deleted_at: Optional[datetime]


class SecretResponse(SecretMetaResponse):
    """Detail view — includes decrypted value."""
    value: str


class SecretSearchRequest(BaseModel):
    query: Optional[str] = Field(None, description="Search in key name")
    category: Optional[str] = None
    tag: Optional[str] = None
    owner_id: Optional[uuid.UUID] = None
    status: Optional[SecretStatus] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    updated_after: Optional[datetime] = None
    updated_before: Optional[datetime] = None
    sort_by: str = Field("created_at", pattern="^(key|category|created_at|updated_at|version)$")
    sort_order: str = Field("desc", pattern="^(asc|desc)$")
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=200)


# ── Audit ────────────────────────────────────────────────────────────────────

class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    user_id: Optional[uuid.UUID]
    action: AuditAction
    resource_type: Optional[str]
    resource_id: Optional[str]
    ip_address: Optional[str]
    endpoint: Optional[str]
    execution_time_ms: Optional[int]
    status_code: Optional[int]
    success: bool
    extra_data: Optional[dict]
    created_at: datetime


# ── Health ───────────────────────────────────────────────────────────────────

class ComponentHealth(BaseModel):
    status: str  # "healthy" | "degraded" | "unhealthy"
    message: Optional[str] = None
    latency_ms: Optional[float] = None


class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    components: dict[str, ComponentHealth]


# ── Metrics ──────────────────────────────────────────────────────────────────

class MetricsResponse(BaseModel):
    total_users: int
    active_users: int
    total_secrets: int
    active_secrets: int
    deleted_secrets: int
    total_audit_events: int
    secret_reads: int
    secret_writes: int
    secret_updates: int
    secret_deletes: int
    successful_logins: int
    failed_logins: int
    total_policies: int


# ── Generic ──────────────────────────────────────────────────────────────────

class MessageResponse(BaseModel):
    message: str
