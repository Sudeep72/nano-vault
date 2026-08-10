"""
NanoVault Database Models — v2.0 Enterprise Edition

Existing tables (v1.x):
  users, refresh_tokens, policies, user_policies, secrets, audit_logs

New tables (v2.0):
  organizations, projects, teams, groups, namespaces,
  team_members, secret_versions, leases, dynamic_credentials,
  wrapped_tokens, cubbyhole_entries, rotation_history,
  service_accounts, mfa_configs, vault_tokens
"""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import (
    String, Text, Boolean, DateTime, ForeignKey,
    Enum, JSON, Integer, Index, BigInteger, Table, Column, CheckConstraint, Float,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.session import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── Enums ────────────────────────────────────────────────────────────────────

class UserRole(str, PyEnum):
    ADMIN = "ADMIN"
    USER = "USER"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"


class SecretStatus(str, PyEnum):
    ACTIVE = "active"
    DELETED = "deleted"
    ARCHIVED = "archived"
    EXPIRED = "expired"


class LeaseStatus(str, PyEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    RENEWED = "renewed"


class TokenType(str, PyEnum):
    SERVICE = "service"
    BATCH = "batch"
    PERIODIC = "periodic"
    ORPHAN = "orphan"


class TokenStatus(str, PyEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class CredentialType(str, PyEnum):
    DATABASE_POSTGRES = "database_postgres"
    DATABASE_MYSQL = "database_mysql"
    DATABASE_SQLITE = "database_sqlite"
    CLOUD_AWS = "cloud_aws"
    CLOUD_AZURE = "cloud_azure"
    CLOUD_GCP = "cloud_gcp"
    APP_API_KEY = "app_api_key"
    APP_ACCESS_TOKEN = "app_access_token"


class RotationStatus(str, PyEnum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"


class AuditAction(str, PyEnum):
    # Auth
    USER_REGISTER = "USER_REGISTER"
    USER_LOGIN = "USER_LOGIN"
    USER_LOGOUT = "USER_LOGOUT"
    USER_LOGIN_FAILED = "USER_LOGIN_FAILED"
    TOKEN_REFRESH = "TOKEN_REFRESH"
    MFA_ENABLED = "MFA_ENABLED"
    MFA_DISABLED = "MFA_DISABLED"
    MFA_VERIFIED = "MFA_VERIFIED"
    MFA_FAILED = "MFA_FAILED"
    # Vault tokens
    VAULT_TOKEN_CREATE = "VAULT_TOKEN_CREATE"
    VAULT_TOKEN_RENEW = "VAULT_TOKEN_RENEW"
    VAULT_TOKEN_REVOKE = "VAULT_TOKEN_REVOKE"
    VAULT_TOKEN_LOOKUP = "VAULT_TOKEN_LOOKUP"
    # Secrets
    SECRET_CREATE = "SECRET_CREATE"
    SECRET_READ = "SECRET_READ"
    SECRET_UPDATE = "SECRET_UPDATE"
    SECRET_DELETE = "SECRET_DELETE"
    SECRET_RESTORE = "SECRET_RESTORE"
    SECRET_PURGE = "SECRET_PURGE"
    SECRET_ROLLBACK = "SECRET_ROLLBACK"
    SECRET_ROTATE = "SECRET_ROTATE"
    SECRET_ACCESS_DENIED = "SECRET_ACCESS_DENIED"
    SECRET_VERSION_READ = "SECRET_VERSION_READ"
    # Dynamic secrets
    DYNAMIC_CRED_GENERATE = "DYNAMIC_CRED_GENERATE"
    DYNAMIC_CRED_REVOKE = "DYNAMIC_CRED_REVOKE"
    # Leases
    LEASE_CREATE = "LEASE_CREATE"
    LEASE_RENEW = "LEASE_RENEW"
    LEASE_REVOKE = "LEASE_REVOKE"
    LEASE_EXPIRE = "LEASE_EXPIRE"
    # Response wrapping
    WRAP_CREATE = "WRAP_CREATE"
    WRAP_UNWRAP = "WRAP_UNWRAP"
    WRAP_EXPIRED = "WRAP_EXPIRED"
    # Cubbyhole
    CUBBYHOLE_WRITE = "CUBBYHOLE_WRITE"
    CUBBYHOLE_READ = "CUBBYHOLE_READ"
    CUBBYHOLE_DELETE = "CUBBYHOLE_DELETE"
    # Policy
    POLICY_CREATE = "POLICY_CREATE"
    POLICY_UPDATE = "POLICY_UPDATE"
    POLICY_DELETE = "POLICY_DELETE"
    POLICY_ASSIGN = "POLICY_ASSIGN"
    POLICY_REVOKE = "POLICY_REVOKE"
    # Org/team/namespace
    ORG_CREATE = "ORG_CREATE"
    PROJECT_CREATE = "PROJECT_CREATE"
    TEAM_CREATE = "TEAM_CREATE"
    NAMESPACE_CREATE = "NAMESPACE_CREATE"


# ── M2M tables ────────────────────────────────────────────────────────────────

user_policy_table = Table(
    "user_policies", Base.metadata,
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("policy_id", UUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"), primary_key=True),
    Column("assigned_at", DateTime(timezone=True), default=_now),
)

team_member_table = Table(
    "team_members", Base.metadata,
    Column("team_id", UUID(as_uuid=True), ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True),
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("joined_at", DateTime(timezone=True), default=_now),
    Column("role", String(32), default="member"),
)


# ── Core user models ──────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.USER, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # MFA
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Org
    org_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True)

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    secrets: Mapped[list["Secret"]] = relationship(back_populates="owner", cascade="all, delete-orphan")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="user")
    policies: Mapped[list["Policy"]] = relationship(secondary=user_policy_table, back_populates="users")
    mfa_config: Mapped["MFAConfig | None"] = relationship(back_populates="user", uselist=False, cascade="all, delete-orphan")
    vault_tokens: Mapped[list["VaultToken"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    cubbyhole_entries: Mapped[list["CubbyholeEntry"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    org: Mapped["Organization | None"] = relationship(back_populates="members", foreign_keys=[org_id])


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship(back_populates="refresh_tokens")


# ── MFA ───────────────────────────────────────────────────────────────────────

class MFAConfig(Base):
    __tablename__ = "mfa_configs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    totp_secret: Mapped[str] = mapped_column(String(64), nullable=False)
    recovery_codes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship(back_populates="mfa_config")


# ── Org / Project / Team / Namespace ─────────────────────────────────────────

class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    members: Mapped[list["User"]] = relationship(back_populates="org", foreign_keys="User.org_id")
    projects: Mapped[list["Project"]] = relationship(back_populates="org", cascade="all, delete-orphan")
    namespaces: Mapped[list["Namespace"]] = relationship(back_populates="org", cascade="all, delete-orphan")


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    org: Mapped["Organization"] = relationship(back_populates="projects")
    teams: Mapped[list["Team"]] = relationship(back_populates="project", cascade="all, delete-orphan")

    __table_args__ = (Index("ix_projects_org_name", "org_id", "name", unique=True),)


class Team(Base):
    __tablename__ = "teams"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    project: Mapped["Project"] = relationship(back_populates="teams")
    members: Mapped[list["User"]] = relationship(secondary=team_member_table)


class Namespace(Base):
    __tablename__ = "namespaces"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    path: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("namespaces.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    org: Mapped["Organization"] = relationship(back_populates="namespaces")
    children: Mapped[list["Namespace"]] = relationship()


# ── Policy ────────────────────────────────────────────────────────────────────

class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    permissions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    parent_policy_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("policies.id", ondelete="SET NULL"), nullable=True)
    namespace_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("namespaces.id", ondelete="SET NULL"), nullable=True)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    users: Mapped[list["User"]] = relationship(secondary=user_policy_table, back_populates="policies")
    parent: Mapped["Policy | None"] = relationship(remote_side="Policy.id")


# ── Secrets ───────────────────────────────────────────────────────────────────

class Secret(Base):
    __tablename__ = "secrets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    namespace_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("namespaces.id", ondelete="SET NULL"), nullable=True)
    key: Mapped[str] = mapped_column(String(255), nullable=False)
    encrypted_value: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    tags: Mapped[list | None] = mapped_column(JSON, nullable=True, default=list)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[SecretStatus] = mapped_column(Enum(SecretStatus), default=SecretStatus.ACTIVE, nullable=False, index=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    encryption_algorithm: Mapped[str] = mapped_column(String(32), default="AES-256-GCM", nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    last_accessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    access_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Expiration / scheduling
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scheduled_delete_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Rotation
    rotation_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    rotation_interval_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_rotation_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    owner: Mapped["User"] = relationship(back_populates="secrets")
    versions: Mapped[list["SecretVersion"]] = relationship(back_populates="secret", cascade="all, delete-orphan", order_by="SecretVersion.version_number.desc()")
    rotation_history: Mapped[list["RotationHistory"]] = relationship(back_populates="secret", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_secrets_owner_key_active", "owner_id", "key",
              postgresql_where="is_deleted = false"),
        Index("ix_secrets_expires_at", "expires_at"),
        CheckConstraint("version >= 1", name="ck_secrets_version_positive"),
    )


class SecretVersion(Base):
    """Immutable version history for every secret value change."""
    __tablename__ = "secret_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    secret_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("secrets.id", ondelete="CASCADE"), nullable=False, index=True)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    encrypted_value: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    change_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_current: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    secret: Mapped["Secret"] = relationship(back_populates="versions")

    __table_args__ = (
        Index("ix_secret_versions_secret_version", "secret_id", "version_number", unique=True),
    )


class RotationHistory(Base):
    __tablename__ = "rotation_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    secret_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("secrets.id", ondelete="CASCADE"), nullable=False, index=True)
    old_version: Mapped[int] = mapped_column(Integer, nullable=False)
    new_version: Mapped[int] = mapped_column(Integer, nullable=False)
    rotation_type: Mapped[str] = mapped_column(String(32), nullable=False)  # manual/scheduled/automatic
    status: Mapped[RotationStatus] = mapped_column(Enum(RotationStatus), nullable=False)
    initiated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    secret: Mapped["Secret"] = relationship(back_populates="rotation_history")


# ── Dynamic Credentials + Leases ─────────────────────────────────────────────

class DynamicCredential(Base):
    __tablename__ = "dynamic_credentials"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    credential_type: Mapped[CredentialType] = mapped_column(Enum(CredentialType), nullable=False)
    encrypted_credentials: Mapped[str] = mapped_column(Text, nullable=False)
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    extra_data: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)

    lease: Mapped["Lease | None"] = relationship(back_populates="credential", uselist=False)


class Lease(Base):
    __tablename__ = "leases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    lease_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    credential_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("dynamic_credentials.id", ondelete="CASCADE"), nullable=True)
    status: Mapped[LeaseStatus] = mapped_column(Enum(LeaseStatus), default=LeaseStatus.ACTIVE, nullable=False)
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    renewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    renewal_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_renewals: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    credential: Mapped["DynamicCredential | None"] = relationship(back_populates="lease")


# ── Vault Token Engine ────────────────────────────────────────────────────────

class VaultToken(Base):
    __tablename__ = "vault_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    parent_token_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    token_type: Mapped[TokenType] = mapped_column(Enum(TokenType), default=TokenType.SERVICE, nullable=False)
    status: Mapped[TokenStatus] = mapped_column(Enum(TokenStatus), default=TokenStatus.ACTIVE, nullable=False)
    policies: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=3600)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_renewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    renewal_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_renewals: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    extra_data: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)

    user: Mapped["User"] = relationship(back_populates="vault_tokens")


# ── Response Wrapping ─────────────────────────────────────────────────────────

class WrappedToken(Base):
    __tablename__ = "wrapped_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    wrap_token: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    wrap_token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    encrypted_payload: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


# ── Cubbyhole ─────────────────────────────────────────────────────────────────

class CubbyholeEntry(Base):
    __tablename__ = "cubbyhole_entries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    vault_token_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    key: Mapped[str] = mapped_column(String(255), nullable=False)
    encrypted_value: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship(back_populates="cubbyhole_entries")

    __table_args__ = (
        Index("ix_cubbyhole_user_key", "user_id", "key", unique=True),
    )


# ── Service Accounts ──────────────────────────────────────────────────────────

class ServiceAccount(Base):
    __tablename__ = "service_accounts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    api_key_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    org_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True)
    policy_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ── Audit Log ─────────────────────────────────────────────────────────────────

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action: Mapped[AuditAction] = mapped_column(Enum(AuditAction), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    execution_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    extra_data: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    namespace_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("namespaces.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)

    user: Mapped["User | None"] = relationship(back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_logs_user_action", "user_id", "action"),
    )


# ── Engine Registry ───────────────────────────────────────────────────────────

class EngineStatus(str, PyEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    MOUNTED = "mounted"


class EngineMount(Base):
    """
    Persistent registry of all secrets engine mounts.
    Tracks enabled/disabled/mounted state per engine.
    """
    __tablename__ = "engine_mounts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    engine_type: Mapped[str] = mapped_column(String(64), nullable=False)
    mount_path: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[EngineStatus] = mapped_column(Enum(EngineStatus), default=EngineStatus.ENABLED, nullable=False)
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    namespace_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("namespaces.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    mounted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ── Policy Inheritance ────────────────────────────────────────────────────────

class PolicyInheritance(Base):
    """
    Tracks explicit parent-child policy relationships.
    Allows policy trees to be walked for effective permission calculation.
    """
    __tablename__ = "policy_inheritance"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    parent_policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"), nullable=False, index=True)
    child_policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"), nullable=False, index=True)
    override: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    __table_args__ = (
        Index("ix_policy_inheritance_pair", "parent_policy_id", "child_policy_id", unique=True),
    )


# ═══════════════════════════════════════════════════════
# NanoVault v3.0 Models
# ═══════════════════════════════════════════════════════

class TransitKeyType(str, PyEnum):
    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    RSA_4096 = "rsa-4096"
    ED25519 = "ed25519"

class TransitKeyStatus(str, PyEnum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    DISABLED = "disabled"
    DESTROYED = "destroyed"

class CertificateType(str, PyEnum):
    ROOT_CA = "root_ca"
    INTERMEDIATE_CA = "intermediate_ca"
    SERVER = "server"
    CLIENT = "client"
    MTLS = "mtls"
    INTERNAL = "internal"

class CertificateStatus(str, PyEnum):
    VALID = "valid"
    REVOKED = "revoked"
    EXPIRED = "expired"
    PENDING = "pending"

class SealStatus(str, PyEnum):
    SEALED = "sealed"
    UNSEALED = "unsealed"

class UnsealProviderType(str, PyEnum):
    AWS_KMS = "aws_kms"
    AZURE_KEY_VAULT = "azure_key_vault"
    GCP_KMS = "gcp_kms"
    LOCAL_HSM = "local_hsm"
    MANUAL = "manual"

class IdentityProviderType(str, PyEnum):
    OIDC = "oidc"
    LDAP = "ldap"
    ACTIVE_DIRECTORY = "active_directory"
    JWT = "jwt"
    SAML = "saml"

class PolicyFileFormat(str, PyEnum):
    YAML = "yaml"
    JSON = "json"
    HCL = "hcl"


class TransitKey(Base):
    __tablename__ = "transit_keys"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    key_type: Mapped[TransitKeyType] = mapped_column(Enum(TransitKeyType), nullable=False)
    status: Mapped[TransitKeyStatus] = mapped_column(Enum(TransitKeyStatus), default=TransitKeyStatus.ACTIVE, nullable=False)
    current_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    min_decryption_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    exportable: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    deletion_allowed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    labels: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    rotation_policy_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_rotation_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    versions: Mapped[list["TransitKeyVersion"]] = relationship(back_populates="key", cascade="all, delete-orphan")


class TransitKeyVersion(Base):
    __tablename__ = "transit_key_versions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("transit_keys.id", ondelete="CASCADE"), nullable=False, index=True)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    encrypted_key_material: Mapped[str] = mapped_column(Text, nullable=False)
    public_key_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    is_current: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    archived: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    destroyed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    key: Mapped["TransitKey"] = relationship(back_populates="versions")
    __table_args__ = (Index("ix_transit_key_versions_key_ver", "key_id", "version_number", unique=True),)


class CertificateAuthority(Base):
    __tablename__ = "certificate_authorities"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    ca_type: Mapped[CertificateType] = mapped_column(Enum(CertificateType), nullable=False)
    parent_ca_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("certificate_authorities.id", ondelete="SET NULL"), nullable=True)
    subject_dn: Mapped[str] = mapped_column(Text, nullable=False)
    certificate_pem: Mapped[str] = mapped_column(Text, nullable=False)
    encrypted_private_key: Mapped[str] = mapped_column(Text, nullable=False)
    serial_number: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    key_algorithm: Mapped[str] = mapped_column(String(64), nullable=False, default="RSA-4096")
    status: Mapped[CertificateStatus] = mapped_column(Enum(CertificateStatus), default=CertificateStatus.VALID, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    certificates: Mapped[list["Certificate"]] = relationship(back_populates="ca", cascade="all, delete-orphan")
    children: Mapped[list["CertificateAuthority"]] = relationship()


class Certificate(Base):
    __tablename__ = "certificates"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ca_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("certificate_authorities.id", ondelete="CASCADE"), nullable=False, index=True)
    cert_type: Mapped[CertificateType] = mapped_column(Enum(CertificateType), nullable=False)
    common_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    subject_dn: Mapped[str] = mapped_column(Text, nullable=False)
    san_dns: Mapped[list | None] = mapped_column(JSON, nullable=True)
    san_ips: Mapped[list | None] = mapped_column(JSON, nullable=True)
    certificate_pem: Mapped[str] = mapped_column(Text, nullable=False)
    certificate_chain_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    csr_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    serial_number: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    status: Mapped[CertificateStatus] = mapped_column(Enum(CertificateStatus), default=CertificateStatus.VALID, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    renewed_from_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("certificates.id", ondelete="SET NULL"), nullable=True)
    issued_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    ca: Mapped["CertificateAuthority"] = relationship(back_populates="certificates")


class VaultSealState(Base):
    __tablename__ = "vault_seal_state"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    status: Mapped[SealStatus] = mapped_column(Enum(SealStatus), default=SealStatus.SEALED, nullable=False)
    total_shares: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    shares_provided: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    encrypted_master_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    unseal_provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sealed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    unsealed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    initialized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class ShamirShare(Base):
    __tablename__ = "shamir_shares"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    share_index: Mapped[int] = mapped_column(Integer, nullable=False)
    share_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    distributed_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AutoUnsealProvider(Base):
    __tablename__ = "auto_unseal_providers"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    provider_type: Mapped[UnsealProviderType] = mapped_column(Enum(UnsealProviderType), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_healthy: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    last_health_check: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class IdentityProvider(Base):
    __tablename__ = "identity_providers"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    provider_type: Mapped[IdentityProviderType] = mapped_column(Enum(IdentityProviderType), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    group_mappings: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    role_mappings: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    namespace_mappings: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class PolicyFile(Base):
    __tablename__ = "policy_files"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    format: Mapped[PolicyFileFormat] = mapped_column(Enum(PolicyFileFormat), nullable=False)
    current_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    versions: Mapped[list["PolicyFileVersion"]] = relationship(back_populates="policy_file", cascade="all, delete-orphan")


class PolicyFileVersion(Base):
    __tablename__ = "policy_file_versions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_file_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("policy_files.id", ondelete="CASCADE"), nullable=False, index=True)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    parsed_permissions: Mapped[list | None] = mapped_column(JSON, nullable=True)
    is_valid: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    validation_errors: Mapped[list | None] = mapped_column(JSON, nullable=True)
    is_current: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    policy_file: Mapped["PolicyFile"] = relationship(back_populates="versions")
    __table_args__ = (Index("ix_policy_file_versions_file_ver", "policy_file_id", "version_number", unique=True),)


# ═══════════════════════════════════════════════════════════════════════════
# NanoVault v4.0 Models — Platform Experience & Engineering Excellence
# ═══════════════════════════════════════════════════════════════════════════

class BenchmarkStatus(str, PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class BenchmarkRun(Base):
    """Stores the results of every benchmark execution for historical comparison."""
    __tablename__ = "benchmark_runs"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    benchmark_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # e.g. "crypto", "secrets", "transit", "pki", "auth", "full"
    status: Mapped[BenchmarkStatus] = mapped_column(Enum(BenchmarkStatus), default=BenchmarkStatus.COMPLETED)
    results: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # {"aes_encrypt_1000_ms": 12.3, "throughput_ops_per_sec": 81000, ...}
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class DemoDataset(Base):
    """Tracks demo data seeding sessions so they can be identified and reset."""
    __tablename__ = "demo_datasets"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    label: Mapped[str] = mapped_column(String(128), nullable=False, default="enterprise-demo")
    loaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    records_created: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # {"orgs": 2, "namespaces": 6, "secrets": 40, "transit_keys": 5, ...}
    loaded_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


class AuditReplayEvent(Base):
    """
    Captures a snapshot of each audit event at replay time, enriched with
    context (resolved names, payload summaries) so the replay engine can
    reconstruct a full timeline without hitting the live DB on every seek.
    """
    __tablename__ = "audit_replay_events"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audit_log_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("audit_logs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # replay session identifier so multiple replays can coexist
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resource: Mapped[str | None] = mapped_column(String(255), nullable=True)
    namespace: Mapped[str | None] = mapped_column(String(255), nullable=True)
    payload_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    original_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (Index("ix_replay_events_session_seq", "session_id", "sequence"),)
