from __future__ import annotations
"""
Dynamic Secrets Engine — NanoVault v2.0

Generates short-lived credentials on demand.
All credentials have leases and auto-expire.

Supported backends (v2):
  - PostgreSQL (simulated)
  - MySQL (simulated)
  - SQLite (simulated)
  - AWS IAM (simulated)
  - Azure (simulated)
  - GCP (simulated)
  - API Keys (generated)
  - Access Tokens (generated)
"""
import uuid
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException
from app.engines.base import BaseSecretsEngine, engine_registry
from app.models.models import DynamicCredential, Lease, LeaseStatus, CredentialType, User
from app.core.encryption import encryption_service
import json


def _now():
    return datetime.now(timezone.utc)


def _generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _generate_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def _make_lease_id(cred_type: str) -> str:
    return f"{cred_type}/{uuid.uuid4()}"


# ── Credential generators ─────────────────────────────────────────────────────

def _gen_postgres(ttl: int, db_name: str = "app_db") -> dict:
    username = f"nano_dyn_{secrets.token_hex(4)}"
    return {
        "type": "database/postgresql",
        "username": username,
        "password": _generate_password(),
        "host": "localhost",
        "port": 5432,
        "database": db_name,
        "connection_string": f"postgresql://{username}:***@localhost:5432/{db_name}",
        "ttl_seconds": ttl,
        "note": "Simulated — in production connects to PostgreSQL and creates a real role",
    }


def _gen_mysql(ttl: int, db_name: str = "app_db") -> dict:
    username = f"nano_dyn_{secrets.token_hex(4)}"
    return {
        "type": "database/mysql",
        "username": username,
        "password": _generate_password(),
        "host": "localhost",
        "port": 3306,
        "database": db_name,
        "connection_string": f"mysql://{username}:***@localhost:3306/{db_name}",
        "ttl_seconds": ttl,
        "note": "Simulated — in production connects to MySQL and creates a real user",
    }


def _gen_sqlite(ttl: int) -> dict:
    return {
        "type": "database/sqlite",
        "token": _generate_token(16),
        "database_path": f"/tmp/nano_dyn_{secrets.token_hex(4)}.db",
        "ttl_seconds": ttl,
        "note": "Simulated SQLite credential",
    }


def _gen_aws(ttl: int) -> dict:
    access_key = f"ASIA{secrets.token_hex(8).upper()}"
    return {
        "type": "cloud/aws",
        "access_key_id": access_key,
        "secret_access_key": _generate_token(20),
        "session_token": _generate_token(40),
        "region": "us-east-1",
        "ttl_seconds": ttl,
        "note": "Simulated — in production calls AWS STS AssumeRole",
    }


def _gen_azure(ttl: int) -> dict:
    return {
        "type": "cloud/azure",
        "client_id": str(uuid.uuid4()),
        "client_secret": _generate_token(24),
        "tenant_id": str(uuid.uuid4()),
        "subscription_id": str(uuid.uuid4()),
        "ttl_seconds": ttl,
        "note": "Simulated — in production creates Azure Service Principal",
    }


def _gen_gcp(ttl: int) -> dict:
    return {
        "type": "cloud/gcp",
        "service_account_email": f"nano-dyn-{secrets.token_hex(4)}@project.iam.gserviceaccount.com",
        "access_token": _generate_token(32),
        "project_id": f"nano-project-{secrets.token_hex(4)}",
        "ttl_seconds": ttl,
        "note": "Simulated — in production creates GCP service account key",
    }


def _gen_api_key(ttl: int) -> dict:
    return {
        "type": "app/api_key",
        "api_key": f"nv_live_{_generate_token(24)}",
        "key_id": str(uuid.uuid4()),
        "ttl_seconds": ttl,
    }


def _gen_access_token(ttl: int) -> dict:
    return {
        "type": "app/access_token",
        "token": f"nv_tok_{_generate_token(32)}",
        "token_type": "bearer",
        "ttl_seconds": ttl,
    }


_GENERATORS = {
    CredentialType.DATABASE_POSTGRES: _gen_postgres,
    CredentialType.DATABASE_MYSQL: _gen_mysql,
    CredentialType.DATABASE_SQLITE: _gen_sqlite,
    CredentialType.CLOUD_AWS: _gen_aws,
    CredentialType.CLOUD_AZURE: _gen_azure,
    CredentialType.CLOUD_GCP: _gen_gcp,
    CredentialType.APP_API_KEY: _gen_api_key,
    CredentialType.APP_ACCESS_TOKEN: _gen_access_token,
}


@engine_registry.register("dynamic")
class DynamicSecretsEngine(BaseSecretsEngine):
    engine_name = "dynamic"
    engine_version = "2.0"
    description = "Dynamic credential generation with lease management"

    async def read(self, path: str, **kwargs) -> dict:
        raise NotImplementedError("Use generate()")

    async def write(self, path: str, data: dict, **kwargs) -> dict:
        raise NotImplementedError("Use generate()")

    async def delete(self, path: str, **kwargs) -> bool:
        raise NotImplementedError("Use revoke()")

    async def list(self, path: str, **kwargs) -> list[str]:
        raise NotImplementedError("Use list_credentials()")

    @staticmethod
    async def generate(
        db: AsyncSession,
        owner: User,
        credential_type: CredentialType,
        ttl_seconds: int = 3600,
        max_renewals: int = 5,
        **kwargs,
    ) -> tuple[DynamicCredential, Lease, dict]:
        """Generate a dynamic credential and create its lease."""
        if ttl_seconds < 60:
            raise HTTPException(status_code=400, detail="TTL must be at least 60 seconds")
        if ttl_seconds > 86400:
            raise HTTPException(status_code=400, detail="TTL cannot exceed 24 hours")

        generator = _GENERATORS.get(credential_type)
        if not generator:
            raise HTTPException(status_code=400, detail=f"Unsupported credential type: {credential_type}")

        plaintext = generator(ttl_seconds, **kwargs)
        encrypted = encryption_service.encrypt(json.dumps(plaintext))

        now = _now()
        expires = now + timedelta(seconds=ttl_seconds)

        cred = DynamicCredential(
            owner_id=owner.id,
            credential_type=credential_type,
            encrypted_credentials=encrypted,
            ttl_seconds=ttl_seconds,
            expires_at=expires,
            metadata={"generator": credential_type.value},
        )
        db.add(cred)
        await db.flush()

        lease_id = _make_lease_id(credential_type.value)
        lease = Lease(
            lease_id=lease_id,
            owner_id=owner.id,
            credential_id=cred.id,
            ttl_seconds=ttl_seconds,
            expires_at=expires,
            max_renewals=max_renewals,
        )
        db.add(lease)
        await db.flush()

        return cred, lease, plaintext

    @staticmethod
    async def revoke(db: AsyncSession, lease_id: str, owner: User) -> None:
        from sqlalchemy import select
        result = await db.execute(
            select(Lease).where(Lease.lease_id == lease_id, Lease.owner_id == owner.id)
        )
        lease = result.scalar_one_or_none()
        if not lease:
            raise HTTPException(status_code=404, detail="Lease not found")

        lease.status = LeaseStatus.REVOKED
        lease.revoked_at = _now()

        if lease.credential_id:
            cred_result = await db.execute(
                select(DynamicCredential).where(DynamicCredential.id == lease.credential_id)
            )
            cred = cred_result.scalar_one_or_none()
            if cred:
                cred.revoked = True
                cred.revoked_at = _now()
        await db.flush()


dynamic_engine = DynamicSecretsEngine()
