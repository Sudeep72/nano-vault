"""Pytest configuration — NanoVault v2.0 Enterprise Hardening"""
import asyncio
import base64
import os
import pytest
import pytest_asyncio

os.environ["SECRET_KEY"] = "test-secret-key-min-32-characters-long!"
os.environ["JWT_SECRET_KEY"] = "test-jwt-key-min-32-characters-long!!!"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["ENCRYPTION_KEY"] = base64.b64encode(b"0" * 32).decode()
os.environ["ALLOWED_ORIGINS"] = "http://localhost:3000"
os.environ["APP_VERSION"] = "2.0.0"

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import StaticPool
from httpx import AsyncClient, ASGITransport

_engine = create_async_engine(
    "sqlite+aiosqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_Session = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)

import app.db.session as _db
_db.engine = _engine
_db.AsyncSessionLocal = _Session

from app.db.session import Base, get_db
from app.main import app

# Disable rate limiting in tests
from slowapi import Limiter
from slowapi.util import get_remote_address
_noop_limiter = Limiter(key_func=get_remote_address, default_limits=[])
app.state.limiter = _noop_limiter


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _create_schema():
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # Seed built-in policies and engine mounts
    async with _Session() as db:
        from app.services.policy_service import policy_service
        from app.services.v2.engine_service import engine_service
        await policy_service.seed_builtins(db)
        await engine_service.seed_defaults(db)
        await db.commit()
    yield
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture()
async def client(_create_schema):
    async def _override():
        async with _Session() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    app.dependency_overrides[get_db] = _override
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c
    finally:
        app.dependency_overrides.clear()
        # Wipe data rows between tests
        try:
            async with _engine.begin() as conn:
                from app.models.models import (
                    AuditLog, Secret, SecretVersion, RotationHistory,
                    RefreshToken, user_policy_table, User, Policy,
                    DynamicCredential, Lease, VaultToken, WrappedToken,
                    CubbyholeEntry, MFAConfig, Organization, Project,
                    Team, Namespace, ServiceAccount, team_member_table,
                    EngineMount, PolicyInheritance,
                )
                for table in [
                    AuditLog.__table__, RotationHistory.__table__,
                    SecretVersion.__table__, Secret.__table__,
                    CubbyholeEntry.__table__, WrappedToken.__table__,
                    VaultToken.__table__, Lease.__table__,
                    DynamicCredential.__table__, RefreshToken.__table__,
                    MFAConfig.__table__, team_member_table,
                    user_policy_table, Team.__table__,
                    Project.__table__, Namespace.__table__,
                    PolicyInheritance.__table__,
                    ServiceAccount.__table__, User.__table__,
                    Organization.__table__, EngineMount.__table__,
                ]:
                    try:
                        await conn.execute(table.delete())
                    except Exception:
                        pass
                # Keep builtin policies
                try:
                    await conn.execute(
                        Policy.__table__.delete().where(
                            Policy.__table__.c.is_builtin == False  # noqa
                        )
                    )
                except Exception:
                    pass
        except Exception:
            pass  # teardown errors must not fail tests

        # Re-seed engine mounts after teardown
        try:
            async with _Session() as db:
                from app.services.v2.engine_service import engine_service
                await engine_service.seed_defaults(db)
                await db.commit()
        except Exception:
            pass


@pytest_asyncio.fixture
async def registered_user(client):
    payload = {"username": "testuser", "email": "test@example.com", "password": "SecurePass1!"}
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201, resp.text
    return payload


@pytest_asyncio.fixture
async def auth_headers(client, registered_user):
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, Policy, user_policy_table
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        user = (await db.execute(
            select(User).where(User.username == "testuser")
        )).scalar_one()
        policy = (await db.execute(
            select(Policy).where(Policy.name == "admin")
        )).scalar_one()
        exists = (await db.execute(
            select(user_policy_table).where(
                user_policy_table.c.user_id == user.id,
                user_policy_table.c.policy_id == policy.id,
            )
        )).first()
        if not exists:
            await db.execute(user_policy_table.insert().values(
                user_id=user.id, policy_id=policy.id
            ))
        await db.commit()

    resp = await client.post("/api/v1/auth/login", json={
        "username": registered_user["username"],
        "password": registered_user["password"],
    })
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['data']['access_token']}"}
