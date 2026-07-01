"""Pytest configuration and shared fixtures — NanoVault v1.0.1"""
import asyncio
import base64
import os
import pytest
import pytest_asyncio

# Set env before any app imports
os.environ["SECRET_KEY"] = "test-secret-key-min-32-characters-long!"
os.environ["JWT_SECRET_KEY"] = "test-jwt-key-min-32-characters-long!!!"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["ENCRYPTION_KEY"] = base64.b64encode(b"0" * 32).decode()
os.environ["ALLOWED_ORIGINS"] = "http://localhost:3000"
os.environ["APP_VERSION"] = "1.0.1"

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


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _create_schema():
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # Seed built-in policies once
    async with _Session() as db:
        from app.services.policy_service import policy_service
        await policy_service.seed_builtins(db)
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
        # Wipe data rows but keep schema and built-in policies
        async with _engine.begin() as conn:
            # Delete in order to avoid FK violations
            from app.models.models import AuditLog, Secret, RefreshToken, user_policy_table, User, Policy
            for table in [AuditLog.__table__, Secret.__table__, RefreshToken.__table__,
                          user_policy_table, User.__table__]:
                await conn.execute(table.delete())
            # Re-seed built-in policies (Policy table was NOT cleared)
        # Actually clear non-builtin policies too but keep builtins
        async with _Session() as db:
            from sqlalchemy import delete
            from app.models.models import Policy
            await db.execute(delete(Policy).where(Policy.is_builtin == False))  # noqa
            await db.commit()


@pytest_asyncio.fixture
async def registered_user(client):
    payload = {"username": "testuser", "email": "test@example.com", "password": "SecurePass1!"}
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201, resp.text
    return payload


@pytest_asyncio.fixture
async def auth_headers(client, registered_user):
    # Assign 'admin' policy to testuser so secrets tests pass policy checks
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, UserRole, Policy, user_policy_table
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.username == "testuser"))).scalar_one()
        policy = (await db.execute(select(Policy).where(Policy.name == "admin"))).scalar_one()
        # Assign admin policy
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
