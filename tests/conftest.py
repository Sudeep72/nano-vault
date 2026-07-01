"""Pytest configuration and shared fixtures."""
import asyncio
import base64
import os
import pytest
import pytest_asyncio

# Set env BEFORE any app imports
os.environ["SECRET_KEY"] = "test-secret-key-min-32-characters-long!"
os.environ["JWT_SECRET_KEY"] = "test-jwt-key-min-32-characters-long!!!"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["ENCRYPTION_KEY"] = base64.b64encode(b"0" * 32).decode()
os.environ["ALLOWED_ORIGINS"] = "http://localhost:3000"

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import StaticPool
from httpx import AsyncClient, ASGITransport

# Build the shared in-memory engine and inject into db module BEFORE app imports
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
    """Create all tables once per session."""
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
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
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as c:
            yield c
    finally:
        app.dependency_overrides.clear()
        # Wipe all rows after each test
        async with _engine.begin() as conn:
            for table in reversed(Base.metadata.sorted_tables):
                await conn.execute(table.delete())


@pytest_asyncio.fixture
async def registered_user(client):
    payload = {"username": "testuser", "email": "test@example.com", "password": "SecurePass1!"}
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201, resp.text
    return payload


@pytest_asyncio.fixture
async def auth_headers(client, registered_user):
    resp = await client.post("/api/v1/auth/login", json={
        "username": registered_user["username"],
        "password": registered_user["password"],
    })
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}
