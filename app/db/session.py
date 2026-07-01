from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


# Engine and session factory are created lazily or injected by tests/app startup.
# Modules should import `get_db` and `Base`; they must not import `engine` directly.
engine = None  # set by create_engine_from_settings() or test monkey-patch
AsyncSessionLocal = None  # same


def create_engine_from_settings(database_url: str, debug: bool = False):
    """Call once at startup (main.py lifespan) to initialise the engine."""
    global engine, AsyncSessionLocal
    from app.core.config import settings
    _is_sqlite = database_url.startswith("sqlite")
    _kwargs = {} if _is_sqlite else {
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20,
    }
    engine = create_async_engine(database_url, echo=debug, **_kwargs)
    AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    return engine


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
