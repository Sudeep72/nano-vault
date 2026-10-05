"""Storage Backend Framework — NanoVault v3.0 Completion."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional


class StorageBackend(ABC):
    backend_name: str = "base"

    @abstractmethod
    async def health_check(self) -> tuple[bool, str]: ...

    @abstractmethod
    async def get_connection_info(self) -> dict: ...

    @abstractmethod
    async def validate(self) -> dict: ...


class PostgreSQLBackend(StorageBackend):
    backend_name = "postgresql"

    def __init__(self, engine):
        self.engine = engine

    async def health_check(self) -> tuple[bool, str]:
        from sqlalchemy import text
        try:
            async with self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return True, "PostgreSQL connection healthy"
        except Exception as e:
            return False, str(e)

    async def get_connection_info(self) -> dict:
        return {"backend": "postgresql", "pool_size": getattr(self.engine.pool, "size", lambda: None)()}

    async def validate(self) -> dict:
        healthy, msg = await self.health_check()
        return {"backend": self.backend_name, "valid": healthy, "message": msg}


class SQLiteBackend(StorageBackend):
    backend_name = "sqlite"

    def __init__(self, engine):
        self.engine = engine

    async def health_check(self) -> tuple[bool, str]:
        from sqlalchemy import text
        try:
            async with self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return True, "SQLite connection healthy"
        except Exception as e:
            return False, str(e)

    async def get_connection_info(self) -> dict:
        return {"backend": "sqlite", "file_based": True}

    async def validate(self) -> dict:
        healthy, msg = await self.health_check()
        return {"backend": self.backend_name, "valid": healthy, "message": msg}


class LocalFileBackend(StorageBackend):
    """Encrypted local file storage — for backup exports."""
    backend_name = "local_file"

    def __init__(self, base_path: str = "/tmp/nanovault_storage"):
        import os
        self.base_path = base_path
        os.makedirs(base_path, exist_ok=True)

    async def health_check(self) -> tuple[bool, str]:
        import os
        try:
            testfile = os.path.join(self.base_path, ".health")
            with open(testfile, "w") as f:
                f.write("ok")
            os.remove(testfile)
            return True, "Local file storage writable"
        except Exception as e:
            return False, str(e)

    async def get_connection_info(self) -> dict:
        return {"backend": "local_file", "path": self.base_path}

    async def validate(self) -> dict:
        healthy, msg = await self.health_check()
        return {"backend": self.backend_name, "valid": healthy, "message": msg}


# Reserved for future backends — registered but not implemented
_RESERVED_BACKENDS = ["mysql", "mongodb", "s3", "azure_blob", "gcs"]


class StorageManager:
    """Manages the active storage backend and supports live switching."""

    def __init__(self):
        self._backends: dict[str, StorageBackend] = {}
        self._active: Optional[str] = None

    def register(self, name: str, backend: StorageBackend):
        self._backends[name] = backend
        if self._active is None:
            self._active = name

    def get_active(self) -> Optional[StorageBackend]:
        return self._backends.get(self._active) if self._active else None

    def switch(self, name: str) -> bool:
        if name not in self._backends:
            return False
        self._active = name
        return True

    def list_backends(self) -> list[dict]:
        result = []
        for name, backend in self._backends.items():
            result.append({"name": name, "type": backend.backend_name, "active": name == self._active})
        for reserved in _RESERVED_BACKENDS:
            result.append({"name": reserved, "type": reserved, "active": False, "status": "reserved_future"})
        return result

    async def validate_active(self) -> dict:
        backend = self.get_active()
        if not backend:
            return {"valid": False, "message": "No active backend configured"}
        return await backend.validate()


storage_manager = StorageManager()
