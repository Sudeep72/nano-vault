"""
Secrets Engine Base — NanoVault v2.0

All secrets engines implement this interface.
New engines plug in without modifying existing code.
"""
from abc import ABC, abstractmethod
from typing import Any


class BaseSecretsEngine(ABC):
    """Abstract base for all secrets engines."""

    engine_name: str = "base"
    engine_version: str = "1.0"
    description: str = ""

    @abstractmethod
    async def read(self, path: str, **kwargs) -> dict: ...

    @abstractmethod
    async def write(self, path: str, data: dict, **kwargs) -> dict: ...

    @abstractmethod
    async def delete(self, path: str, **kwargs) -> bool: ...

    @abstractmethod
    async def list(self, path: str, **kwargs) -> list[str]: ...

    def metadata(self) -> dict:
        return {
            "engine": self.engine_name,
            "version": self.engine_version,
            "description": self.description,
        }


class EngineRegistry:
    """Registry of all available secrets engines."""
    _engines: dict[str, type[BaseSecretsEngine]] = {}

    @classmethod
    def register(cls, name: str):
        def decorator(engine_cls: type[BaseSecretsEngine]):
            cls._engines[name] = engine_cls
            return engine_cls
        return decorator

    @classmethod
    def get(cls, name: str) -> type[BaseSecretsEngine] | None:
        return cls._engines.get(name)

    @classmethod
    def list_engines(cls) -> list[dict]:
        return [
            {"name": name, "class": cls.__name__}
            for name, cls in cls._engines.items()
        ]


engine_registry = EngineRegistry()
