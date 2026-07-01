from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "NanoVault"
    APP_ENV: str = "development"
    DEBUG: bool = False
    SECRET_KEY: str = ""
    API_V1_PREFIX: str = "/api/v1"

    JWT_SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    DATABASE_URL: str = ""
    ENCRYPTION_KEY: str = ""

    RATE_LIMIT_PER_MINUTE: int = 60
    AUTH_RATE_LIMIT_PER_MINUTE: int = 10
    ALLOWED_ORIGINS: str = "http://localhost:3000"

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.replace(",", " ").split()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Lazy proxy — avoids instantiation at import time when env vars aren't set yet
class _SettingsProxy:
    _instance: Settings | None = None

    def __getattr__(self, name: str):
        if self._instance is None:
            object.__setattr__(self, '_instance', get_settings())
        return getattr(self._instance, name)


settings = _SettingsProxy()
