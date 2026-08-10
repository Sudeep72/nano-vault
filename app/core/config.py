"""
NanoVault Configuration — v1.0.1
Validates all required settings at startup. Missing keys = hard failure with clear message.
"""
import base64
import sys
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    APP_NAME: str = "NanoVault"
    APP_VERSION: str = "4.0.0"
    APP_ENV: str = "development"
    DEBUG: bool = False
    SECRET_KEY: str = ""
    API_V1_PREFIX: str = "/api/v1"

    # JWT
    JWT_SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database
    DATABASE_URL: str = ""

    # Encryption
    ENCRYPTION_KEY: str = ""
    ENCRYPTION_KEY_VERSION: int = 1

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    AUTH_RATE_LIMIT_PER_MINUTE: int = 10

    # CORS
    ALLOWED_ORIGINS: str = "http://localhost:3000"

    # Secret validation limits
    MAX_SECRET_SIZE_BYTES: int = 65536     # 64 KB
    MAX_KEY_LENGTH: int = 255
    MAX_TAG_COUNT: int = 20
    MAX_CATEGORY_LENGTH: int = 128
    MAX_DESCRIPTION_LENGTH: int = 2048

    # Request limits
    MAX_REQUEST_SIZE_BYTES: int = 1_048_576  # 1 MB

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.replace(",", " ").split()]

    def validate_startup(self) -> None:
        """Called at lifespan startup — exits with clear message if config is invalid."""
        errors = []

        if not self.DATABASE_URL:
            errors.append("  DATABASE_URL is not set")
        if not self.JWT_SECRET_KEY:
            errors.append("  JWT_SECRET_KEY is not set")
        if len(self.JWT_SECRET_KEY) < 32:
            errors.append("  JWT_SECRET_KEY must be at least 32 characters")
        if not self.SECRET_KEY:
            errors.append("  SECRET_KEY is not set")
        if not self.ENCRYPTION_KEY:
            errors.append("  ENCRYPTION_KEY is not set")
        else:
            try:
                key_bytes = base64.b64decode(self.ENCRYPTION_KEY)
                if len(key_bytes) != 32:
                    errors.append("  ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256)")
            except Exception:
                errors.append("  ENCRYPTION_KEY is not valid base64")

        if errors:
            print("\n[NanoVault] STARTUP FAILED — missing or invalid configuration:\n")
            for e in errors:
                print(e)
            print("\nRun: python scripts/generate_env.py  to generate a valid .env file\n")
            sys.exit(1)


@lru_cache
def get_settings() -> Settings:
    return Settings()


class _SettingsProxy:
    _instance: Settings | None = None

    def __getattr__(self, name: str):
        if self._instance is None:
            object.__setattr__(self, "_instance", get_settings())
        return getattr(self._instance, name)


settings = _SettingsProxy()
