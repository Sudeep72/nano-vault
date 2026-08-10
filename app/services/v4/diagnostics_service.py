"""
Developer Experience — Config Validator, Environment Checker, Startup
Diagnostics — NanoVault v4.0

Mirrors the exact validation rules in app/core/config.py's validate_startup(),
but reports every finding instead of sys.exit(1) on the first failure —
so `nvctl diagnose` gives you the full picture in one pass, not one error
at a time across repeated restarts.
"""
from __future__ import annotations
import base64
import importlib
import os
import sys
from app.core.config import settings

REQUIRED_ENV_VARS = ["DATABASE_URL", "JWT_SECRET_KEY", "SECRET_KEY", "ENCRYPTION_KEY"]
OPTIONAL_ENV_VARS = ["REDIS_URL", "OTEL_EXPORTER_OTLP_ENDPOINT", "ALLOWED_ORIGINS"]
REQUIRED_PACKAGES = [
    "fastapi", "sqlalchemy", "cryptography", "jose", "passlib", "pydantic",
    "httpx", "click", "rich", "apscheduler", "prometheus_client",
]
OPTIONAL_PACKAGES = ["redis", "opentelemetry", "ldap3", "jwt"]


class DiagnosticsService:

    @staticmethod
    def validate_config() -> dict:
        """Same rules as Settings.validate_startup(), but collects every issue."""
        checks = []

        def check(name, condition, message):
            checks.append({"check": name, "passed": condition, "message": message if not condition else "OK"})

        check("DATABASE_URL set", bool(settings.DATABASE_URL), "DATABASE_URL is not set")
        check("JWT_SECRET_KEY set", bool(settings.JWT_SECRET_KEY), "JWT_SECRET_KEY is not set")
        check("JWT_SECRET_KEY length", len(settings.JWT_SECRET_KEY or "") >= 32,
              "JWT_SECRET_KEY must be at least 32 characters")
        check("SECRET_KEY set", bool(settings.SECRET_KEY), "SECRET_KEY is not set")
        check("ENCRYPTION_KEY set", bool(settings.ENCRYPTION_KEY), "ENCRYPTION_KEY is not set")

        if settings.ENCRYPTION_KEY:
            try:
                key_bytes = base64.b64decode(settings.ENCRYPTION_KEY)
                check("ENCRYPTION_KEY decodes to 32 bytes", len(key_bytes) == 32,
                      f"ENCRYPTION_KEY decodes to {len(key_bytes)} bytes, expected 32 (AES-256)")
            except Exception:
                check("ENCRYPTION_KEY is valid base64", False, "ENCRYPTION_KEY is not valid base64")

        passed = sum(1 for c in checks if c["passed"])
        return {"checks": checks, "passed": passed, "total": len(checks),
                "all_passed": passed == len(checks)}

    @staticmethod
    def check_environment() -> dict:
        results = {"required": [], "optional": []}
        for var in REQUIRED_ENV_VARS:
            results["required"].append({"var": var, "set": bool(os.environ.get(var) or getattr(settings, var, None))})
        for var in OPTIONAL_ENV_VARS:
            results["optional"].append({"var": var, "set": bool(os.environ.get(var))})

        results["python_version"] = sys.version.split()[0]
        results["python_ok"] = sys.version_info >= (3, 12)
        return results

    @staticmethod
    def check_dependencies() -> dict:
        required_status = []
        for pkg in REQUIRED_PACKAGES:
            try:
                importlib.import_module(pkg)
                required_status.append({"package": pkg, "installed": True})
            except ImportError:
                required_status.append({"package": pkg, "installed": False})

        optional_status = []
        for pkg in OPTIONAL_PACKAGES:
            try:
                importlib.import_module(pkg)
                optional_status.append({"package": pkg, "installed": True})
            except ImportError:
                optional_status.append({"package": pkg, "installed": False,
                                        "note": "optional — related features fail open without it"})

        missing_required = [p["package"] for p in required_status if not p["installed"]]
        return {"required": required_status, "optional": optional_status,
                "all_required_installed": len(missing_required) == 0,
                "missing_required": missing_required}

    @staticmethod
    async def startup_diagnostics(db) -> dict:
        """Full diagnostic sweep — config + env + deps + live DB connectivity."""
        from sqlalchemy import text
        config_result = DiagnosticsService.validate_config()
        env_result = DiagnosticsService.check_environment()
        deps_result = DiagnosticsService.check_dependencies()

        db_ok = True
        db_error = None
        try:
            await db.execute(text("SELECT 1"))
        except Exception as e:
            db_ok = False
            db_error = str(e)

        overall_healthy = config_result["all_passed"] and deps_result["all_required_installed"] and db_ok

        return {
            "overall_healthy": overall_healthy,
            "config": config_result,
            "environment": env_result,
            "dependencies": deps_result,
            "database": {"connected": db_ok, "error": db_error},
        }

    @staticmethod
    def get_sample_env() -> str:
        """Returns the exact .env template scripts/generate_env.py produces,
        for developers who want to see it without running the script."""
        return (
            "# NanoVault sample .env — see scripts/generate_env.py for the real generator\n"
            "SECRET_KEY=<32+ char random string>\n"
            "JWT_SECRET_KEY=<32+ char random string>\n"
            "ENCRYPTION_KEY=<base64-encoded 32 random bytes>\n"
            "DATABASE_URL=postgresql+asyncpg://nano_vault_user:nano_vault_pass@localhost:5432/nano_vault_db\n"
            "ALLOWED_ORIGINS=http://localhost:3000\n"
            "# Optional:\n"
            "# REDIS_URL=redis://localhost:6379/0\n"
            "# OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317\n"
        )


diagnostics_service = DiagnosticsService()
