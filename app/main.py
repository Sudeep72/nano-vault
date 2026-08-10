"""
NanoVault v2.0 Enterprise Hardening Edition
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.core.config import settings
from app.middleware.security import (
    SecurityHeadersMiddleware, RequestIDMiddleware,
    StructuredLoggingMiddleware, RequestSizeLimitMiddleware,
)

# v1 routers
from app.api.v1.endpoints import auth, secrets, audit, policies, health

# v2 routers — original
from app.api.v2.endpoints import kv, dynamic, tokens, mfa, wrap, cubbyhole, orgs, dashboard

# v2 routers — enterprise hardening
from app.api.v2.endpoints import engines, namespaces, policy_inheritance, metadata

# v3 routers — Advanced Vault Platform (Parts 1, 2, 3)
from app.api.v3.endpoints import transit, pki, seal, identity, policy_as_code, ops, completion, final_completion, pass2_completion

# v4 routers — Platform Experience & Engineering Excellence
from app.api.v4.endpoints import architecture, benchmarks, replay, threat_model, demo, dev_experience, playground

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"],
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate_startup()

    from app.db.session import create_engine_from_settings, engine, Base
    if engine is None:
        _engine = create_engine_from_settings(settings.DATABASE_URL, settings.DEBUG)
    else:
        _engine = engine

    async with _engine.begin() as conn:
        await conn.run_sync(lambda c: Base.metadata.create_all(c, checkfirst=True))

    from app.db.session import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        from app.services.policy_service import policy_service
        from app.services.v2.engine_service import engine_service
        await policy_service.seed_builtins(db)
        await engine_service.seed_defaults(db)
        # Trigger v3 engine registration in runtime registry
        from app.engines.transit.engine import transit_engine  # noqa
        from app.engines.pki.engine import pki_engine  # noqa
        await db.commit()

    # Register storage backends (real abstraction, PostgreSQL/SQLite active by default)
    from app.storage.base import storage_manager, PostgreSQLBackend, SQLiteBackend, LocalFileBackend
    if settings.DATABASE_URL.startswith("sqlite"):
        storage_manager.register("sqlite-primary", SQLiteBackend(_engine))
    else:
        storage_manager.register("postgresql-primary", PostgreSQLBackend(_engine))
    storage_manager.register("local-file-backup", LocalFileBackend())

    # Start real APScheduler background jobs (lease cleanup, rotation, token cleanup, engine health)
    from app.services.v3.apscheduler_service import start_scheduler, stop_scheduler
    start_scheduler()

    # OpenTelemetry (no-op unless OTEL_EXPORTER_OTLP_ENDPOINT is set)
    from app.services.v3.otel_service import init_tracing, instrument_fastapi
    init_tracing("nanovault")
    instrument_fastapi(app)

    # Redis cache (no-op unless REDIS_URL is set — falls back silently)
    from app.services.v3.cache_service import init_cache
    init_cache()

    logging.getLogger("nano_vault").info("NanoVault %s started", settings.APP_VERSION)
    yield
    stop_scheduler()
    await _engine.dispose()


app = FastAPI(
    title="NanoVault v3.0 — Advanced Vault Platform",
    description=(
        "## 🔐 NanoVault v2.0 — Enterprise Vault Platform\n\n"
        "**v1 API** — Auth, KV Secrets, Policies, Audit (`/api/v1/`)\n\n"
        "**v2 API** — KV Versioning, Dynamic Secrets, Lease Engine, "
        "Token Engine, MFA, Response Wrapping, Cubbyhole, "
        "Organizations, Teams, Namespaces, Engine Management, "
        "Policy Inheritance, Secret Metadata (`/api/v2/`)\n\n"
        "**Auth:** Login at `/api/v1/auth/login` → click **Authorize** → paste Bearer token.\n\n"
        "**Namespace:** Pass `X-Vault-Namespace: <path>` header to operate in a specific namespace."
    ),
    version="4.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_tags=[
        {"name": "Authentication",             "description": "Register, login, token lifecycle"},
        {"name": "KV Secrets Engine",          "description": "CRUD secrets — v1 compatible"},
        {"name": "KV Secrets Engine v2",       "description": "Versioning, rollback, rotation"},
        {"name": "Dynamic Secrets Engine",     "description": "Generate short-lived credentials with leases"},
        {"name": "Vault Token Engine",         "description": "Service/batch/periodic tokens"},
        {"name": "Identity & MFA",             "description": "TOTP MFA setup, verify, recovery"},
        {"name": "Response Wrapping",          "description": "One-time wrapped token delivery"},
        {"name": "Cubbyhole Engine",           "description": "Private per-token scratch space"},
        {"name": "Organizations & Teams",      "description": "Org, project, team management"},
        {"name": "Namespace Management",       "description": "Logical isolation — create, delete, switch, hierarchy"},
        {"name": "Secrets Engine Management",  "description": "Enable, disable, mount, unmount, reload engines"},
        {"name": "Policy Inheritance",         "description": "Hierarchical policies — effective permissions, inheritance tree"},
        {"name": "Secret Metadata",            "description": "Rich metadata API without exposing values"},
        {"name": "Enterprise Dashboard",       "description": "Full system overview — admin only"},
        {"name": "Policy Engine",              "description": "Named path-based policies"},
        {"name": "Audit",                      "description": "Immutable event log"},
        {"name": "Observability",              "description": "Health and metrics"},
        {"name": "Admin",                      "description": "Admin-only operations"},
    ],
)

# ── Middleware ────────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.MAX_REQUEST_SIZE_BYTES)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(StructuredLoggingMiddleware)

from app.middleware.structured_logging import CorrelationMiddleware, configure_json_logging
if settings.APP_ENV == "production":
    configure_json_logging()
app.add_middleware(CorrelationMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-Vault-Namespace"],
    expose_headers=["X-Request-ID", "X-Response-Time-Ms"],
)

# ── v1 routes ─────────────────────────────────────────────────────────────────
v1 = settings.API_V1_PREFIX
app.include_router(auth.router,     prefix=v1)
app.include_router(secrets.router,  prefix=v1)
app.include_router(audit.router,    prefix=v1)
app.include_router(policies.router, prefix=v1)
app.include_router(health.router)

# ── v2 routes — original ──────────────────────────────────────────────────────
v2 = "/api/v2"
app.include_router(kv.router,         prefix=v2)
app.include_router(dynamic.router,    prefix=v2)
app.include_router(tokens.router,     prefix=v2)
app.include_router(mfa.router,        prefix=v2)
app.include_router(wrap.router,       prefix=v2)
app.include_router(cubbyhole.router,  prefix=v2)
app.include_router(orgs.router,       prefix=v2)
app.include_router(dashboard.router,  prefix=v2)

# ── v2 routes — enterprise hardening ─────────────────────────────────────────
app.include_router(engines.router,             prefix=v2)
app.include_router(namespaces.router,          prefix=v2)
app.include_router(policy_inheritance.router,  prefix=v2)
app.include_router(metadata.router,            prefix=v2)

# ── v3 routes — Advanced Vault Platform ──────────────────────────────────────
v3 = "/api/v3"
app.include_router(transit.router,        prefix=v3)
app.include_router(pki.router,            prefix=v3)
app.include_router(seal.router,           prefix=v3)
app.include_router(identity.router,       prefix=v3)
app.include_router(policy_as_code.router, prefix=v3)
app.include_router(ops.router,            prefix=v3)
app.include_router(completion.router,     prefix=v3)
app.include_router(final_completion.router, prefix=v3)
app.include_router(pass2_completion.router, prefix=v3)

# ── v4 routes — Platform Experience & Engineering Excellence ────────────────
v4 = "/api/v4"
app.include_router(architecture.router,    prefix=v4)
app.include_router(benchmarks.router,      prefix=v4)
app.include_router(replay.router,          prefix=v4)
app.include_router(threat_model.router,    prefix=v4)
app.include_router(demo.router,            prefix=v4)
app.include_router(dev_experience.router,  prefix=v4)
app.include_router(playground.router,      prefix=v4)


@app.get("/docs", include_in_schema=False)
async def swagger_ui():
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="NanoVault Enterprise API",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
    )


@app.get("/redoc", include_in_schema=False)
async def redoc_ui():
    return get_redoc_html(
        openapi_url="/openapi.json",
        title="NanoVault Enterprise — ReDoc",
        redoc_js_url="https://cdn.jsdelivr.net/npm/redoc@latest/bundles/redoc.standalone.js",
    )


@app.get("/", include_in_schema=False)
async def root():
    return HTMLResponse("""<!DOCTYPE html>
<html><head><title>NanoVault Enterprise</title>
<style>
  body{font-family:monospace;background:#0d1117;color:#58a6ff;
       display:flex;align-items:center;justify-content:center;
       height:100vh;margin:0;flex-direction:column;gap:6px;}
  h1{font-size:2rem;margin:0;}p{color:#8b949e;margin:4px 0 12px;}
  .links a{color:#3fb950;margin:0 10px;text-decoration:none;font-size:1rem;}
  .badge{background:#161b22;border:1px solid #30363d;border-radius:6px;
         padding:4px 10px;font-size:.8rem;color:#8b949e;margin:3px;}
  .badges{display:flex;flex-wrap:wrap;justify-content:center;max-width:600px;}
</style></head>
<body>
  <h1>🔐 NanoVault Enterprise</h1>
  <p>Enterprise-grade secrets management platform</p>
  <div class="links">
    <a href="/docs">Swagger</a>
    <a href="/redoc">ReDoc</a>
    <a href="/health">Health</a>
    <a href="/metrics">Metrics</a>
    <a href="/api/v2/dashboard">Dashboard</a>
    <a href="/api/v2/engines">Engines</a>
  </div>
  <br>
  <div class="badges">
    <span class="badge">KV v2 + Versioning</span>
    <span class="badge">Dynamic Secrets</span>
    <span class="badge">Lease Engine</span>
    <span class="badge">Token Engine</span>
    <span class="badge">MFA TOTP</span>
    <span class="badge">Response Wrapping</span>
    <span class="badge">Cubbyhole</span>
    <span class="badge">Namespace Isolation</span>
    <span class="badge">Policy Inheritance</span>
    <span class="badge">Engine Registry</span>
    <span class="badge">Secret Metadata</span>
  </div>
</body></html>""")


@app.get("/health", include_in_schema=False)
async def health_check():
    return JSONResponse({"status": "healthy", "version": "4.0.0", "service": "NanoVault Enterprise"})


@app.get("/routes", include_in_schema=False)
async def list_routes():
    """Debug endpoint — lists all registered API routes."""
    routes = sorted([
        {"path": r.path, "methods": list(r.methods) if hasattr(r, "methods") and r.methods else []}
        for r in app.routes
        if hasattr(r, "path") and r.path.startswith("/api/v2")
    ], key=lambda x: x["path"])
    return JSONResponse({"v2_routes": routes, "count": len(routes)})


@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):
    logging.getLogger("nano_vault").error("Unhandled: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"success": False, "error": "An internal error occurred", "details": {}},
    )


@app.exception_handler(404)
async def not_found(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={"success": False, "error": "Not found", "details": {"path": request.url.path}},
    )
