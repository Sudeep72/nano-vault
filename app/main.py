"""
NanoVault v1.0.1 — Production-Inspired Secrets Management Platform
"""
import logging
import logging.config
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
from app.api.v1.endpoints import auth, secrets, audit, policies, health

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"],
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Validate config — exits with clear message if anything is wrong
    settings.validate_startup()

    # 2. Init DB engine if not already injected (tests inject before import)
    from app.db.session import create_engine_from_settings, engine, Base
    if engine is None:
        _engine = create_engine_from_settings(settings.DATABASE_URL, settings.DEBUG)
    else:
        _engine = engine

    # 3. Create tables
    async with _engine.begin() as conn:
        await conn.run_sync(lambda c: Base.metadata.create_all(c, checkfirst=True))

    # 4. Seed built-in policies
    from app.db.session import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        from app.services.policy_service import policy_service
        await policy_service.seed_builtins(db)
        await db.commit()

    logging.getLogger("nano_vault").info(
        "NanoVault %s started — env=%s", settings.APP_VERSION, settings.APP_ENV
    )
    yield
    await _engine.dispose()


app = FastAPI(
    title="NanoVault",
    description=(
        "## 🔐 NanoVault\n\n"
        "Production-inspired secrets management platform.\n\n"
        "**Features:** AES-256-GCM encryption · JWT + Argon2id auth · "
        "Path-based RBAC · Immutable audit trail · Soft delete + restore\n\n"
        "**Auth:** Use `/api/v1/auth/login` to obtain a Bearer token, "
        "then click **Authorize** above and paste it."
    ),
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_tags=[
        {"name": "Authentication", "description": "Register, login, token lifecycle"},
        {"name": "KV Secrets Engine", "description": "Create, read, update, delete, search, restore secrets"},
        {"name": "Policy Engine", "description": "Named policies with path-based permissions"},
        {"name": "Audit", "description": "Immutable append-only event log"},
        {"name": "Observability", "description": "Health check and metrics"},
        {"name": "Admin", "description": "Admin-only operations"},
    ],
)

# ── Middleware (outermost first) ──────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.MAX_REQUEST_SIZE_BYTES)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(StructuredLoggingMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID", "X-Response-Time-Ms"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
prefix = settings.API_V1_PREFIX
app.include_router(auth.router, prefix=prefix)
app.include_router(secrets.router, prefix=prefix)
app.include_router(audit.router, prefix=prefix)
app.include_router(policies.router, prefix=prefix)
app.include_router(health.router)   # /health and /metrics at root level


# ── Docs (local assets, no CDN dependency for JS/CSS) ────────────────────────
@app.get("/docs", include_in_schema=False)
async def swagger_ui():
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="NanoVault API",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
    )


@app.get("/redoc", include_in_schema=False)
async def redoc_ui():
    return get_redoc_html(
        openapi_url="/openapi.json",
        title="NanoVault API — ReDoc",
        redoc_js_url="https://cdn.jsdelivr.net/npm/redoc@latest/bundles/redoc.standalone.js",
    )


@app.get("/", include_in_schema=False)
async def root():
    return HTMLResponse("""<!DOCTYPE html>
<html><head><title>NanoVault</title>
<style>
  body{font-family:monospace;background:#0d1117;color:#58a6ff;
       display:flex;align-items:center;justify-content:center;
       height:100vh;margin:0;flex-direction:column;gap:8px;}
  h1{font-size:2rem;margin:0;}
  p{color:#8b949e;margin:4px 0 16px;}
  .links a{color:#3fb950;margin:0 12px;text-decoration:none;font-size:1.1rem;}
  .links a:hover{text-decoration:underline;}
  .badge{background:#161b22;border:1px solid #30363d;border-radius:6px;
         padding:4px 12px;font-size:.85rem;color:#8b949e;}
</style></head>
<body>
  <h1>🔐 NanoVault</h1>
  <p>Production-inspired secrets management platform</p>
  <div class="links">
    <a href="/docs">Swagger UI</a>
    <a href="/redoc">ReDoc</a>
    <a href="/health">Health</a>
    <a href="/metrics">Metrics</a>
  </div>
  <br>
  <span class="badge">v1.0.1 · AES-256-GCM · JWT · RBAC · Audit</span>
</body></html>""")


# ── Global exception handler ──────────────────────────────────────────────────
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logging.getLogger("nano_vault").error(
        "Unhandled exception: %s %s — %s", request.method, request.url.path, exc
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"success": False, "error": "An internal error occurred", "details": {}},
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={"success": False, "error": "Not found", "details": {"path": request.url.path}},
    )
