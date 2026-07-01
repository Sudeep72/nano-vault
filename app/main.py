"""
NanoVault — Production-Inspired Secrets Management Platform
"""
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
from app.middleware.security import SecurityHeadersMiddleware, RequestIDMiddleware
from app.api.v1.endpoints import auth, secrets, audit

limiter = Limiter(key_func=get_remote_address, default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.db.session import create_engine_from_settings, engine, Base
    if engine is None:
        _engine = create_engine_from_settings(settings.DATABASE_URL, settings.DEBUG)
    else:
        _engine = engine
    async with _engine.begin() as conn:
        await conn.run_sync(lambda c: Base.metadata.create_all(c, checkfirst=True))
    yield
    await _engine.dispose()


# Disable built-in docs so we can serve them ourselves from local static assets
app = FastAPI(
    title="NanoVault",
    description="Production-inspired secrets management. AES-256-GCM · JWT · RBAC · Audit.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,    # we serve manually below
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

prefix = settings.API_V1_PREFIX
app.include_router(auth.router, prefix=prefix)
app.include_router(secrets.router, prefix=prefix)
app.include_router(audit.router, prefix=prefix)


# ── Docs served from FastAPI's bundled static assets (no CDN needed) ─────────
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
    return HTMLResponse("""
<!DOCTYPE html><html><head><title>NanoVault</title>
<style>body{font-family:monospace;background:#0d1117;color:#58a6ff;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0;flex-direction:column;}
a{color:#3fb950;margin:8px;}h1{font-size:2rem;}</style></head>
<body>
<h1>🔐 NanoVault</h1>
<p>Production-inspired secrets management</p>
<div><a href="/docs">Swagger UI</a> · <a href="/redoc">ReDoc</a> · <a href="/health">Health</a></div>
</body></html>
""")


@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "healthy", "service": "NanoVault", "version": "1.0.0"}


@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal error occurred"},
    )
