"""Security and logging middleware — NanoVault v1.0.1"""
import time
import uuid
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("nano_vault.access")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "worker-src blob:;"
    ),
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}

_REMOVE_HEADERS = ("server", "x-powered-by")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers[k] = v
        for h in _REMOVE_HEADERS:
            if h in response.headers:
                del response.headers[h]
        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    """Logs every request with: request_id, method, path, status, IP, UA, exec time."""

    async def dispatch(self, request: Request, call_next) -> Response:
        t0 = time.monotonic()
        request_id = getattr(request.state, "request_id", "-")

        fwd = request.headers.get("X-Forwarded-For")
        ip = fwd.split(",")[0].strip() if fwd else (
            request.client.host if request.client else "-"
        )

        response = await call_next(request)

        exec_ms = round((time.monotonic() - t0) * 1000, 2)
        logger.info(
            "%s %s %s",
            request.method,
            request.url.path,
            response.status_code,
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "ip": ip,
                "user_agent": request.headers.get("User-Agent", "-"),
                "exec_ms": exec_ms,
            },
        )
        response.headers["X-Response-Time-Ms"] = str(exec_ms)
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests exceeding MAX_REQUEST_SIZE_BYTES."""

    def __init__(self, app, max_bytes: int = 1_048_576):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_bytes:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=413,
                content={
                    "success": False,
                    "error": "Request too large",
                    "details": {"max_bytes": self.max_bytes},
                },
            )
        return await call_next(request)
