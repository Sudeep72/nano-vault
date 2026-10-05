"""Structured JSON logging with correlation IDs — NanoVault v3.0 Completion."""
from __future__ import annotations
import json
import logging
import time
import uuid
from contextvars import ContextVar
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="-")
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": correlation_id_var.get(),
            "request_id": request_id_var.get(),
        }
        for attr in ("user_id", "namespace", "engine", "duration_ms", "status_code", "method", "path"):
            if hasattr(record, attr):
                payload[attr] = getattr(record, attr)
        return json.dumps(payload)


class CorrelationMiddleware(BaseHTTPMiddleware):
    """Injects request_id + correlation_id into every request and logs structured JSON."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        request_id_var.set(request_id)
        correlation_id_var.set(correlation_id)
        request.state.request_id = request_id
        request.state.correlation_id = correlation_id

        t0 = time.monotonic()
        response = await call_next(request)
        duration_ms = round((time.monotonic() - t0) * 1000, 2)

        logger = logging.getLogger("nano_vault.http")
        user_id = getattr(request.state, "user_id", None)
        namespace = request.headers.get("X-Vault-Namespace", "root")
        engine = request.url.path.split("/")[3] if len(request.url.path.split("/")) > 3 else "-"

        logger.info(
            "%s %s -> %s (%sms)", request.method, request.url.path, response.status_code, duration_ms,
            extra={
                "user_id": user_id, "namespace": namespace, "engine": engine,
                "duration_ms": duration_ms, "status_code": response.status_code,
                "method": request.method, "path": request.url.path,
            },
        )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Correlation-ID"] = correlation_id
        return response


def configure_json_logging():
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
