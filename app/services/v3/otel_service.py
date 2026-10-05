"""
OpenTelemetry integration — NanoVault v3.0 Final Completion.
Real distributed tracing with OTLP export. Supports Jaeger and Tempo backends.
Falls back to a no-op tracer if OTel packages or collector are unavailable.
"""
from __future__ import annotations
import os
import functools
import logging

logger = logging.getLogger("nano_vault.otel")

_tracer = None
_enabled = False


def init_tracing(service_name: str = "nanovault", otlp_endpoint: str = None):
    """Initialize OpenTelemetry tracing. Safe no-op if packages/collector unavailable."""
    global _tracer, _enabled
    otlp_endpoint = otlp_endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    if not otlp_endpoint:
        logger.info("OTEL_EXPORTER_OTLP_ENDPOINT not set — tracing disabled")
        return None

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        resource = Resource(attributes={"service.name": service_name})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(service_name)
        _enabled = True
        logger.info("OpenTelemetry tracing initialized -> %s", otlp_endpoint)
        return _tracer
    except Exception as e:
        logger.warning("OpenTelemetry init failed, tracing disabled: %s", e)
        return None


def instrument_fastapi(app):
    """Auto-instrument all FastAPI routes with OTel spans."""
    if not _enabled:
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app)
        logger.info("FastAPI instrumented for tracing")
    except Exception as e:
        logger.warning("FastAPI instrumentation failed: %s", e)


def instrument_sqlalchemy(engine):
    """Auto-instrument SQLAlchemy engine for DB span tracing."""
    if not _enabled:
        return
    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        SQLAlchemyInstrumentor().instrument(engine=engine.sync_engine)
        logger.info("SQLAlchemy instrumented for tracing")
    except Exception as e:
        logger.warning("SQLAlchemy instrumentation not available: %s", e)


def traced_span(name: str):
    """Decorator: wrap a function (scheduler jobs, CLI commands, storage ops) in a span."""
    def decorator(fn):
        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            if not _enabled or _tracer is None:
                return await fn(*args, **kwargs)
            with _tracer.start_as_current_span(name):
                return await fn(*args, **kwargs)

        @functools.wraps(fn)
        def sync_wrapper(*args, **kwargs):
            if not _enabled or _tracer is None:
                return fn(*args, **kwargs)
            with _tracer.start_as_current_span(name):
                return fn(*args, **kwargs)

        import asyncio
        return async_wrapper if asyncio.iscoroutinefunction(fn) else sync_wrapper
    return decorator


def get_trace_context() -> dict:
    """Return current trace/span IDs for correlation with logs."""
    if not _enabled:
        return {"trace_id": None, "span_id": None, "enabled": False}
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        ctx = span.get_span_context()
        return {"trace_id": format(ctx.trace_id, "032x"), "span_id": format(ctx.span_id, "016x"), "enabled": True}
    except Exception:
        return {"trace_id": None, "span_id": None, "enabled": True}


def status() -> dict:
    return {
        "enabled": _enabled,
        "backend": "otlp",
        "supported_collectors": ["jaeger", "tempo"],
        "endpoint": os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", None),
    }
