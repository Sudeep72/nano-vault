"""
AI Observability — NanoVault v5.0 (Step 16)

Registers AI metrics on the SAME prometheus_client registry the rest of
NanoVault already uses (app.services.v3.prometheus_service.registry) —
one /api/v3/metrics scrape target covers the whole platform, AI included.
No sensitive prompt content is ever put in a metric label.
"""
from __future__ import annotations
from typing import Optional
from prometheus_client import Counter, Histogram, Gauge
from app.services.v3.prometheus_service import registry

ai_requests_total = Counter(
    "nanovault_ai_requests_total", "AI provider requests", ["task", "outcome"], registry=registry
)
ai_request_latency_ms = Histogram(
    "nanovault_ai_request_latency_ms", "AI request latency", ["task"], registry=registry
)
ai_tokens_total = Counter(
    "nanovault_ai_tokens_total", "AI token usage", ["direction"], registry=registry
)
ai_findings_total = Gauge(
    "nanovault_ai_findings_total", "Total AI findings created", registry=registry
)
ai_enabled_gauge = Gauge(
    "nanovault_ai_enabled", "1 if AI is enabled and configured, else 0", registry=registry
)


class AIMetricsService:

    @staticmethod
    def record_request(task: str, outcome: str, latency_ms: float,
                       input_tokens: Optional[int] = None, output_tokens: Optional[int] = None) -> None:
        ai_requests_total.labels(task=task, outcome=outcome).inc()
        if latency_ms:
            ai_request_latency_ms.labels(task=task).observe(latency_ms)
        if input_tokens:
            ai_tokens_total.labels(direction="input").inc(input_tokens)
        if output_tokens:
            ai_tokens_total.labels(direction="output").inc(output_tokens)

    @staticmethod
    async def sync_gauges(db) -> None:
        from app.services.v5.ai_provider_service import validate_ai_config
        from sqlalchemy import select, func
        from app.models.models import AIFinding

        config = validate_ai_config()
        ai_enabled_gauge.set(1 if config.get("configured") else 0)

        count = (await db.execute(select(func.count()).select_from(AIFinding))).scalar_one()
        ai_findings_total.set(count)


ai_metrics_service = AIMetricsService()
