"""
AI Security Engine — NanoVault v5.0

Orchestrates: context → guardrails → provider request → validate → finding → audit.

This is the ONLY module that calls app.services.v5.ai_provider_service.get_provider().
Every other v5 service (analyst, search) goes through this engine rather
than talking to the provider directly, so the audit/validation/error
handling logic exists in exactly one place.
"""
from __future__ import annotations
import time
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.v5.ai_provider_service import (
    get_provider, AIRequest, AIProviderError, AIProviderUnavailableError,
    AIProviderTimeoutError, AIProviderAuthError, AIProviderRateLimitError,
    AIProviderMalformedResponseError,
)
from app.services.v5.guardrails_service import (
    SYSTEM_INSTRUCTION_PREFIX, build_full_context, sanitize_user_query,
)

_now = lambda: datetime.now(timezone.utc)

FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "observed_evidence": {"type": "array", "items": {"type": "string"}},
        "ai_inference": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "string", "enum": ["low", "medium", "high", "insufficient_evidence"]},
        "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
        "related_entities": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "observed_evidence", "ai_inference", "confidence", "severity", "recommended_actions"],
}


class AIEngineResult:
    def __init__(self, success: bool, finding: Optional[dict] = None, error: Optional[str] = None,
                 error_type: Optional[str] = None, latency_ms: float = 0.0):
        self.success = success
        self.finding = finding
        self.error = error
        self.error_type = error_type
        self.latency_ms = latency_ms

    def to_dict(self) -> dict:
        return {"success": self.success, "finding": self.finding, "error": self.error,
                "error_type": self.error_type, "latency_ms": self.latency_ms}


class AISecurityEngine:

    @staticmethod
    async def run_analysis(
        db: AsyncSession, current_user, task: str,
        context_items: list[dict], user_query: Optional[str] = None,
        category: str = "general",
    ) -> AIEngineResult:
        """
        The single orchestration path every v5 capability funnels through.
        1. Input/context   — context_items, already gathered by security_context_service
        2. Guardrails       — redact + delimit
        3. Model request    — via provider abstraction
        4. Validation       — schema check (provider layer) + sanity check here
        5. Structured finding
        6. Audit record
        """
        from app.services.v5.ai_metrics_service import ai_metrics_service
        from app.services.v5.findings_service import findings_service
        from app.services.audit_service import audit_service
        from app.models.models import AuditAction

        provider = get_provider()
        if provider is None:
            ai_metrics_service.record_request(task, "unavailable", 0)
            return AIEngineResult(False, error="AI is disabled or misconfigured (AI_ENABLED=false or provider not configured)",
                                  error_type="unavailable")

        ok, msg = provider.is_configured()
        if not ok:
            ai_metrics_service.record_request(task, "unavailable", 0)
            return AIEngineResult(False, error=msg, error_type="unavailable")

        from app.core.config import settings
        sanitized_context = build_full_context(context_items[:settings.AI_MAX_CONTEXT_ITEMS])
        sanitized_query = sanitize_user_query(user_query) if user_query else None

        request = AIRequest(
            task=task,
            system_instruction=SYSTEM_INSTRUCTION_PREFIX,
            untrusted_context=sanitized_context,
            user_query=sanitized_query,
            response_schema=FINDING_SCHEMA,
            max_output_tokens=settings.AI_MAX_OUTPUT_TOKENS,
            temperature=settings.AI_TEMPERATURE,
        )

        t0 = time.perf_counter()
        try:
            response = await provider.generate(request)
        except AIProviderTimeoutError as e:
            ai_metrics_service.record_request(task, "timeout", (time.perf_counter() - t0) * 1000)
            await AISecurityEngine._audit(db, current_user, task, "timeout", None, audit_service, AuditAction)
            return AIEngineResult(False, error=str(e), error_type="timeout")
        except AIProviderAuthError as e:
            ai_metrics_service.record_request(task, "auth_error", (time.perf_counter() - t0) * 1000)
            await AISecurityEngine._audit(db, current_user, task, "auth_error", None, audit_service, AuditAction)
            return AIEngineResult(False, error=str(e), error_type="auth_error")
        except AIProviderRateLimitError as e:
            ai_metrics_service.record_request(task, "rate_limited", (time.perf_counter() - t0) * 1000)
            await AISecurityEngine._audit(db, current_user, task, "rate_limited", None, audit_service, AuditAction)
            return AIEngineResult(False, error=str(e), error_type="rate_limited")
        except AIProviderMalformedResponseError as e:
            ai_metrics_service.record_request(task, "malformed_response", (time.perf_counter() - t0) * 1000)
            await AISecurityEngine._audit(db, current_user, task, "malformed_response", None, audit_service, AuditAction)
            return AIEngineResult(False, error=str(e), error_type="malformed_response")
        except AIProviderUnavailableError as e:
            ai_metrics_service.record_request(task, "unavailable", (time.perf_counter() - t0) * 1000)
            await AISecurityEngine._audit(db, current_user, task, "unavailable", None, audit_service, AuditAction)
            return AIEngineResult(False, error=str(e), error_type="unavailable")
        except AIProviderError as e:
            ai_metrics_service.record_request(task, "error", (time.perf_counter() - t0) * 1000)
            await AISecurityEngine._audit(db, current_user, task, "error", None, audit_service, AuditAction)
            return AIEngineResult(False, error=str(e), error_type="error")

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        validated = AISecurityEngine._validate_finding_shape(response.parsed)
        if not validated:
            ai_metrics_service.record_request(task, "malformed_response", latency_ms)
            await AISecurityEngine._audit(db, current_user, task, "malformed_response", None, audit_service, AuditAction)
            return AIEngineResult(False, error="Model response did not match the required finding schema after parsing",
                                  error_type="malformed_response", latency_ms=latency_ms)

        finding = await findings_service.create_finding(
            db, current_user, category=category, severity=validated["severity"],
            summary=validated["summary"], evidence=validated["observed_evidence"],
            explanation=validated["ai_inference"], confidence=validated["confidence"],
            recommended_actions=validated["recommended_actions"],
            related_entities=validated.get("related_entities", []),
            provider=response.provider, model=response.model, latency_ms=latency_ms,
        )

        ai_metrics_service.record_request(task, "success", latency_ms,
                                          input_tokens=response.input_tokens, output_tokens=response.output_tokens)
        await AISecurityEngine._audit(db, current_user, task, "success", str(finding.id), audit_service, AuditAction)

        return AIEngineResult(True, finding=finding.to_dict(), latency_ms=latency_ms)

    @staticmethod
    def _validate_finding_shape(parsed: Optional[dict]) -> Optional[dict]:
        """
        Belt-and-suspenders check beyond the provider-level JSON schema
        validation — confirms every required field is present and
        confidence/severity are within the allowed enum before this data
        is allowed anywhere near the findings table.
        """
        if not parsed or not isinstance(parsed, dict):
            return None
        required = ["summary", "observed_evidence", "ai_inference", "confidence", "severity", "recommended_actions"]
        if not all(k in parsed for k in required):
            return None
        if parsed["confidence"] not in ("low", "medium", "high", "insufficient_evidence"):
            return None
        if parsed["severity"] not in ("info", "low", "medium", "high", "critical"):
            return None
        return parsed

    @staticmethod
    async def _audit(db, current_user, task, outcome, finding_id, audit_service, AuditAction):
        """
        Records the AI operation without ever storing the prompt or
        response content — only what the spec's Step 12 asks for:
        who, when, what operation, what outcome, which finding.
        """
        await audit_service.log(
            db, AuditAction.AI_ANALYSIS_RUN,
            user_id=current_user.id, resource_type="ai_analysis", resource_id=finding_id,
            success=(outcome == "success"),
            metadata={"task": task, "outcome": outcome, "provider": "gemini"},
        )
        await db.commit()


ai_security_engine = AISecurityEngine()
