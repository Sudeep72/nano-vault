"""AI Security Analyst for v6 deterministic findings — Phase 3"""
from __future__ import annotations
import time, uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException
from app.services.v5.ai_provider_service import get_provider, AIRequest, AIProviderError, AIProviderUnavailableError, AIProviderTimeoutError, AIProviderAuthError, AIProviderRateLimitError, AIProviderMalformedResponseError
from app.services.v5.guardrails_service import SYSTEM_INSTRUCTION_PREFIX, build_full_context, sanitize_user_query
from app.services.v5.ai_security_engine import AISecurityEngine, FINDING_SCHEMA
from app.services.v5.findings_service import findings_service, _finding_to_dict
from app.services.v5.ai_metrics_service import ai_metrics_service
from app.services.audit_service import audit_service
from app.models.models import AuditAction, UserRole


class SecurityAnalystV6Result:
    def __init__(self, success, finding=None, error=None, error_type=None, latency_ms=0.0):
        self.success=success; self.finding=finding; self.error=error; self.error_type=error_type; self.latency_ms=latency_ms
    def to_dict(self): return {"success":self.success,"finding":self.finding,"error":self.error,"error_type":self.error_type,"latency_ms":self.latency_ms}


class SecurityAnalystV6Service:
    @staticmethod
    async def explain_finding(db: AsyncSession, current_user, finding_id: uuid.UUID, question: Optional[str] = None):
        finding = await findings_service.get(db, finding_id)
        if finding.category not in ("risk_assessment", "correlation"):
            raise HTTPException(400, f"Finding category '{finding.category}' is not a v6 deterministic finding")
        if current_user.role != UserRole.ADMIN and finding.created_by != current_user.id:
            raise HTTPException(403, "Not authorized to request AI explanation for this finding")

        provider = get_provider()
        if provider is None:
            ai_metrics_service.record_request("explain_v6_finding", "unavailable", 0)
            return SecurityAnalystV6Result(False, error="AI is disabled or misconfigured", error_type="unavailable")
        ok_conf, msg = provider.is_configured()
        if not ok_conf:
            ai_metrics_service.record_request("explain_v6_finding", "unavailable", 0)
            return SecurityAnalystV6Result(False, error=msg, error_type="unavailable")

        ctx = [{"finding_category":finding.category,"deterministic_risk_score":finding.risk_score,"deterministic_risk_level":finding.risk_level,"triggered_rules":finding.triggered_rules,"observed_evidence":finding.evidence}]
        if finding.category == "correlation" and finding.correlated_event_ids:
            from app.services.v5.security_context_service import security_context_service
            ctx.append({"correlated_events_detail": await security_context_service.gather_events_by_ids(db, finding.correlated_event_ids, current_user)})

        from app.core.config import settings
        q = sanitize_user_query(question) if question else f"Explain why this {finding.category} finding was flagged. Summarize the evidence, assess whether it looks like a genuine security concern or likely false positive, and recommend concrete next steps."
        t0 = time.perf_counter()
        try:
            resp = await provider.generate(AIRequest(task="explain_v6_finding", system_instruction=SYSTEM_INSTRUCTION_PREFIX, untrusted_context=build_full_context(ctx), user_query=q, response_schema=FINDING_SCHEMA, max_output_tokens=settings.AI_MAX_OUTPUT_TOKENS, temperature=settings.AI_TEMPERATURE))
        except (AIProviderTimeoutError, AIProviderAuthError, AIProviderRateLimitError, AIProviderMalformedResponseError, AIProviderUnavailableError, AIProviderError) as e:
            etype = type(e).__name__.replace("AIProvider","").replace("Error","").lower() or "error"
            ms = round((time.perf_counter()-t0)*1000,2)
            ai_metrics_service.record_request("explain_v6_finding", etype, ms)
            await audit_service.log(db, AuditAction.AI_ANALYSIS_RUN, user_id=current_user.id, resource_type="ai_finding_explanation", resource_id=str(finding_id), success=False, metadata={"task":"explain_v6_finding","outcome":etype})
            await db.commit()
            return SecurityAnalystV6Result(False, error=str(e), error_type=etype, latency_ms=ms)

        ms = round((time.perf_counter()-t0)*1000,2)
        validated = AISecurityEngine._validate_finding_shape(resp.parsed)
        if not validated:
            ai_metrics_service.record_request("explain_v6_finding","malformed_response",ms)
            await audit_service.log(db, AuditAction.AI_ANALYSIS_RUN, user_id=current_user.id, resource_type="ai_finding_explanation", resource_id=str(finding_id), success=False, metadata={"task":"explain_v6_finding","outcome":"malformed_response"})
            await db.commit()
            return SecurityAnalystV6Result(False, error="Model response did not match required schema", error_type="malformed_response", latency_ms=ms)

        updated = await findings_service.attach_ai_explanation(db, finding_id, explanation=validated["ai_inference"]+[f"Summary: {validated['summary']}"], additional_recommended_actions=validated["recommended_actions"], provider=resp.provider, model=resp.model, latency_ms=ms)
        ai_metrics_service.record_request("explain_v6_finding","success",ms,input_tokens=resp.input_tokens,output_tokens=resp.output_tokens)
        await audit_service.log(db, AuditAction.AI_ANALYSIS_RUN, user_id=current_user.id, resource_type="ai_finding_explanation", resource_id=str(finding_id), success=True, metadata={"task":"explain_v6_finding","outcome":"success"})
        await db.commit()
        return SecurityAnalystV6Result(True, finding=_finding_to_dict(updated), latency_ms=ms)

security_analyst_v6_service = SecurityAnalystV6Service()
