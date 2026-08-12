"""
AI Security Analyst — NanoVault v5.0 (Step 5)

Answers "what happened / why is this suspicious / what should I investigate"
questions about a specific event by gathering real context via
security_context_service and routing through ai_security_engine.
"""
from __future__ import annotations
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException
from app.services.v5.security_context_service import security_context_service
from app.services.v5.ai_security_engine import ai_security_engine


class SecurityAnalystService:

    @staticmethod
    async def explain_event(db: AsyncSession, current_user, audit_log_id: uuid.UUID, question: str = None) -> dict:
        """Step 7 (threat/anomaly explanation) + Step 5 (analyst Q&A) — same
        underlying flow, since explaining an event IS answering the analyst's
        default question about it."""
        context = await security_context_service.build_context_for_event(db, current_user, audit_log_id)
        if "error" in context:
            raise HTTPException(status_code=403 if "authorized" in context["error"] else 404, detail=context["error"])

        default_question = question or (
            "Summarize this event, explain whether it appears suspicious or normal based on the "
            "surrounding timeline, and recommend next investigation steps if warranted."
        )
        result = await ai_security_engine.run_analysis(
            db, current_user, task="explain_event",
            context_items=[context], user_query=default_question, category="event_explanation",
        )
        return result.to_dict()

    @staticmethod
    async def investigate(db: AsyncSession, current_user, audit_log_id: uuid.UUID, investigator_question: str) -> dict:
        """Step 8 — investigation workspace Q&A against a specific event's context."""
        context = await security_context_service.build_context_for_event(db, current_user, audit_log_id)
        if "error" in context:
            raise HTTPException(status_code=403 if "authorized" in context["error"] else 404, detail=context["error"])

        result = await ai_security_engine.run_analysis(
            db, current_user, task="investigate",
            context_items=[context], user_query=investigator_question, category="investigation",
        )
        return result.to_dict()


security_analyst_service = SecurityAnalystService()
