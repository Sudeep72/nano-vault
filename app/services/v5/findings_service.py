"""AI Security Findings — NanoVault v5.0 extended for v6"""
from __future__ import annotations
import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException
from app.models.models import AIFinding, AIFindingSeverity, AIFindingConfidence, AIFindingStatus


def _finding_to_dict(f: AIFinding) -> dict:
    return {
        "id": str(f.id), "category": f.category, "severity": f.severity.value,
        "confidence": f.confidence.value, "status": f.status.value,
        "summary": f.summary, "evidence": f.evidence, "explanation": f.explanation,
        "recommended_actions": f.recommended_actions, "related_entities": f.related_entities or [],
        "ai_provider": f.ai_provider, "ai_model": f.ai_model, "latency_ms": f.latency_ms,
        "risk_score": f.risk_score, "risk_level": f.risk_level,
        "triggered_rules": f.triggered_rules or [], "correlated_event_ids": f.correlated_event_ids or [],
        "created_by": str(f.created_by) if f.created_by else None,
        "created_at": f.created_at.isoformat(), "updated_at": f.updated_at.isoformat(),
    }

AIFinding.to_dict = _finding_to_dict


class FindingsService:

    @staticmethod
    async def create_finding(
        db: AsyncSession, current_user, *, category: str, severity: str, summary: str,
        evidence: list[str], explanation: list[str], confidence: str,
        recommended_actions: list[str], related_entities: list[str],
        provider: Optional[str] = None, model: Optional[str] = None, latency_ms: Optional[float] = None,
        risk_score: Optional[int] = None, risk_level: Optional[str] = None,
        triggered_rules: Optional[list[str]] = None, correlated_event_ids: Optional[list[str]] = None,
    ) -> AIFinding:
        finding = AIFinding(
            category=category, severity=AIFindingSeverity(severity), confidence=AIFindingConfidence(confidence),
            summary=summary, evidence=evidence, explanation=explanation,
            recommended_actions=recommended_actions, related_entities=related_entities,
            ai_provider=provider, ai_model=model, latency_ms=latency_ms, created_by=current_user.id,
            risk_score=risk_score, risk_level=risk_level,
            triggered_rules=triggered_rules or [], correlated_event_ids=correlated_event_ids or [],
        )
        db.add(finding)
        await db.flush()
        return finding

    @staticmethod
    async def get(db: AsyncSession, finding_id: uuid.UUID) -> AIFinding:
        f = (await db.execute(select(AIFinding).where(AIFinding.id == finding_id))).scalar_one_or_none()
        if not f:
            raise HTTPException(status_code=404, detail="Finding not found")
        return f

    @staticmethod
    async def list_findings(
        db: AsyncSession, category: Optional[str] = None, severity: Optional[str] = None,
        status: Optional[str] = None, limit: int = 50,
        risk_level: Optional[str] = None, min_risk_score: Optional[int] = None,
        has_correlated_events: Optional[bool] = None,
    ) -> list[dict]:
        q = select(AIFinding).order_by(AIFinding.created_at.desc()).limit(limit)
        if category:
            q = q.where(AIFinding.category == category)
        if severity:
            q = q.where(AIFinding.severity == AIFindingSeverity(severity))
        if status:
            q = q.where(AIFinding.status == AIFindingStatus(status))
        if risk_level:
            q = q.where(AIFinding.risk_level == risk_level)
        if min_risk_score is not None:
            q = q.where(AIFinding.risk_score >= min_risk_score)
        findings = (await db.execute(q)).scalars().all()
        if has_correlated_events is True:
            findings = [f for f in findings if f.correlated_event_ids]
        elif has_correlated_events is False:
            findings = [f for f in findings if not f.correlated_event_ids]
        return [_finding_to_dict(f) for f in findings]

    @staticmethod
    async def update_status(db: AsyncSession, finding_id: uuid.UUID, status: str) -> AIFinding:
        f = await FindingsService.get(db, finding_id)
        f.status = AIFindingStatus(status)
        await db.flush()
        return f

    @staticmethod
    async def attach_ai_explanation(
        db: AsyncSession, finding_id: uuid.UUID, *,
        explanation: list[str], additional_recommended_actions: list[str],
        provider: str, model: str, latency_ms: float,
    ) -> AIFinding:
        """Updates AI explanation on an existing finding. Never touches deterministic fields."""
        f = await FindingsService.get(db, finding_id)
        f.explanation = explanation
        f.recommended_actions = list(f.recommended_actions or []) + additional_recommended_actions
        f.ai_provider = provider
        f.ai_model = model
        f.latency_ms = latency_ms
        await db.flush()
        return f


findings_service = FindingsService()
