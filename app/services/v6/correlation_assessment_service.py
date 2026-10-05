"""Correlation Assessment Orchestration — v6 Phase 2"""
from __future__ import annotations
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.v6.correlation_service import correlation_engine
from app.services.v5.findings_service import findings_service
from app.services.audit_service import audit_service
from app.models.models import AuditAction

def _sev(score): return "critical" if score>=70 else ("high" if score>=40 else ("medium" if score>=15 else "info"))
def _conf(n): return "insufficient_evidence" if n==0 else ("high" if n>=2 else "medium")

class CorrelationAssessmentService:
    @staticmethod
    async def correlate_and_record_user(db, current_user, target_user_id: uuid.UUID, window_hours: int = 24) -> dict:
        r = await correlation_engine.correlate_user(db, target_user_id, window_hours)
        f = await findings_service.create_finding(db, current_user, category="correlation", severity=_sev(r["correlation_score"]), confidence=_conf(r["chains_found"]), summary=f"Correlation analysis for {target_user_id}: {r['chains_found']} chain(s) over {r['events_analyzed']} events", evidence=[m["description"] for m in r["matches"]], explanation=[], recommended_actions=["Review correlated event chain"] if r["chains_found"] else ["No chains detected"], related_entities=[str(target_user_id)], risk_score=r["correlation_score"], risk_level=_sev(r["correlation_score"]), triggered_rules=r["triggered_chain_ids"], correlated_event_ids=r["correlated_event_ids"])
        await audit_service.log(db, AuditAction.AI_FINDING_CREATE, user_id=current_user.id, resource_type="ai_finding", resource_id=str(f.id), metadata={"category":"correlation","chains_found":r["chains_found"],"target_user_id":str(target_user_id)})
        await db.commit()
        return {"correlation": r, "finding_id": str(f.id)}

    @staticmethod
    async def correlate_and_record_platform(db, current_user, window_hours: int = 24) -> dict:
        r = await correlation_engine.correlate_recent_activity(db, window_hours)
        f = await findings_service.create_finding(db, current_user, category="correlation", severity=_sev(r["correlation_score"]), confidence=_conf(r["chains_found"]), summary=f"Platform correlation: {r['chains_found']} chain(s) over {r['events_analyzed']} events", evidence=[m["description"] for m in r["matches"]], explanation=[], recommended_actions=["Review correlated chains"] if r["chains_found"] else ["No chains detected"], related_entities=[], risk_score=r["correlation_score"], risk_level=_sev(r["correlation_score"]), triggered_rules=r["triggered_chain_ids"], correlated_event_ids=r["correlated_event_ids"])
        await audit_service.log(db, AuditAction.AI_FINDING_CREATE, user_id=current_user.id, resource_type="ai_finding", resource_id=str(f.id), metadata={"category":"correlation","chains_found":r["chains_found"],"scope":"platform"})
        await db.commit()
        return {"correlation": r, "finding_id": str(f.id)}

correlation_assessment_service = CorrelationAssessmentService()
