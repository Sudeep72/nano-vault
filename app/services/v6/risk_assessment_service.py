"""Risk Assessment Orchestration — v6 Phase 1"""
from __future__ import annotations
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.v6.risk_engine import risk_engine, _score_to_level
from app.services.v5.findings_service import findings_service
from app.services.audit_service import audit_service
from app.models.models import AuditAction

def _conf(n): return "insufficient_evidence" if n==0 else ("high" if n>=2 else "medium")
def _recs(level):
    return {"low":["Continue routine monitoring"],"medium":["Review triggered rules","Confirm activity matches expected behavior"],"high":["Investigate promptly","Consider re-authentication or MFA"],"critical":["Investigate immediately","Consider restricting credentials","Escalate to security admin"]}.get(level,["Review findings"])

class RiskAssessmentService:
    @staticmethod
    async def assess_and_record_user(db, current_user, target_user_id: uuid.UUID, window_hours: int = 24) -> dict:
        a = await risk_engine.assess_user(db, target_user_id, window_hours)
        f = await findings_service.create_finding(db, current_user, category="risk_assessment", severity=a["risk_level"] if a["risk_level"] != "low" else "low", confidence=_conf(len(a["triggered_rules"])), summary=f"Risk assessment for {target_user_id}: {a['risk_score']}/100 ({a['risk_level']}) over {a['events_analyzed']} events", evidence=a["evidence"], explanation=[], recommended_actions=_recs(a["risk_level"]), related_entities=a["affected_entities"], risk_score=a["risk_score"], risk_level=a["risk_level"], triggered_rules=a["triggered_rules"])
        await audit_service.log(db, AuditAction.AI_FINDING_CREATE, user_id=current_user.id, resource_type="ai_finding", resource_id=str(f.id), metadata={"category":"risk_assessment","risk_score":a["risk_score"],"target_user_id":str(target_user_id)})
        await db.commit()
        return {"assessment": a, "finding_id": str(f.id)}

    @staticmethod
    async def assess_and_record_platform(db, current_user, window_hours: int = 24) -> dict:
        a = await risk_engine.assess_recent_activity(db, window_hours)
        f = await findings_service.create_finding(db, current_user, category="risk_assessment", severity=a["risk_level"] if a["risk_level"] != "low" else "low", confidence=_conf(len(a["triggered_rules"])), summary=f"Platform risk assessment: {a['risk_score']}/100 ({a['risk_level']}) over {a['events_analyzed']} events", evidence=a["evidence"], explanation=[], recommended_actions=_recs(a["risk_level"]), related_entities=a["affected_entities"], risk_score=a["risk_score"], risk_level=a["risk_level"], triggered_rules=a["triggered_rules"])
        await audit_service.log(db, AuditAction.AI_FINDING_CREATE, user_id=current_user.id, resource_type="ai_finding", resource_id=str(f.id), metadata={"category":"risk_assessment","scope":"platform"})
        await db.commit()
        return {"assessment": a, "finding_id": str(f.id)}

risk_assessment_service = RiskAssessmentService()
