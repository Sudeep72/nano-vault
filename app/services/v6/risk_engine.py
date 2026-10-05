"""Deterministic Security Risk Engine — NanoVault v6.0, Phase 1. No AI calls."""
from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.models import AuditLog, AuditAction

_now = lambda: datetime.now(timezone.utc)


@dataclass
class RuleResult:
    rule_id: str; triggered: bool; points: int
    evidence: list[str] = field(default_factory=list)
    affected_entities: list[str] = field(default_factory=list)

@dataclass
class RiskRule:
    rule_id: str; description: str
    evaluate: Callable[[list[AuditLog]], RuleResult]


def _rule_repeated_auth_failures(logs):
    failures = [l for l in logs if l.action == AuditAction.USER_LOGIN_FAILED]
    if len(failures) >= 5: return RuleResult("repeated_auth_failures", True, 30, [f"{len(failures)} failed logins"])
    if len(failures) >= 3: return RuleResult("repeated_auth_failures", True, 15, [f"{len(failures)} failed logins"])
    return RuleResult("repeated_auth_failures", False, 0)

def _rule_ip_churn(logs):
    ips = {l.ip_address for l in logs if l.ip_address}
    if len(ips) >= 3: return RuleResult("ip_address_churn", True, 20, [f"{len(ips)} distinct IPs"], list(ips)[:5])
    if len(ips) == 2: return RuleResult("ip_address_churn", True, 10, [f"2 distinct IPs: {sorted(ips)}"], list(ips))
    return RuleResult("ip_address_churn", False, 0)

def _rule_failed_then_success(logs):
    ordered = sorted(logs, key=lambda l: l.created_at)
    fail_streak = 0
    for l in ordered:
        if l.action == AuditAction.USER_LOGIN_FAILED: fail_streak += 1
        elif l.action == AuditAction.USER_LOGIN:
            if fail_streak >= 3: return RuleResult("failed_then_success_login", True, 35, [f"{fail_streak} failures then success"], [str(l.user_id)] if l.user_id else [])
            fail_streak = 0
    return RuleResult("failed_then_success_login", False, 0)

def _rule_high_volume_reads(logs):
    reads = [l for l in logs if l.action == AuditAction.SECRET_READ]
    if len(reads) >= 20: return RuleResult("high_volume_secret_reads", True, 25, [f"{len(reads)} secret reads"])
    if len(reads) >= 10: return RuleResult("high_volume_secret_reads", True, 10, [f"{len(reads)} secret reads"])
    return RuleResult("high_volume_secret_reads", False, 0)

def _rule_priv_ops(logs):
    sensitive = {AuditAction.VAULT_TOKEN_CREATE, AuditAction.POLICY_CREATE, AuditAction.POLICY_DELETE, AuditAction.ORG_CREATE}
    hits = [l for l in logs if l.action in sensitive]
    if len(hits) >= 3: return RuleResult("privilege_sensitive_operations", True, 20, [f"{len(hits)} priv ops: {sorted({h.action.value for h in hits})}"])
    return RuleResult("privilege_sensitive_operations", False, 0)

def _rule_unusual_timing(logs):
    off = [l for l in logs if 0 <= l.created_at.hour < 5]
    if len(off) >= 5: return RuleResult("unusual_activity_timing", True, 10, [f"{len(off)} events 00:00-05:00 UTC"])
    return RuleResult("unusual_activity_timing", False, 0)

def _score_to_level(score):
    if score >= 70: return "critical"
    if score >= 45: return "high"
    if score >= 20: return "medium"
    return "low"

REGISTRY = [
    RiskRule("repeated_auth_failures", "Repeated authentication failures", _rule_repeated_auth_failures),
    RiskRule("ip_address_churn", "Multiple distinct IP addresses", _rule_ip_churn),
    RiskRule("failed_then_success_login", "Failed logins then success", _rule_failed_then_success),
    RiskRule("high_volume_secret_reads", "Abnormally high secret reads", _rule_high_volume_reads),
    RiskRule("privilege_sensitive_operations", "Privilege-sensitive operations", _rule_priv_ops),
    RiskRule("unusual_activity_timing", "Activity during unusual hours", _rule_unusual_timing),
]


class RiskEngine:
    @staticmethod
    async def assess_user(db: AsyncSession, target_user_id: uuid.UUID, window_hours: int = 24) -> dict:
        from app.models.models import User
        since = _now() - timedelta(hours=window_hours)
        target_user = (await db.execute(select(User).where(User.id == target_user_id))).scalar_one_or_none()
        owned = (await db.execute(select(AuditLog).where(AuditLog.user_id == target_user_id, AuditLog.created_at >= since))).scalars().all()
        failed = []
        if target_user:
            cands = (await db.execute(select(AuditLog).where(AuditLog.action == AuditAction.USER_LOGIN_FAILED, AuditLog.created_at >= since))).scalars().all()
            failed = [l for l in cands if l.extra_data and l.extra_data.get("username") == target_user.username]
        logs = sorted(owned + failed, key=lambda l: l.created_at)
        return RiskEngine._run(logs, "user", str(target_user_id), window_hours)

    @staticmethod
    async def assess_recent_activity(db: AsyncSession, window_hours: int = 24, limit: int = 500) -> dict:
        since = _now() - timedelta(hours=window_hours)
        logs = (await db.execute(select(AuditLog).where(AuditLog.created_at >= since).order_by(AuditLog.created_at.asc()).limit(limit))).scalars().all()
        return RiskEngine._run(logs, "platform", None, window_hours)

    @staticmethod
    def _run(logs, entity_type, entity_id, window_hours):
        triggered, evidence, entities, pts = [], [], set(), 0
        for rule in REGISTRY:
            r = rule.evaluate(logs)
            if r.triggered:
                triggered.append(r.rule_id); evidence.extend(r.evidence); entities.update(r.affected_entities); pts += r.points
        score = min(pts, 100)
        return {"entity_type": entity_type, "entity_id": entity_id, "window_hours": window_hours, "events_analyzed": len(logs), "risk_score": score, "risk_level": _score_to_level(score), "triggered_rules": triggered, "evidence": evidence, "affected_entities": sorted(entities), "assessed_at": _now().isoformat()}

    @staticmethod
    def list_rules():
        return [{"rule_id": r.rule_id, "description": r.description} for r in REGISTRY]

risk_engine = RiskEngine()
