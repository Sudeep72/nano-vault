"""Event Correlation Engine — v6 Phase 2. No AI calls."""
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
class CorrelationMatch:
    chain_id: str; matched: bool; description: str = ""; event_ids: list[str] = field(default_factory=list); points: int = 0

@dataclass
class CorrelationRule:
    chain_id: str; description: str; evaluate: Callable[[list[AuditLog]], list[CorrelationMatch]]

def _seq(logs): return [(l.action, l) for l in sorted(logs, key=lambda x: x.created_at)]

def _rule_login_secret_lifecycle(logs):
    seq = _seq(logs); matches = []
    for i, (action, log) in enumerate(seq):
        if action != AuditAction.USER_LOGIN: continue
        wend = log.created_at + timedelta(minutes=30)
        following = [l for a, l in seq[i+1:] if l.created_at <= wend]
        if any(l.action == AuditAction.SECRET_READ for l in following) and any(l.action == AuditAction.SECRET_CREATE for l in following):
            evts = [log] + [l for l in following if l.action in (AuditAction.SECRET_READ, AuditAction.SECRET_CREATE)]
            matches.append(CorrelationMatch("login_then_secret_lifecycle", True, f"Login -> secret read -> creation within 30min ({len(evts)} events)", [str(e.id) for e in evts], 15))
    return matches

def _rule_failed_burst_sensitive(logs):
    seq = _seq(logs); sensitive = {AuditAction.VAULT_TOKEN_CREATE, AuditAction.POLICY_CREATE, AuditAction.POLICY_DELETE, AuditAction.ORG_CREATE, AuditAction.SECRET_DELETE}
    matches = []; fail_streak = []
    for action, log in seq:
        if action == AuditAction.USER_LOGIN_FAILED: fail_streak.append(log)
        elif action == AuditAction.USER_LOGIN:
            if len(fail_streak) >= 3:
                wend = log.created_at + timedelta(minutes=15)
                sens = [l for a, l in seq if l.created_at > log.created_at and l.created_at <= wend and a in sensitive]
                if sens:
                    matches.append(CorrelationMatch("failed_burst_success_sensitive_op", True, f"{len(fail_streak)} failures -> success -> {len(sens)} sensitive op(s) within 15min", [str(e.id) for e in fail_streak + [log] + sens], 40))
            fail_streak = []
    return matches

def _rule_new_ip_secret(logs):
    seq = _seq(logs); seen = set(); matches = []
    for action, log in seq:
        if action == AuditAction.USER_LOGIN and log.ip_address and log.ip_address not in seen:
            wend = log.created_at + timedelta(minutes=10)
            ops = [l for a, l in seq if l.created_at > log.created_at and l.created_at <= wend and a in (AuditAction.SECRET_READ, AuditAction.SECRET_CREATE, AuditAction.SECRET_UPDATE)]
            if ops: matches.append(CorrelationMatch("new_ip_auth_secret_access", True, f"New IP {log.ip_address} -> {len(ops)} secret op(s) within 10min", [str(e.id) for e in [log]+ops], 25))
        if log.ip_address: seen.add(log.ip_address)
    return matches

CORRELATION_REGISTRY = [
    CorrelationRule("login_then_secret_lifecycle", "Login -> secret read -> creation", _rule_login_secret_lifecycle),
    CorrelationRule("failed_burst_success_sensitive_op", "Failed burst -> success -> sensitive op", _rule_failed_burst_sensitive),
    CorrelationRule("new_ip_auth_secret_access", "New IP -> auth -> secret access", _rule_new_ip_secret),
]

class CorrelationEngine:
    @staticmethod
    async def correlate_user(db, target_user_id: uuid.UUID, window_hours: int = 24) -> dict:
        from app.models.models import User
        since = _now() - timedelta(hours=window_hours)
        target = (await db.execute(select(User).where(User.id == target_user_id))).scalar_one_or_none()
        owned = (await db.execute(select(AuditLog).where(AuditLog.user_id == target_user_id, AuditLog.created_at >= since))).scalars().all()
        failed = []
        if target:
            cands = (await db.execute(select(AuditLog).where(AuditLog.action == AuditAction.USER_LOGIN_FAILED, AuditLog.created_at >= since))).scalars().all()
            failed = [l for l in cands if l.extra_data and l.extra_data.get("username") == target.username]
        return CorrelationEngine._run(owned + failed, "user", str(target_user_id), window_hours)

    @staticmethod
    async def correlate_recent_activity(db, window_hours: int = 24, limit: int = 500) -> dict:
        since = _now() - timedelta(hours=window_hours)
        logs = (await db.execute(select(AuditLog).where(AuditLog.created_at >= since).order_by(AuditLog.created_at.asc()).limit(limit))).scalars().all()
        return CorrelationEngine._run(logs, "platform", None, window_hours)

    @staticmethod
    def _run(logs, entity_type, entity_id, window_hours):
        all_matches, triggered, evids, pts = [], [], set(), 0
        for rule in CORRELATION_REGISTRY:
            for m in rule.evaluate(logs):
                if m.matched:
                    all_matches.append({"chain_id":m.chain_id,"description":m.description,"event_ids":m.event_ids,"points":m.points})
                    triggered.append(m.chain_id); evids.update(m.event_ids); pts += m.points
        return {"entity_type":entity_type,"entity_id":entity_id,"window_hours":window_hours,"events_analyzed":len(logs),"correlation_score":min(pts,100),"chains_found":len(all_matches),"matches":all_matches,"triggered_chain_ids":sorted(set(triggered)),"correlated_event_ids":sorted(evids),"analyzed_at":_now().isoformat()}

    @staticmethod
    def list_rules(): return [{"chain_id":r.chain_id,"description":r.description} for r in CORRELATION_REGISTRY]

correlation_engine = CorrelationEngine()
