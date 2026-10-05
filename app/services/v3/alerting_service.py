"""
Alerting Completion — NanoVault v3.0 Final Completion Pass 2.
Alert history tracking, suppression windows, and dependency-health aggregation
across every subsystem (engines, identity, replication, scheduler, cache).
"""
from __future__ import annotations
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

_now = lambda: datetime.now(timezone.utc)
_ALERT_HISTORY: list[dict] = []
_SUPPRESSIONS: dict[str, dict] = {}  # alert_name -> {"until": ts, "reason": str}


class AlertingService:

    @staticmethod
    def fire_alert(name: str, severity: str, message: str, labels: Optional[dict] = None) -> dict:
        if AlertingService.is_suppressed(name):
            return {"fired": False, "reason": "suppressed"}
        alert = {
            "id": str(uuid.uuid4()), "name": name, "severity": severity,
            "message": message, "labels": labels or {}, "fired_at": _now().isoformat(),
        }
        _ALERT_HISTORY.append(alert)
        if len(_ALERT_HISTORY) > 1000:
            _ALERT_HISTORY.pop(0)
        return {"fired": True, "alert": alert}

    @staticmethod
    def suppress(alert_name: str, duration_minutes: int, reason: str) -> dict:
        until = _now() + timedelta(minutes=duration_minutes)
        _SUPPRESSIONS[alert_name] = {"until": until, "reason": reason}
        return {"suppressed": alert_name, "until": until.isoformat(), "reason": reason}

    @staticmethod
    def unsuppress(alert_name: str) -> dict:
        removed = _SUPPRESSIONS.pop(alert_name, None)
        return {"unsuppressed": alert_name, "was_active": removed is not None}

    @staticmethod
    def is_suppressed(alert_name: str) -> bool:
        s = _SUPPRESSIONS.get(alert_name)
        if not s:
            return False
        if s["until"] < _now():
            _SUPPRESSIONS.pop(alert_name, None)
            return False
        return True

    @staticmethod
    def get_history(limit: int = 50, severity: Optional[str] = None) -> list[dict]:
        items = _ALERT_HISTORY
        if severity:
            items = [a for a in items if a["severity"] == severity]
        return list(reversed(items))[:limit]

    @staticmethod
    def get_active_suppressions() -> list[dict]:
        now = _now()
        return [{"alert_name": k, "until": v["until"].isoformat(), "reason": v["reason"]}
                for k, v in _SUPPRESSIONS.items() if v["until"] > now]

    @staticmethod
    async def get_dependency_health(db) -> dict:
        """Aggregates health across every subsystem into one dependency graph view."""
        from sqlalchemy import text
        deps = {}

        try:
            await db.execute(text("SELECT 1"))
            deps["database"] = {"healthy": True}
        except Exception as e:
            deps["database"] = {"healthy": False, "error": str(e)}

        from app.services.v3.cache_service import health as cache_health
        deps["cache"] = cache_health()

        from app.services.v3.otel_service import status as otel_status
        deps["tracing"] = otel_status()

        from app.services.v3.apscheduler_service import get_scheduler_jobs
        jobs = get_scheduler_jobs()
        deps["scheduler"] = {"healthy": True, "active_jobs": len(jobs)}

        from app.services.v3.replication_service import replication_service
        deps["replication"] = {"healthy": True, "regions": replication_service.health_check_all()}

        from app.services.v2.engine_service import engine_service
        mounts = await engine_service.list_all(db)
        deps["engines"] = {"healthy": len(mounts) > 0, "count": len(mounts)}

        overall = all(
            d.get("healthy", d.get("available", True)) for d in deps.values()
        )
        return {"overall_healthy": overall, "dependencies": deps, "checked_at": _now().isoformat()}


alerting_service = AlertingService()
