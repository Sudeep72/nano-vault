"""
Multi-Region Replication — NanoVault v3.0 Final Completion.
Real state machine for primary/secondary/DR/read-replica roles, simulated locally
(no actual cross-process network replication — that requires real multi-node deployment).
"""
from __future__ import annotations
import time
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum


class RegionRole(str, PyEnum):
    PRIMARY = "primary"
    SECONDARY = "secondary"
    DR = "disaster_recovery"
    READ_REPLICA = "read_replica"


class RegionHealth(str, PyEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNREACHABLE = "unreachable"


def _now(): return datetime.now(timezone.utc)


class _Region:
    def __init__(self, name: str, role: RegionRole):
        self.id = str(uuid.uuid4())
        self.name = name
        self.role = role
        self.health = RegionHealth.HEALTHY
        self.last_sync_at = _now()
        self.replication_lag_ms = 0.0
        self.version_counter = 0  # simulated data version for conflict detection


class ReplicationService:
    """
    In-process simulation of a multi-region topology.
    Real deployment would replace this with actual streaming replication
    (e.g. PostgreSQL logical replication) between physically separate nodes.
    """

    def __init__(self):
        self._regions: dict[str, _Region] = {
            "us-east-1": _Region("us-east-1", RegionRole.PRIMARY),
            "us-west-2": _Region("us-west-2", RegionRole.SECONDARY),
            "eu-west-1": _Region("eu-west-1", RegionRole.DR),
        }
        self._conflict_log: list[dict] = []

    def get_topology(self) -> dict:
        return {
            "regions": [
                {"name": r.name, "role": r.role.value, "health": r.health.value,
                 "replication_lag_ms": r.replication_lag_ms,
                 "last_sync_at": r.last_sync_at.isoformat(), "version": r.version_counter}
                for r in self._regions.values()
            ],
            "primary": next((r.name for r in self._regions.values() if r.role == RegionRole.PRIMARY), None),
        }

    def simulate_write(self, region_name: str) -> dict:
        """Simulate a write on the primary and propagate a version bump to secondaries."""
        primary = next((r for r in self._regions.values() if r.role == RegionRole.PRIMARY), None)
        if not primary or primary.name != region_name:
            return {"error": f"'{region_name}' is not the primary region — writes must go to primary"}
        primary.version_counter += 1
        for r in self._regions.values():
            if r.role != RegionRole.PRIMARY:
                # Simulate propagation lag proportional to a fixed network model
                r.replication_lag_ms = 12.5 if r.role == RegionRole.SECONDARY else 45.0
                r.version_counter = primary.version_counter  # eventually consistent
                r.last_sync_at = _now()
        return {"primary_version": primary.version_counter, "propagated_to": [
            r.name for r in self._regions.values() if r.role != RegionRole.PRIMARY
        ]}

    def detect_conflicts(self) -> list[dict]:
        """Compare version counters across regions to detect divergence."""
        versions = {r.name: r.version_counter for r in self._regions.values()}
        primary_version = next((v for r, v in versions.items() if self._regions[r].role == RegionRole.PRIMARY), 0)
        conflicts = []
        for name, version in versions.items():
            if version != primary_version:
                conflicts.append({"region": name, "expected_version": primary_version, "actual_version": version})
        if conflicts:
            self._conflict_log.append({"detected_at": _now().isoformat(), "conflicts": conflicts})
        return conflicts

    def failover(self, target_region: str) -> dict:
        """Promote target_region to primary; demote old primary to secondary."""
        target = self._regions.get(target_region)
        if not target:
            return {"error": f"Region '{target_region}' not found"}
        old_primary = next((r for r in self._regions.values() if r.role == RegionRole.PRIMARY), None)
        if old_primary:
            old_primary.role = RegionRole.SECONDARY
            old_primary.health = RegionHealth.DEGRADED
        target.role = RegionRole.PRIMARY
        target.health = RegionHealth.HEALTHY
        target.last_sync_at = _now()
        return {
            "failover_complete": True,
            "new_primary": target.name,
            "old_primary": old_primary.name if old_primary else None,
            "at": _now().isoformat(),
        }

    def promote(self, region_name: str) -> dict:
        """Promote a read-replica or DR region to secondary (staging before full failover)."""
        r = self._regions.get(region_name)
        if not r:
            return {"error": f"Region '{region_name}' not found"}
        if r.role == RegionRole.PRIMARY:
            return {"error": "Already primary"}
        r.role = RegionRole.SECONDARY
        return {"promoted": region_name, "new_role": r.role.value}

    def health_check_all(self) -> dict:
        return {r.name: r.health.value for r in self._regions.values()}

    def get_conflict_log(self) -> list[dict]:
        return self._conflict_log[-50:]


replication_service = ReplicationService()
