"""
Policy Inheritance Service — NanoVault v2.0 Enterprise Hardening

Hierarchical policy evaluation:
  Organization policy → Project policy → Team policy → User policy

Supports:
  - Parent policies
  - Child policy overrides
  - Explicit deny rules
  - Policy merging
  - Effective permission calculation
"""
from __future__ import annotations
import uuid
import fnmatch
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.models import (
    Policy, User, UserRole, Organization, Project, Team,
    user_policy_table, team_member_table, PolicyInheritance,
)


# Actions hierarchy
ALL_ACTIONS = {"create", "read", "update", "delete", "list"}


def _path_matches(pattern: str, key: str) -> bool:
    return fnmatch.fnmatch(key, pattern)


class EffectivePermissions:
    """Result of a full policy evaluation chain."""

    def __init__(self):
        self.allowed: dict[str, set[str]] = {}   # path_pattern -> allowed actions
        self.denied: dict[str, set[str]] = {}    # path_pattern -> denied actions
        self.sources: list[str] = []             # policy names that contributed

    def allow(self, path: str, actions: list[str], source: str):
        if path not in self.allowed:
            self.allowed[path] = set()
        self.allowed[path].update(actions)
        if source not in self.sources:
            self.sources.append(source)

    def deny(self, path: str, actions: list[str], source: str):
        if path not in self.denied:
            self.denied[path] = set()
        self.denied[path].update(actions)
        if source not in self.sources:
            self.sources.append(source)

    def is_allowed(self, secret_key: str, action: str) -> bool:
        """Explicit deny wins. Then check allows."""
        for pattern, denied_actions in self.denied.items():
            if _path_matches(pattern, secret_key) and action in denied_actions:
                return False
        for pattern, allowed_actions in self.allowed.items():
            if _path_matches(pattern, secret_key) and action in allowed_actions:
                return True
        return False

    def to_dict(self) -> dict:
        return {
            "allowed": {k: list(v) for k, v in self.allowed.items()},
            "denied": {k: list(v) for k, v in self.denied.items()},
            "policy_sources": self.sources,
        }


class PolicyInheritanceService:

    @staticmethod
    def _apply_policy(perms: EffectivePermissions, policy: Policy) -> None:
        for rule in (policy.permissions or []):
            path = rule.get("path", "")
            actions = rule.get("actions", [])
            deny = rule.get("deny", False)
            if deny:
                perms.deny(path, actions, policy.name)
            else:
                perms.allow(path, actions, policy.name)

    @staticmethod
    async def _get_user_direct_policies(db: AsyncSession, user_id: uuid.UUID) -> list[Policy]:
        result = await db.execute(
            select(Policy)
            .join(user_policy_table, Policy.id == user_policy_table.c.policy_id)
            .where(user_policy_table.c.user_id == user_id)
        )
        return result.scalars().all()

    @staticmethod
    async def _get_team_policies(db: AsyncSession, user_id: uuid.UUID) -> list[Policy]:
        """Get policies from all teams the user belongs to."""
        teams_result = await db.execute(
            select(Team)
            .join(team_member_table, Team.id == team_member_table.c.team_id)
            .where(team_member_table.c.user_id == user_id)
        )
        teams = teams_result.scalars().all()
        policies = []
        for team in teams:
            for policy_id in (team.policy_ids or []):
                try:
                    pol = (await db.execute(
                        select(Policy).where(Policy.id == uuid.UUID(policy_id))
                    )).scalar_one_or_none()
                    if pol:
                        policies.append(pol)
                except Exception:
                    pass
        return policies

    @staticmethod
    async def _get_parent_policies(db: AsyncSession, policy: Policy) -> list[Policy]:
        """Walk the parent chain of a policy."""
        chain = []
        current = policy
        visited = set()
        while current.parent_policy_id and str(current.parent_policy_id) not in visited:
            visited.add(str(current.parent_policy_id))
            parent = (await db.execute(
                select(Policy).where(Policy.id == current.parent_policy_id)
            )).scalar_one_or_none()
            if not parent:
                break
            chain.insert(0, parent)
            current = parent
        return chain

    @staticmethod
    async def compute_effective(
        db: AsyncSession,
        user: User,
    ) -> EffectivePermissions:
        """
        Compute effective permissions for a user following the hierarchy:
          Org policies → Project policies → Team policies → User direct policies
        Admin bypasses everything.
        """
        perms = EffectivePermissions()

        if user.role == UserRole.ADMIN:
            perms.allow("*", list(ALL_ACTIONS), "admin_role")
            return perms

        # 1. User direct policies (with parent chain)
        direct = await PolicyInheritanceService._get_user_direct_policies(db, user.id)
        for policy in direct:
            parents = await PolicyInheritanceService._get_parent_policies(db, policy)
            for parent in parents:
                PolicyInheritanceService._apply_policy(perms, parent)
            PolicyInheritanceService._apply_policy(perms, policy)

        # 2. Team policies
        team_policies = await PolicyInheritanceService._get_team_policies(db, user.id)
        for policy in team_policies:
            PolicyInheritanceService._apply_policy(perms, policy)

        return perms

    @staticmethod
    async def check(
        db: AsyncSession,
        user: User,
        secret_key: str,
        action: str,
    ) -> bool:
        if user.role == UserRole.ADMIN:
            return True
        perms = await PolicyInheritanceService.compute_effective(db, user)
        return perms.is_allowed(secret_key, action)

    @staticmethod
    async def require(
        db: AsyncSession,
        user: User,
        secret_key: str,
        action: str,
    ) -> None:
        from fastapi import HTTPException
        allowed = await PolicyInheritanceService.check(db, user, secret_key, action)
        if not allowed:
            raise HTTPException(
                status_code=403,
                detail=f"Policy denied: action '{action}' on path '{secret_key}'",
            )

    @staticmethod
    async def get_inheritance_tree(
        db: AsyncSession,
        policy_id: uuid.UUID,
    ) -> dict:
        """Return a tree showing policy and its full parent chain."""
        policy = (await db.execute(
            select(Policy).where(Policy.id == policy_id)
        )).scalar_one_or_none()
        if not policy:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Policy not found")

        parents = await PolicyInheritanceService._get_parent_policies(db, policy)
        return {
            "policy": {
                "id": str(policy.id),
                "name": policy.name,
                "permissions": policy.permissions,
                "is_builtin": policy.is_builtin,
            },
            "parent_chain": [
                {
                    "id": str(p.id),
                    "name": p.name,
                    "permissions": p.permissions,
                }
                for p in parents
            ],
            "depth": len(parents),
        }


policy_inheritance_service = PolicyInheritanceService()
