"""
Policy Engine — NanoVault v1.0.1

Implements path-based RBAC on top of the existing role system.
Admin role is always a superuser — policy checks are bypassed.

Permission model:
  Each policy has a list of rules: [{path: "aws/*", actions: ["read","list"]}, ...]
  Path matching supports trailing wildcard: "aws/*" matches "aws/prod/key"
  Exact match also supported: "database/password" matches only that key.

Built-in policies created at startup:
  admin     — all actions on *
  developer — create/read/update/delete/list on dev/*, read/list on aws/*
  readonly  — read/list on *
  database-team — all on database/*, read/list on *
  devops    — all on aws/*, all on production/*, read/list on *
"""
import uuid
import fnmatch
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status
from app.models.models import Policy, User, UserRole, user_policy_table
from app.schemas.schemas import PolicyCreateRequest, PolicyUpdateRequest


BUILTIN_POLICIES = [
    {
        "name": "admin",
        "description": "Superuser — all actions on all paths",
        "permissions": [{"path": "*", "actions": ["create", "read", "update", "delete", "list"]}],
        "is_builtin": True,
    },
    {
        "name": "developer",
        "description": "Full access to dev paths, read-only on aws",
        "permissions": [
            {"path": "dev/*", "actions": ["create", "read", "update", "delete", "list"]},
            {"path": "aws/*", "actions": ["read", "list"]},
        ],
        "is_builtin": True,
    },
    {
        "name": "readonly",
        "description": "Read and list access to all paths",
        "permissions": [{"path": "*", "actions": ["read", "list"]}],
        "is_builtin": True,
    },
    {
        "name": "database-team",
        "description": "Full access to database paths, read-only elsewhere",
        "permissions": [
            {"path": "database/*", "actions": ["create", "read", "update", "delete", "list"]},
            {"path": "*", "actions": ["read", "list"]},
        ],
        "is_builtin": True,
    },
    {
        "name": "devops",
        "description": "Full access to aws and production paths",
        "permissions": [
            {"path": "aws/*", "actions": ["create", "read", "update", "delete", "list"]},
            {"path": "production/*", "actions": ["create", "read", "update", "delete", "list"]},
            {"path": "*", "actions": ["read", "list"]},
        ],
        "is_builtin": True,
    },
]


def _path_matches(pattern: str, key: str) -> bool:
    """Match a secret key against a policy path pattern. Supports fnmatch wildcards."""
    return fnmatch.fnmatch(key, pattern)


class PolicyService:

    @staticmethod
    async def seed_builtins(db: AsyncSession) -> None:
        """Create built-in policies if they don't exist. Called at startup."""
        for p in BUILTIN_POLICIES:
            exists = await db.execute(select(Policy).where(Policy.name == p["name"]))
            if not exists.scalar_one_or_none():
                db.add(Policy(**p))
        await db.flush()

    @staticmethod
    async def check_permission(
        db: AsyncSession,
        user: User,
        secret_key: str,
        action: str,
    ) -> bool:
        """
        Returns True if user is allowed to perform action on secret_key.
        Admin role always returns True.
        If user has no policies assigned, defaults to DENY.
        """
        if user.role == UserRole.ADMIN:
            return True

        # Load user's policies (eager via relationship if loaded, else query)
        result = await db.execute(
            select(Policy)
            .join(user_policy_table, Policy.id == user_policy_table.c.policy_id)
            .where(user_policy_table.c.user_id == user.id)
        )
        policies = result.scalars().all()

        for policy in policies:
            for rule in (policy.permissions or []):
                if _path_matches(rule.get("path", ""), secret_key):
                    if action in rule.get("actions", []):
                        return True
        return False

    @staticmethod
    async def require_permission(
        db: AsyncSession,
        user: User,
        secret_key: str,
        action: str,
    ) -> None:
        allowed = await PolicyService.check_permission(db, user, secret_key, action)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Policy denied: action '{action}' on path '{secret_key}'",
            )

    @staticmethod
    async def create(db: AsyncSession, req: PolicyCreateRequest) -> Policy:
        exists = await db.execute(select(Policy).where(Policy.name == req.name))
        if exists.scalar_one_or_none():
            raise HTTPException(status_code=409, detail=f"Policy '{req.name}' already exists")
        policy = Policy(
            name=req.name,
            description=req.description,
            permissions=[p.model_dump() for p in req.permissions],
        )
        db.add(policy)
        await db.flush()
        return policy

    @staticmethod
    async def update(db: AsyncSession, policy_id: uuid.UUID, req: PolicyUpdateRequest) -> Policy:
        result = await db.execute(select(Policy).where(Policy.id == policy_id))
        policy = result.scalar_one_or_none()
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        if policy.is_builtin:
            raise HTTPException(status_code=403, detail="Built-in policies cannot be modified")
        if req.description is not None:
            policy.description = req.description
        if req.permissions is not None:
            policy.permissions = [p.model_dump() for p in req.permissions]
        await db.flush()
        return policy

    @staticmethod
    async def delete(db: AsyncSession, policy_id: uuid.UUID) -> None:
        result = await db.execute(select(Policy).where(Policy.id == policy_id))
        policy = result.scalar_one_or_none()
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        if policy.is_builtin:
            raise HTTPException(status_code=403, detail="Built-in policies cannot be deleted")
        await db.delete(policy)
        await db.flush()

    @staticmethod
    async def assign(db: AsyncSession, user_id: uuid.UUID, policy_id: uuid.UUID) -> None:
        from app.models.models import User as UserModel
        user = (await db.execute(select(UserModel).where(UserModel.id == user_id))).scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        policy = (await db.execute(select(Policy).where(Policy.id == policy_id))).scalar_one_or_none()
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        # Check not already assigned
        stmt = select(user_policy_table).where(
            user_policy_table.c.user_id == user_id,
            user_policy_table.c.policy_id == policy_id,
        )
        if (await db.execute(stmt)).first():
            raise HTTPException(status_code=409, detail="Policy already assigned to user")
        await db.execute(
            user_policy_table.insert().values(user_id=user_id, policy_id=policy_id)
        )
        await db.flush()

    @staticmethod
    async def revoke(db: AsyncSession, user_id: uuid.UUID, policy_id: uuid.UUID) -> None:
        await db.execute(
            user_policy_table.delete().where(
                user_policy_table.c.user_id == user_id,
                user_policy_table.c.policy_id == policy_id,
            )
        )
        await db.flush()

    @staticmethod
    async def list_all(db: AsyncSession) -> list[Policy]:
        result = await db.execute(select(Policy).order_by(Policy.name))
        return result.scalars().all()

    @staticmethod
    async def get_user_policies(db: AsyncSession, user_id: uuid.UUID) -> list[Policy]:
        result = await db.execute(
            select(Policy)
            .join(user_policy_table, Policy.id == user_policy_table.c.policy_id)
            .where(user_policy_table.c.user_id == user_id)
        )
        return result.scalars().all()


policy_service = PolicyService()
