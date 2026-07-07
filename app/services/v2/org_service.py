from __future__ import annotations
"""Organization, Project, Team, Namespace Service — NanoVault v2.0"""
import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException
from app.models.models import Organization, Project, Team, Namespace, User, team_member_table


class OrgService:

    # ── Organizations ─────────────────────────────────────────────────────────

    @staticmethod
    async def create_org(db: AsyncSession, name: str, description: Optional[str] = None) -> Organization:
        exists = (await db.execute(select(Organization).where(Organization.name == name))).scalar_one_or_none()
        if exists:
            raise HTTPException(status_code=409, detail=f"Organization '{name}' already exists")
        org = Organization(name=name, description=description)
        db.add(org)
        await db.flush()
        return org

    @staticmethod
    async def get_org(db: AsyncSession, org_id: uuid.UUID) -> Organization:
        org = (await db.execute(select(Organization).where(Organization.id == org_id))).scalar_one_or_none()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        return org

    @staticmethod
    async def list_orgs(db: AsyncSession) -> list[Organization]:
        return (await db.execute(select(Organization).order_by(Organization.name))).scalars().all()

    @staticmethod
    async def add_member(db: AsyncSession, org_id: uuid.UUID, user: User) -> None:
        org = await OrgService.get_org(db, org_id)
        user.org_id = org.id
        await db.flush()

    # ── Projects ──────────────────────────────────────────────────────────────

    @staticmethod
    async def create_project(
        db: AsyncSession, org_id: uuid.UUID,
        name: str, description: Optional[str] = None,
    ) -> Project:
        await OrgService.get_org(db, org_id)
        project = Project(org_id=org_id, name=name, description=description)
        db.add(project)
        await db.flush()
        return project

    @staticmethod
    async def list_projects(db: AsyncSession, org_id: uuid.UUID) -> list[Project]:
        return (await db.execute(
            select(Project).where(Project.org_id == org_id).order_by(Project.name)
        )).scalars().all()

    # ── Teams ─────────────────────────────────────────────────────────────────

    @staticmethod
    async def create_team(
        db: AsyncSession, project_id: uuid.UUID,
        name: str, description: Optional[str] = None,
        policy_ids: Optional[list[str]] = None,
    ) -> Team:
        team = Team(
            project_id=project_id,
            name=name,
            description=description,
            policy_ids=policy_ids or [],
        )
        db.add(team)
        await db.flush()
        return team

    @staticmethod
    async def add_team_member(db: AsyncSession, team_id: uuid.UUID, user_id: uuid.UUID, role: str = "member") -> None:
        existing = (await db.execute(
            select(team_member_table).where(
                team_member_table.c.team_id == team_id,
                team_member_table.c.user_id == user_id,
            )
        )).first()
        if existing:
            raise HTTPException(status_code=409, detail="User already in team")
        await db.execute(
            team_member_table.insert().values(team_id=team_id, user_id=user_id, role=role)
        )
        await db.flush()

    @staticmethod
    async def list_teams(db: AsyncSession, project_id: uuid.UUID) -> list[Team]:
        return (await db.execute(
            select(Team).where(Team.project_id == project_id).order_by(Team.name)
        )).scalars().all()

    # ── Namespaces ────────────────────────────────────────────────────────────

    @staticmethod
    async def create_namespace(
        db: AsyncSession, org_id: uuid.UUID,
        name: str, path: str,
        description: Optional[str] = None,
        parent_id: Optional[uuid.UUID] = None,
    ) -> Namespace:
        existing = (await db.execute(select(Namespace).where(Namespace.path == path))).scalar_one_or_none()
        if existing:
            raise HTTPException(status_code=409, detail=f"Namespace path '{path}' already exists")
        ns = Namespace(
            org_id=org_id, name=name, path=path,
            description=description, parent_id=parent_id,
        )
        db.add(ns)
        await db.flush()
        return ns

    @staticmethod
    async def list_namespaces(db: AsyncSession, org_id: uuid.UUID) -> list[Namespace]:
        return (await db.execute(
            select(Namespace).where(Namespace.org_id == org_id).order_by(Namespace.path)
        )).scalars().all()


org_service = OrgService()
