"""Organizations, Projects, Teams, Namespaces — NanoVault v2.0"""
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok, created
from app.services.v2.org_service import org_service
from app.services.audit_service import audit_service
from app.models.models import AuditAction

router = APIRouter(prefix="/orgs", tags=["Organizations & Teams"])


class OrgRequest(BaseModel):
    name: str
    description: Optional[str] = None


class ProjectRequest(BaseModel):
    name: str
    description: Optional[str] = None


class TeamRequest(BaseModel):
    name: str
    description: Optional[str] = None
    policy_ids: list[str] = []


class MemberRequest(BaseModel):
    user_id: uuid.UUID
    role: str = "member"


class NamespaceRequest(BaseModel):
    name: str
    path: str
    description: Optional[str] = None
    parent_id: Optional[uuid.UUID] = None


# ── Organizations ─────────────────────────────────────────────────────────────

@router.post("/", summary="Create organization [Admin]")
async def create_org(
    body: OrgRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin),
):
    org = await org_service.create_org(db, body.name, body.description)
    await audit_service.log(db, AuditAction.ORG_CREATE, user_id=admin.id,
                            resource_type="organization", resource_id=str(org.id), request=request)
    return created({"id": str(org.id), "name": org.name}, "Organization created")


@router.get("/", summary="List all organizations")
async def list_orgs(db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    orgs = await org_service.list_orgs(db)
    return ok([{"id": str(o.id), "name": o.name, "description": o.description,
                "created_at": o.created_at.isoformat()} for o in orgs], "Organizations retrieved")


@router.post("/{org_id}/members", summary="Add user to organization [Admin]")
async def add_member(
    org_id: uuid.UUID, body: MemberRequest,
    db: AsyncSession = Depends(get_db), admin=Depends(require_admin),
):
    from app.models.models import User
    from sqlalchemy import select
    user = (await db.execute(select(User).where(User.id == body.user_id))).scalar_one_or_none()
    if not user:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="User not found")
    await org_service.add_member(db, org_id, user)
    return ok(message=f"User added to organization")


# ── Projects ──────────────────────────────────────────────────────────────────

@router.post("/{org_id}/projects", summary="Create project [Admin]")
async def create_project(
    org_id: uuid.UUID, body: ProjectRequest,
    request: Request, db: AsyncSession = Depends(get_db), admin=Depends(require_admin),
):
    project = await org_service.create_project(db, org_id, body.name, body.description)
    await audit_service.log(db, AuditAction.PROJECT_CREATE, user_id=admin.id,
                            resource_type="project", resource_id=str(project.id), request=request)
    return created({"id": str(project.id), "name": project.name}, "Project created")


@router.get("/{org_id}/projects", summary="List projects in organization")
async def list_projects(
    org_id: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(get_current_user),
):
    projects = await org_service.list_projects(db, org_id)
    return ok([{"id": str(p.id), "name": p.name, "description": p.description} for p in projects],
              "Projects retrieved")


# ── Teams ─────────────────────────────────────────────────────────────────────

@router.post("/{org_id}/projects/{project_id}/teams", summary="Create team [Admin]")
async def create_team(
    org_id: uuid.UUID, project_id: uuid.UUID, body: TeamRequest,
    request: Request, db: AsyncSession = Depends(get_db), admin=Depends(require_admin),
):
    team = await org_service.create_team(db, project_id, body.name, body.description, body.policy_ids)
    await audit_service.log(db, AuditAction.TEAM_CREATE, user_id=admin.id,
                            resource_type="team", resource_id=str(team.id), request=request)
    return created({"id": str(team.id), "name": team.name}, "Team created")


@router.post("/{org_id}/projects/{project_id}/teams/{team_id}/members", summary="Add member to team [Admin]")
async def add_team_member(
    org_id: uuid.UUID, project_id: uuid.UUID, team_id: uuid.UUID, body: MemberRequest,
    db: AsyncSession = Depends(get_db), admin=Depends(require_admin),
):
    await org_service.add_team_member(db, team_id, body.user_id, body.role)
    return ok(message="Member added to team")


# ── Namespaces ────────────────────────────────────────────────────────────────

@router.post("/{org_id}/namespaces", summary="Create namespace [Admin]")
async def create_namespace(
    org_id: uuid.UUID, body: NamespaceRequest,
    request: Request, db: AsyncSession = Depends(get_db), admin=Depends(require_admin),
):
    ns = await org_service.create_namespace(
        db, org_id, body.name, body.path, body.description, body.parent_id
    )
    await audit_service.log(db, AuditAction.NAMESPACE_CREATE, user_id=admin.id,
                            resource_type="namespace", resource_id=str(ns.id), request=request)
    return created({"id": str(ns.id), "name": ns.name, "path": ns.path}, "Namespace created")


@router.get("/{org_id}/namespaces", summary="List namespaces in organization")
async def list_namespaces(
    org_id: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(get_current_user),
):
    namespaces = await org_service.list_namespaces(db, org_id)
    return ok([{"id": str(n.id), "name": n.name, "path": n.path, "parent_id": str(n.parent_id) if n.parent_id else None}
               for n in namespaces], "Namespaces retrieved")
