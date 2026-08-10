"""Architecture Explorer + Secret Dependency Graph — NanoVault v4.0"""
from __future__ import annotations
import uuid
from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.core.dependencies import get_current_user
from app.core.responses import ok

router = APIRouter(tags=["Architecture Explorer"])


@router.get("/architecture/graph", summary="Full architecture graph (nodes + edges)")
async def get_graph(_=Depends(get_current_user)):
    from app.services.v4.architecture_service import architecture_service
    return ok(architecture_service.get_full_graph(), "Architecture graph")


@router.get("/architecture/nodes/{node_id}", summary="Get details for one architecture component")
async def get_node(node_id: str, _=Depends(get_current_user)):
    from app.services.v4.architecture_service import architecture_service
    node = architecture_service.get_node(node_id)
    if not node:
        from fastapi import HTTPException
        raise HTTPException(404, f"Node '{node_id}' not found")
    return ok(node, f"Node: {node_id}")


@router.get("/architecture/nodes/{node_id}/dependencies", summary="Dependencies for a component")
async def get_node_deps(node_id: str, _=Depends(get_current_user)):
    from app.services.v4.architecture_service import architecture_service
    return ok(architecture_service.get_node_dependencies(node_id), f"Dependencies for {node_id}")


@router.get("/architecture/category/{category}", summary="Components by category (service/engine/infrastructure)")
async def get_by_category(category: str, _=Depends(get_current_user)):
    from app.services.v4.architecture_service import architecture_service
    return ok(architecture_service.get_by_category(category), f"Category: {category}")


@router.get("/architecture/search", summary="Search architecture components")
async def search(q: str, _=Depends(get_current_user)):
    from app.services.v4.architecture_service import architecture_service
    return ok(architecture_service.search_nodes(q), f"Search results for '{q}'")


@router.get("/architecture/export/dot", summary="Export architecture as Graphviz DOT", response_class=Response)
async def export_dot(_=Depends(get_current_user)):
    from app.services.v4.architecture_service import architecture_service
    return Response(content=architecture_service.export_dot(), media_type="text/vnd.graphviz")


@router.get("/architecture/export/mermaid", summary="Export architecture as Mermaid flowchart", response_class=Response)
async def export_mermaid(_=Depends(get_current_user)):
    from app.services.v4.architecture_service import architecture_service
    return Response(content=architecture_service.export_mermaid(), media_type="text/plain")


# ── Secret Dependency Graph (real DB traversal) ────────────────────────────────

@router.get("/dependency-graph", summary="Full resource dependency graph (real DB relationships)")
async def dependency_graph(db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.services.v4.dependency_graph_service import dependency_graph_service
    return ok(await dependency_graph_service.build_full_graph(db), "Dependency graph")


@router.get("/dependency-graph/secrets/{secret_id}/impact", summary="Impact analysis for a secret")
async def secret_impact(secret_id: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.services.v4.dependency_graph_service import dependency_graph_service
    return ok(await dependency_graph_service.get_secret_impact_analysis(db, secret_id), "Impact analysis")


@router.get("/dependency-graph/reverse/{resource_type}/{resource_id}", summary="Reverse dependency lookup")
async def reverse_deps(resource_type: str, resource_id: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.services.v4.dependency_graph_service import dependency_graph_service
    return ok(await dependency_graph_service.get_reverse_dependencies(db, resource_type, resource_id), "Reverse dependencies")


@router.get("/dependency-graph/ownership", summary="Resource ownership map")
async def ownership_map(db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.services.v4.dependency_graph_service import dependency_graph_service
    return ok(await dependency_graph_service.get_ownership_map(db), "Ownership map")
