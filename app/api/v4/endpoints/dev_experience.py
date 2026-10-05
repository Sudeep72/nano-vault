"""Developer Experience: Diagnostics, Documentation Generator, API Collections — NanoVault v4.0"""
from __future__ import annotations
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.core.dependencies import get_current_user
from app.core.responses import ok

router = APIRouter(tags=["Developer Experience"])


# ── Diagnostics ────────────────────────────────────────────────────────────────

@router.get("/diagnostics/config", summary="Validate configuration (all issues at once, not fail-fast)")
async def config_check():
    from app.services.v4.diagnostics_service import diagnostics_service
    return ok(diagnostics_service.validate_config(), "Config validation")


@router.get("/diagnostics/environment", summary="Check required/optional environment variables")
async def env_check():
    from app.services.v4.diagnostics_service import diagnostics_service
    return ok(diagnostics_service.check_environment(), "Environment check")


@router.get("/diagnostics/dependencies", summary="Check required/optional Python packages installed")
async def deps_check():
    from app.services.v4.diagnostics_service import diagnostics_service
    return ok(diagnostics_service.check_dependencies(), "Dependency check")


@router.get("/diagnostics/full", summary="Full startup diagnostics sweep")
async def full_diagnostics(db: AsyncSession = Depends(get_db)):
    from app.services.v4.diagnostics_service import diagnostics_service
    return ok(await diagnostics_service.startup_diagnostics(db), "Full diagnostics")


@router.get("/diagnostics/sample-env", summary="Get a sample .env template", response_class=Response)
async def sample_env():
    from app.services.v4.diagnostics_service import diagnostics_service
    return Response(content=diagnostics_service.get_sample_env(), media_type="text/plain")


# ── Documentation Generator ──────────────────────────────────────────────────

@router.get("/docs-generator/architecture", summary="Generate architecture diagram (Mermaid)", response_class=Response)
async def gen_architecture(_=Depends(get_current_user)):
    from app.services.v4.doc_generator_service import doc_generator_service
    return Response(content=doc_generator_service.generate_architecture_diagram(), media_type="text/plain")


@router.get("/docs-generator/component-dot", summary="Generate component diagram (Graphviz DOT)", response_class=Response)
async def gen_component_dot(_=Depends(get_current_user)):
    from app.services.v4.doc_generator_service import doc_generator_service
    return Response(content=doc_generator_service.generate_component_diagram_dot(), media_type="text/vnd.graphviz")


@router.get("/docs-generator/er-diagram", summary="Generate ER diagram from real schema (Mermaid)", response_class=Response)
async def gen_er(_=Depends(get_current_user)):
    from app.services.v4.doc_generator_service import doc_generator_service
    return Response(content=doc_generator_service.generate_er_diagram(), media_type="text/plain")


@router.get("/docs-generator/deployment", summary="Generate deployment topology diagram (Mermaid)", response_class=Response)
async def gen_deployment(_=Depends(get_current_user)):
    from app.services.v4.doc_generator_service import doc_generator_service
    return Response(content=doc_generator_service.generate_deployment_diagram(), media_type="text/plain")


@router.get("/docs-generator/sequence/{flow}", summary="Generate sequence diagram for a real flow", response_class=Response)
async def gen_sequence(flow: str, _=Depends(get_current_user)):
    from app.services.v4.doc_generator_service import doc_generator_service
    return Response(content=doc_generator_service.generate_sequence_diagram(flow), media_type="text/plain")


@router.get("/docs-generator/available", summary="List available diagram types")
async def list_diagrams(_=Depends(get_current_user)):
    from app.services.v4.doc_generator_service import doc_generator_service
    return ok(doc_generator_service.list_available_diagrams(), "Available diagrams")


# ── API Collection Generator ──────────────────────────────────────────────────

@router.get("/collections/endpoint-count", summary="Count of API endpoints by tag")
async def endpoint_count(request: Request, _=Depends(get_current_user)):
    from app.services.v4.api_collection_service import api_collection_service
    schema = request.app.openapi()
    return ok(api_collection_service.get_endpoint_count(schema), "Endpoint count")


@router.get("/collections/postman", summary="Generate Postman collection from live OpenAPI schema")
async def postman_collection(request: Request, base_url: str = "http://localhost:8000", _=Depends(get_current_user)):
    from app.services.v4.api_collection_service import api_collection_service
    schema = request.app.openapi()
    return ok(api_collection_service.generate_postman_collection(schema, base_url), "Postman collection")


@router.get("/collections/bruno", summary="Generate Bruno collection files from live OpenAPI schema")
async def bruno_collection(request: Request, base_url: str = "http://localhost:8000", _=Depends(get_current_user)):
    from app.services.v4.api_collection_service import api_collection_service
    schema = request.app.openapi()
    return ok(api_collection_service.generate_bruno_collection(schema, base_url), "Bruno collection files")


@router.get("/collections/curl", summary="Generate curl examples for every endpoint")
async def curl_examples(request: Request, base_url: str = "http://localhost:8000", _=Depends(get_current_user)):
    from app.services.v4.api_collection_service import api_collection_service
    schema = request.app.openapi()
    return ok(api_collection_service.generate_curl_examples(schema, base_url), "curl examples")


@router.get("/collections/python", summary="Generate Python (httpx) examples for every endpoint")
async def python_examples(request: Request, base_url: str = "http://localhost:8000", _=Depends(get_current_user)):
    from app.services.v4.api_collection_service import api_collection_service
    schema = request.app.openapi()
    return ok(api_collection_service.generate_python_examples(schema, base_url), "Python examples")


@router.get("/collections/javascript", summary="Generate JavaScript (fetch) examples for every endpoint")
async def js_examples(request: Request, base_url: str = "http://localhost:8000", _=Depends(get_current_user)):
    from app.services.v4.api_collection_service import api_collection_service
    schema = request.app.openapi()
    return ok(api_collection_service.generate_javascript_examples(schema, base_url), "JavaScript examples")
