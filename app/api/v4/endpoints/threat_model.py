"""Threat Modeling Dashboard — NanoVault v4.0"""
from __future__ import annotations
from fastapi import APIRouter, Depends, Response, HTTPException
from app.core.dependencies import get_current_user
from app.core.responses import ok

router = APIRouter(prefix="/threat-model", tags=["Threat Modeling"])


@router.get("/flow", summary="Data flow: User -> Auth -> AuthZ -> Secrets -> Transit -> PKI -> Storage -> Audit")
async def get_flow(_=Depends(get_current_user)):
    from app.services.v4.threat_model_service import threat_model_service
    return ok(threat_model_service.get_flow(), "Threat model flow")


@router.get("/threats", summary="All threats (STRIDE analysis)")
async def get_threats(_=Depends(get_current_user)):
    from app.services.v4.threat_model_service import threat_model_service
    return ok(threat_model_service.get_all_threats(), "All threats")


@router.get("/threats/{threat_id}", summary="Get one threat with mitigations + framework mappings")
async def get_threat(threat_id: str, _=Depends(get_current_user)):
    from app.services.v4.threat_model_service import threat_model_service
    threat = threat_model_service.get_threat(threat_id)
    if not threat:
        raise HTTPException(404, f"Threat '{threat_id}' not found")
    return ok(threat, threat_id)


@router.get("/stage/{stage}", summary="Threats affecting a specific flow stage")
async def by_stage(stage: str, _=Depends(get_current_user)):
    from app.services.v4.threat_model_service import threat_model_service
    return ok(threat_model_service.get_threats_by_stage(stage), f"Threats at stage: {stage}")


@router.get("/stride/{category}", summary="Threats by STRIDE category")
async def by_stride(category: str, _=Depends(get_current_user)):
    from app.services.v4.threat_model_service import threat_model_service
    return ok(threat_model_service.get_threats_by_stride(category), f"STRIDE category: {category}")


@router.get("/coverage", summary="Threat model coverage summary")
async def coverage(_=Depends(get_current_user)):
    from app.services.v4.threat_model_service import threat_model_service
    return ok(threat_model_service.get_coverage_summary(), "Coverage summary")


@router.get("/export/markdown", summary="Export full threat model as Markdown", response_class=Response)
async def export_markdown(_=Depends(get_current_user)):
    from app.services.v4.threat_model_service import threat_model_service
    return Response(content=threat_model_service.export_markdown(), media_type="text/markdown")
