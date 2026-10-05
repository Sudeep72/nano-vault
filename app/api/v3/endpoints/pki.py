from __future__ import annotations
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin, require_unsealed
from app.core.responses import ok, created
from app.engines.pki.engine import PKIEngine
from app.models.models import CertificateType, CertificateStatus, CertificateAuthority, Certificate, AuditAction
from app.services.audit_service import audit_service

router = APIRouter(prefix="/pki", tags=["PKI Secrets Engine"], dependencies=[Depends(require_unsealed)])

class CreateRootCARequest(BaseModel):
    name: str; subject_dn: str; ttl_days: int = Field(3650, ge=365, le=7300); key_size: int = Field(4096, ge=2048, le=4096)
class CreateIntermediateCARequest(BaseModel):
    name: str; subject_dn: str; parent_ca_id: uuid.UUID; ttl_days: int = Field(1825, ge=90, le=3650); key_size: int = Field(4096, ge=2048, le=4096)
class IssueCertRequest(BaseModel):
    ca_id: uuid.UUID; common_name: str; cert_type: CertificateType = CertificateType.SERVER
    ttl_days: int = Field(365, ge=1, le=3650); san_dns: Optional[list[str]] = None; san_ips: Optional[list[str]] = None; issued_to: Optional[str] = None
class RevokeCertRequest(BaseModel):
    reason: str = "unspecified"
class RenewCertRequest(BaseModel):
    ttl_days: int = Field(365, ge=1, le=3650)

def _ca_dict(ca):
    return {"id": str(ca.id), "name": ca.name, "type": ca.ca_type.value, "subject_dn": ca.subject_dn,
            "serial_number": ca.serial_number, "not_before": ca.not_before.isoformat(), "not_after": ca.not_after.isoformat(),
            "status": ca.status.value, "key_algorithm": ca.key_algorithm,
            "parent_ca_id": str(ca.parent_ca_id) if ca.parent_ca_id else None, "created_at": ca.created_at.isoformat()}

def _cert_dict(c):
    return {"id": str(c.id), "ca_id": str(c.ca_id), "type": c.cert_type.value, "common_name": c.common_name,
            "subject_dn": c.subject_dn, "san_dns": c.san_dns, "san_ips": c.san_ips, "serial_number": c.serial_number,
            "not_before": c.not_before.isoformat(), "not_after": c.not_after.isoformat(), "status": c.status.value,
            "revoked_at": c.revoked_at.isoformat() if c.revoked_at else None, "revocation_reason": c.revocation_reason,
            "issued_to": c.issued_to, "created_at": c.created_at.isoformat()}

@router.post("/ca/root", summary="Create Root Certificate Authority")
async def create_root_ca(body: CreateRootCARequest, request: Request, db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    ca, cert_pem = await PKIEngine.create_root_ca(db, body.name, body.subject_dn, body.ttl_days, body.key_size, admin.id)
    await audit_service.log(db, AuditAction.SECRET_CREATE, user_id=admin.id, resource_type="root_ca", resource_id=str(ca.id), request=request)
    return created({**_ca_dict(ca), "certificate_pem": cert_pem}, f"Root CA '{body.name}' created")

@router.post("/ca/intermediate", summary="Create Intermediate Certificate Authority")
async def create_intermediate_ca(body: CreateIntermediateCARequest, request: Request, db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    ca, chain_pem = await PKIEngine.create_intermediate_ca(db, body.name, body.subject_dn, body.parent_ca_id, body.ttl_days, body.key_size, admin.id)
    await audit_service.log(db, AuditAction.SECRET_CREATE, user_id=admin.id, resource_type="intermediate_ca", resource_id=str(ca.id), request=request)
    return created({**_ca_dict(ca), "chain_pem": chain_pem}, f"Intermediate CA '{body.name}' created")

@router.get("/ca", summary="List all Certificate Authorities")
async def list_cas(db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    cas = await PKIEngine.list_cas(db)
    return ok([_ca_dict(ca) for ca in cas], f"{len(cas)} CAs registered")

@router.get("/ca/{ca_id}/certificate", summary="Get CA certificate PEM")
async def get_ca_cert(ca_id: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    ca = (await db.execute(select(CertificateAuthority).where(CertificateAuthority.id==ca_id))).scalar_one_or_none()
    if not ca: raise HTTPException(404, "CA not found")
    return ok({"certificate_pem": ca.certificate_pem, "subject_dn": ca.subject_dn}, "CA certificate")

@router.get("/ca/{ca_id}/crl", summary="Generate Certificate Revocation List")
async def get_crl(ca_id: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    return ok({"crl_pem": await PKIEngine.generate_crl(db, ca_id)}, "CRL generated")

@router.post("/issue", summary="Issue a certificate from a CA")
async def issue_certificate(body: IssueCertRequest, request: Request, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    cert, cert_pem, chain_pem = await PKIEngine.issue_certificate(db, body.ca_id, body.common_name, body.cert_type, body.ttl_days, body.san_dns, body.san_ips, body.issued_to, current_user.id)
    await audit_service.log(db, AuditAction.SECRET_CREATE, user_id=current_user.id, resource_type="certificate", resource_id=str(cert.id), request=request)
    return created({**_cert_dict(cert), "certificate_pem": cert_pem, "chain_pem": chain_pem}, f"Certificate issued for '{body.common_name}'")

@router.post("/certificates/{cert_id}/revoke", summary="Revoke a certificate")
async def revoke_certificate(cert_id: uuid.UUID, body: RevokeCertRequest, request: Request, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    cert = await PKIEngine.revoke_certificate(db, cert_id, body.reason)
    await audit_service.log(db, AuditAction.SECRET_DELETE, user_id=current_user.id, resource_type="certificate", resource_id=str(cert_id), request=request, metadata={"reason": body.reason})
    return ok(_cert_dict(cert), "Certificate revoked")

@router.post("/certificates/{cert_id}/renew", summary="Renew a certificate")
async def renew_certificate(cert_id: uuid.UUID, body: RenewCertRequest, request: Request, db: AsyncSession = Depends(get_db), current_user=Depends(get_current_user)):
    cert, cert_pem, chain_pem = await PKIEngine.renew_certificate(db, cert_id, body.ttl_days, current_user.id)
    await audit_service.log(db, AuditAction.SECRET_UPDATE, user_id=current_user.id, resource_type="certificate", resource_id=str(cert.id), request=request)
    return created({**_cert_dict(cert), "certificate_pem": cert_pem, "chain_pem": chain_pem}, "Certificate renewed")

@router.get("/certificates", summary="List certificates")
async def list_certificates(ca_id: Optional[uuid.UUID] = None, status: Optional[CertificateStatus] = None, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    certs = await PKIEngine.list_certificates(db, ca_id, status)
    return ok([_cert_dict(c) for c in certs], f"{len(certs)} certificates")

@router.get("/certificates/{cert_id}", summary="Get certificate details")
async def get_certificate(cert_id: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    cert = (await db.execute(select(Certificate).where(Certificate.id==cert_id))).scalar_one_or_none()
    if not cert: raise HTTPException(404, "Certificate not found")
    return ok({**_cert_dict(cert), "certificate_pem": cert.certificate_pem, "chain_pem": cert.certificate_chain_pem, "csr_pem": cert.csr_pem}, "Certificate")
