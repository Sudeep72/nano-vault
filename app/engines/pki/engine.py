from __future__ import annotations
import base64, ipaddress, uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException
from app.engines.base import BaseSecretsEngine, engine_registry
from app.models.models import CertificateAuthority, Certificate, CertificateType, CertificateStatus
from app.core.encryption import encryption_service

def _now(): return datetime.now(timezone.utc)
def _serial(): return int(uuid.uuid4()) & ((1 << 128) - 1)
def _parse_dn(dn):
    attrs = []
    for p in dn.split(","):
        p = p.strip()
        if "=" not in p: continue
        k, v = p.split("=", 1)
        m = {"CN": NameOID.COMMON_NAME, "O": NameOID.ORGANIZATION_NAME,
             "OU": NameOID.ORGANIZATIONAL_UNIT_NAME, "C": NameOID.COUNTRY_NAME,
             "ST": NameOID.STATE_OR_PROVINCE_NAME, "L": NameOID.LOCALITY_NAME}
        oid = m.get(k.strip().upper())
        if oid: attrs.append(x509.NameAttribute(oid, v.strip()))
    return x509.Name(attrs)
def _gen_key(size=4096): return rsa.generate_private_key(65537, size, default_backend())
def _pem(c): return c.public_bytes(serialization.Encoding.PEM).decode()
def _priv_pem(k): return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()

@engine_registry.register("pki")
class PKIEngine(BaseSecretsEngine):
    engine_name = "pki"; engine_version = "3.0"
    description = "PKI Engine — CA, issuance, revocation, CRL"
    async def read(self, p, **kw): raise NotImplementedError
    async def write(self, p, d, **kw): raise NotImplementedError
    async def delete(self, p, **kw): raise NotImplementedError
    async def list(self, p, **kw): raise NotImplementedError

    @staticmethod
    async def create_root_ca(db, name, subject_dn, ttl_days=3650, key_size=4096, created_by=None):
        if (await db.execute(select(CertificateAuthority).where(CertificateAuthority.name==name))).scalar_one_or_none():
            raise HTTPException(409, f"CA '{name}' exists")
        pk = _gen_key(key_size); subj = _parse_dn(subject_dn); ser = _serial()
        now = _now(); na = now + timedelta(days=ttl_days)
        cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj)
            .public_key(pk.public_key()).serial_number(ser).not_valid_before(now).not_valid_after(na)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pk.public_key()), critical=False)
            .add_extension(x509.KeyUsage(True,False,False,False,False,True,True,False,False), critical=True)
            .sign(pk, hashes.SHA256(), default_backend()))
        enc_priv = encryption_service.encrypt(base64.b64encode(_priv_pem(pk).encode()).decode())
        ca = CertificateAuthority(name=name, ca_type=CertificateType.ROOT_CA, subject_dn=subject_dn,
            certificate_pem=_pem(cert), encrypted_private_key=enc_priv, serial_number=str(ser),
            not_before=now, not_after=na, key_algorithm=f"RSA-{key_size}", created_by=created_by)
        db.add(ca); await db.flush(); return ca, _pem(cert)

    @staticmethod
    async def create_intermediate_ca(db, name, subject_dn, parent_ca_id, ttl_days=1825, key_size=4096, created_by=None):
        parent = (await db.execute(select(CertificateAuthority).where(CertificateAuthority.id==parent_ca_id))).scalar_one_or_none()
        if not parent: raise HTTPException(404, "Parent CA not found")
        b64p = encryption_service.decrypt(parent.encrypted_private_key)
        parent_pk = serialization.load_pem_private_key(base64.b64decode(b64p), password=None)
        parent_cert = x509.load_pem_x509_certificate(parent.certificate_pem.encode())
        pk = _gen_key(key_size); subj = _parse_dn(subject_dn); ser = _serial()
        now = _now(); na = now + timedelta(days=ttl_days)
        cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(parent_cert.subject)
            .public_key(pk.public_key()).serial_number(ser).not_valid_before(now).not_valid_after(na)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pk.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(parent_pk.public_key()), critical=False)
            .add_extension(x509.KeyUsage(True,False,False,False,False,True,True,False,False), critical=True)
            .sign(parent_pk, hashes.SHA256(), default_backend()))
        enc_priv = encryption_service.encrypt(base64.b64encode(_priv_pem(pk).encode()).decode())
        chain = _pem(cert) + parent.certificate_pem
        ca = CertificateAuthority(name=name, ca_type=CertificateType.INTERMEDIATE_CA, parent_ca_id=parent_ca_id,
            subject_dn=subject_dn, certificate_pem=_pem(cert), encrypted_private_key=enc_priv,
            serial_number=str(ser), not_before=now, not_after=na, key_algorithm=f"RSA-{key_size}", created_by=created_by)
        db.add(ca); await db.flush(); return ca, chain

    @staticmethod
    async def issue_certificate(db, ca_id, common_name, cert_type, ttl_days=365, san_dns=None, san_ips=None, issued_to=None, created_by=None):
        ca = (await db.execute(select(CertificateAuthority).where(CertificateAuthority.id==ca_id))).scalar_one_or_none()
        if not ca or ca.status == CertificateStatus.REVOKED: raise HTTPException(404, "CA not found or revoked")
        b64p = encryption_service.decrypt(ca.encrypted_private_key)
        ca_pk = serialization.load_pem_private_key(base64.b64decode(b64p), password=None)
        ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
        pk = _gen_key(2048); subj = _parse_dn(f"CN={common_name}"); ser = _serial()
        now = _now(); na = now + timedelta(days=ttl_days)
        sans = []
        for d in (san_dns or []): sans.append(x509.DNSName(d))
        for ip in (san_ips or []):
            try: sans.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except: pass
        if not sans: sans.append(x509.DNSName(common_name))
        ekus = []
        if cert_type in (CertificateType.SERVER, CertificateType.MTLS, CertificateType.INTERNAL): ekus.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if cert_type in (CertificateType.CLIENT, CertificateType.MTLS): ekus.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        b = (x509.CertificateBuilder().subject_name(subj).issuer_name(ca_cert.subject)
            .public_key(pk.public_key()).serial_number(ser).not_valid_before(now).not_valid_after(na)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_pk.public_key()), critical=False)
            .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False), critical=True))
        if ekus: b = b.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
        cert = b.sign(ca_pk, hashes.SHA256(), default_backend())
        cert_pem = _pem(cert); chain_pem = cert_pem + ca.certificate_pem
        c = Certificate(ca_id=ca_id, cert_type=cert_type, common_name=common_name, subject_dn=f"CN={common_name}",
            san_dns=san_dns or [], san_ips=san_ips or [], certificate_pem=cert_pem, certificate_chain_pem=chain_pem,
            serial_number=str(ser), not_before=now, not_after=na, issued_to=issued_to, created_by=created_by)
        db.add(c); await db.flush(); return c, cert_pem, chain_pem

    @staticmethod
    async def revoke_certificate(db, cert_id, reason="unspecified"):
        c = (await db.execute(select(Certificate).where(Certificate.id==cert_id))).scalar_one_or_none()
        if not c: raise HTTPException(404, "Certificate not found")
        if c.status == CertificateStatus.REVOKED: raise HTTPException(400, "Already revoked")
        c.status = CertificateStatus.REVOKED; c.revoked_at = _now(); c.revocation_reason = reason
        await db.flush(); return c

    @staticmethod
    async def renew_certificate(db, cert_id, ttl_days=365, created_by=None):
        old = (await db.execute(select(Certificate).where(Certificate.id==cert_id))).scalar_one_or_none()
        if not old: raise HTTPException(404, "Certificate not found")
        new_c, cp, chain = await PKIEngine.issue_certificate(db, old.ca_id, old.common_name, old.cert_type, ttl_days, old.san_dns, old.san_ips, old.issued_to, created_by)
        new_c.renewed_from_id = cert_id; await db.flush(); return new_c, cp, chain

    @staticmethod
    async def generate_crl(db, ca_id):
        ca = (await db.execute(select(CertificateAuthority).where(CertificateAuthority.id==ca_id))).scalar_one_or_none()
        if not ca: raise HTTPException(404, "CA not found")
        b64p = encryption_service.decrypt(ca.encrypted_private_key)
        ca_pk = serialization.load_pem_private_key(base64.b64decode(b64p), password=None)
        ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
        revoked = (await db.execute(select(Certificate).where(Certificate.ca_id==ca_id, Certificate.status==CertificateStatus.REVOKED))).scalars().all()
        now = _now()
        b = x509.CertificateRevocationListBuilder().issuer_name(ca_cert.subject).last_update(now).next_update(now+timedelta(days=1))
        for rc in revoked:
            b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(int(rc.serial_number)).revocation_date(rc.revoked_at or now).build())
        return b.sign(ca_pk, hashes.SHA256(), default_backend()).public_bytes(serialization.Encoding.PEM).decode()

    @staticmethod
    async def list_cas(db): return (await db.execute(select(CertificateAuthority).order_by(CertificateAuthority.name))).scalars().all()

    @staticmethod
    async def list_certificates(db, ca_id=None, status=None):
        q = select(Certificate)
        if ca_id: q = q.where(Certificate.ca_id==ca_id)
        if status: q = q.where(Certificate.status==status)
        return (await db.execute(q.order_by(Certificate.not_after))).scalars().all()

pki_engine = PKIEngine()
