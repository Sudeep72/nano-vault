"""Real Prometheus metrics — NanoVault v3.0 Completion. Uses official prometheus_client."""
from __future__ import annotations
from prometheus_client import Counter, Histogram, Gauge, CONTENT_TYPE_LATEST, generate_latest, CollectorRegistry

registry = CollectorRegistry()

# Authentication
auth_login_total = Counter("nanovault_auth_login_total", "Total login attempts", ["result"], registry=registry)
auth_active_tokens = Gauge("nanovault_auth_active_tokens", "Active vault tokens", registry=registry)
auth_mfa_verifications = Counter("nanovault_auth_mfa_verifications_total", "MFA verifications", registry=registry)

# Secrets
secrets_total = Gauge("nanovault_secrets_total", "Total secrets", registry=registry)
secrets_read_total = Counter("nanovault_secrets_read_total", "Secret read operations", registry=registry)
secrets_write_total = Counter("nanovault_secrets_write_total", "Secret write operations", registry=registry)

# Transit
transit_encrypt_total = Counter("nanovault_transit_encrypt_total", "Transit encrypt ops", ["key_type"], registry=registry)
transit_decrypt_total = Counter("nanovault_transit_decrypt_total", "Transit decrypt ops", ["key_type"], registry=registry)
transit_sign_total = Counter("nanovault_transit_sign_total", "Transit sign ops", registry=registry)
transit_keys_total = Gauge("nanovault_transit_keys_total", "Total transit keys", registry=registry)

# PKI
pki_certs_issued_total = Counter("nanovault_pki_certs_issued_total", "Certificates issued", ["cert_type"], registry=registry)
pki_certs_revoked_total = Counter("nanovault_pki_certs_revoked_total", "Certificates revoked", registry=registry)
pki_active_certs = Gauge("nanovault_pki_active_certs", "Active valid certificates", registry=registry)

# Engines
engine_operations_total = Counter("nanovault_engine_operations_total", "Engine operations", ["engine", "op"], registry=registry)
engines_mounted = Gauge("nanovault_engines_mounted", "Currently mounted engines", registry=registry)

# Storage
storage_health = Gauge("nanovault_storage_healthy", "Storage backend health (1=healthy)", registry=registry)

# Scheduler
scheduler_job_runs_total = Counter("nanovault_scheduler_job_runs_total", "Scheduler job runs", ["job_type", "status"], registry=registry)
scheduler_job_duration_ms = Histogram("nanovault_scheduler_job_duration_ms", "Scheduler job duration", ["job_type"], registry=registry)

# Namespaces
namespaces_total = Gauge("nanovault_namespaces_total", "Total namespaces", registry=registry)

# HTTP requests
http_requests_total = Counter("nanovault_http_requests_total", "HTTP requests", ["method", "path", "status"], registry=registry)
http_request_duration_ms = Histogram("nanovault_http_request_duration_ms", "HTTP request duration", ["method", "path"], registry=registry)


async def sync_gauges_from_db(db) -> None:
    """Periodically sync gauge metrics from DB state."""
    from sqlalchemy import select, func
    from app.models.models import (
        Secret, TransitKey, Certificate, CertificateStatus,
        VaultToken, TokenStatus, EngineMount, EngineStatus, Namespace,
    )

    async def cnt(model, *cond):
        q = select(func.count()).select_from(model)
        for c in cond: q = q.where(c)
        return (await db.execute(q)).scalar_one()

    secrets_total.set(await cnt(Secret, Secret.is_deleted == False))  # noqa
    transit_keys_total.set(await cnt(TransitKey))
    pki_active_certs.set(await cnt(Certificate, Certificate.status == CertificateStatus.VALID))
    auth_active_tokens.set(await cnt(VaultToken, VaultToken.status == TokenStatus.ACTIVE))
    engines_mounted.set(await cnt(EngineMount, EngineMount.status == EngineStatus.MOUNTED))
    namespaces_total.set(await cnt(Namespace))
    storage_health.set(1)


def render_metrics() -> bytes:
    return generate_latest(registry)
