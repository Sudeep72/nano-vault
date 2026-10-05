"""Pass 2 Final Completion endpoints — Identity sessions, LDAP sync, replication queue, backup restore, alerting."""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok, created

router = APIRouter(tags=["Enterprise Completion Pass 2"])


# ── Identity sessions ──────────────────────────────────────────────────────────

class RefreshRequest(BaseModel):
    session_id: str
    token_endpoint: str
    client_id: str
    client_secret: str

class LogoutRequest(BaseModel):
    session_id: str
    end_session_endpoint: Optional[str] = None

class RoleMappingRequest(BaseModel):
    claims: dict
    group_mappings: dict
    role_mappings: dict
    namespace_mappings: dict


@router.get("/identity/sessions", summary="List active identity sessions [Admin]")
async def list_sessions(_=Depends(require_admin)):
    from app.services.v3.identity_session_service import identity_session_service
    return ok(identity_session_service.list_active_sessions(), "Active sessions")


@router.get("/identity/sessions/{session_id}/validate", summary="Validate a session")
async def validate_session(session_id: str, _=Depends(get_current_user)):
    from app.services.v3.identity_session_service import identity_session_service
    return ok(identity_session_service.validate_session(session_id), "Session valid")


@router.post("/identity/sessions/refresh", summary="Refresh an OIDC session's access token")
async def refresh_session(body: RefreshRequest, _=Depends(get_current_user)):
    from app.services.v3.identity_session_service import identity_session_service
    return ok(identity_session_service.refresh_session(
        body.session_id, body.token_endpoint, body.client_id, body.client_secret
    ), "Session refreshed")


@router.post("/identity/sessions/logout", summary="Logout a session (local + optional IdP)")
async def logout_session(body: LogoutRequest, _=Depends(get_current_user)):
    from app.services.v3.identity_session_service import identity_session_service
    return ok(identity_session_service.logout(body.session_id, body.end_session_endpoint), "Logged out")


@router.post("/identity/role-mapping/apply", summary="Apply group/role/namespace mapping to IdP claims")
async def apply_role_mapping(body: RoleMappingRequest, _=Depends(get_current_user)):
    from app.services.v3.identity_session_service import identity_session_service
    return ok(identity_session_service.apply_role_mapping(
        body.claims, body.group_mappings, body.role_mappings, body.namespace_mappings
    ), "Role mapping applied")


@router.get("/identity/jwks/{issuer:path}", summary="Fetch (cached) JWKS for an issuer")
async def get_jwks(issuer: str, jwks_url: str, force_refresh: bool = False, _=Depends(get_current_user)):
    from app.services.v3.identity_session_service import identity_session_service
    return ok(identity_session_service.get_jwks(issuer, jwks_url, force_refresh), "JWKS retrieved")


@router.get("/identity/jwks/cached/issuers", summary="List all cached JWKS issuers [Admin]")
async def list_cached_issuers(_=Depends(require_admin)):
    from app.services.v3.identity_session_service import identity_session_service
    return ok(identity_session_service.list_cached_issuers(), "Cached issuers")


# ── LDAP sync ──────────────────────────────────────────────────────────────────

class LDAPSyncConfigRequest(BaseModel):
    provider_name: str
    ldap_url: str
    bind_dn: str
    bind_password: str
    user_search_base: str
    group_search_base: str
    interval_minutes: int = 30

@router.post("/identity/ldap/sync-now", summary="Trigger an immediate LDAP sync [Admin]")
async def ldap_sync_now(body: LDAPSyncConfigRequest, _=Depends(require_admin)):
    from app.services.v3.ldap_sync_service import ldap_sync_service
    return ok(ldap_sync_service.sync_now(
        body.provider_name, body.ldap_url, body.bind_dn, body.bind_password,
        body.user_search_base, body.group_search_base,
    ), "LDAP sync complete")


@router.post("/identity/ldap/schedule-sync", summary="Register periodic LDAP sync job [Admin]")
async def ldap_schedule_sync(body: LDAPSyncConfigRequest, _=Depends(require_admin)):
    from app.services.v3.ldap_sync_service import ldap_sync_service
    config = body.model_dump()
    return ok(ldap_sync_service.schedule_periodic_sync(body.provider_name, config, body.interval_minutes),
              "Periodic sync scheduled")


@router.get("/identity/ldap/sync-status", summary="Get last sync status for all LDAP providers [Admin]")
async def ldap_sync_status(_=Depends(require_admin)):
    from app.services.v3.ldap_sync_service import ldap_sync_service
    return ok(ldap_sync_service.get_all_sync_status(), "LDAP sync status")


# ── Replication queue ────────────────────────────────────────────────────────

@router.post("/replication/queue/replicate", summary="Replicate a write across all simulated nodes [Admin]")
async def queue_replicate(from_node: str, resource: str, payload: dict, _=Depends(require_admin)):
    from app.services.v3.replication_queue_service import replication_queue_manager
    return ok(replication_queue_manager.replicate(from_node, resource, payload), "Replication executed")


@router.get("/replication/queue/metrics", summary="Per-node replication metrics")
async def queue_metrics(_=Depends(get_current_user)):
    from app.services.v3.replication_queue_service import replication_queue_manager
    return ok(replication_queue_manager.get_all_metrics(), "Replication metrics")


@router.get("/replication/queue/audit/{node_name}", summary="Replication audit trail for a node")
async def queue_audit(node_name: str, limit: int = 50, _=Depends(get_current_user)):
    from app.services.v3.replication_queue_service import replication_queue_manager
    return ok(replication_queue_manager.get_audit_trail(node_name, limit), "Audit trail")


# ── Backup restore completion ──────────────────────────────────────────────────

class PartialRestoreRequest(BaseModel):
    backup_id: str
    resource_types: list[str]
    secret_keys: Optional[list[str]] = None
    confirm: bool = False

class ScheduleBackupRequest(BaseModel):
    backup_type: str = "full"
    interval_hours: int = 24


@router.post("/backup/v2/{backup_id}/dry-run", summary="Dry-run restore — reports diff without writing [Admin]")
async def dry_run_restore(backup_id: str, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    from app.services.v3.backup_restore_service import backup_restore_service
    return ok(await backup_restore_service.dry_run_restore(db, backup_id), "Dry run complete")


@router.post("/backup/v2/partial-restore", summary="Selective restore of specific resource types/keys [Admin]")
async def partial_restore(body: PartialRestoreRequest, db: AsyncSession = Depends(get_db), _=Depends(require_admin)):
    from app.services.v3.backup_restore_service import backup_restore_service
    result = await backup_restore_service.partial_restore(
        db, body.backup_id, body.resource_types, body.secret_keys, body.confirm
    )
    return created(result, "Partial restore complete" if body.confirm else "Partial restore preview (not confirmed)")


@router.get("/backup/v2/restore-progress/{restore_id}", summary="Check restore job progress")
async def restore_progress(restore_id: str, _=Depends(require_admin)):
    from app.services.v3.backup_restore_service import backup_restore_service
    return ok(backup_restore_service.get_restore_progress(restore_id), "Restore progress")


@router.post("/backup/v2/{backup_id}/validate-before-restore", summary="Pre-restore validation gate [Admin]")
async def validate_before_restore(backup_id: str, _=Depends(require_admin)):
    from app.services.v3.backup_restore_service import backup_restore_service
    return ok(backup_restore_service.validate_before_restore(backup_id), "Pre-restore validation complete")


@router.post("/backup/v2/schedule", summary="Register a periodic backup job [Admin]")
async def schedule_backup(body: ScheduleBackupRequest, _=Depends(require_admin)):
    from app.services.v3.backup_restore_service import backup_restore_service
    return ok(backup_restore_service.schedule_backup(body.backup_type, body.interval_hours), "Backup scheduled")


# ── Alerting ────────────────────────────────────────────────────────────────────

class SuppressRequest(BaseModel):
    alert_name: str
    duration_minutes: int
    reason: str

@router.get("/alerts/history", summary="Alert history")
async def alert_history(limit: int = 50, severity: Optional[str] = None, _=Depends(get_current_user)):
    from app.services.v3.alerting_service import alerting_service
    return ok(alerting_service.get_history(limit, severity), "Alert history")


@router.post("/alerts/suppress", summary="Suppress an alert for a time window [Admin]")
async def alert_suppress(body: SuppressRequest, _=Depends(require_admin)):
    from app.services.v3.alerting_service import alerting_service
    return ok(alerting_service.suppress(body.alert_name, body.duration_minutes, body.reason), "Alert suppressed")


@router.post("/alerts/unsuppress/{alert_name}", summary="Remove a suppression [Admin]")
async def alert_unsuppress(alert_name: str, _=Depends(require_admin)):
    from app.services.v3.alerting_service import alerting_service
    return ok(alerting_service.unsuppress(alert_name), "Suppression removed")


@router.get("/alerts/suppressions", summary="List active suppressions [Admin]")
async def alert_suppressions(_=Depends(require_admin)):
    from app.services.v3.alerting_service import alerting_service
    return ok(alerting_service.get_active_suppressions(), "Active suppressions")


@router.post("/alerts/webhook", summary="Alertmanager webhook receiver")
async def alerts_webhook(payload: dict):
    from app.services.v3.alerting_service import alerting_service
    alerts = payload.get("alerts", [])
    results = []
    for a in alerts:
        name = a.get("labels", {}).get("alertname", "unknown")
        severity = a.get("labels", {}).get("severity", "info")
        message = a.get("annotations", {}).get("summary", "")
        results.append(alerting_service.fire_alert(name, severity, message, a.get("labels", {})))
    return ok({"processed": len(results)}, "Webhook processed")


@router.get("/health/dependencies", summary="Full dependency-health graph across every subsystem")
async def dependency_health(db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.services.v3.alerting_service import alerting_service
    return ok(await alerting_service.get_dependency_health(db), "Dependency health")
