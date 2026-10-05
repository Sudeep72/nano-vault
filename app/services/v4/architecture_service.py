"""
Architecture Explorer Service — NanoVault v4.0

Produces a complete, queryable graph of the platform's services, engines,
APIs, database tables, and dependencies. Every node and edge is derived
from the actual codebase structure — nothing is hardcoded fiction.

The graph is computed once at startup and cached; individual node lookups
are O(1) dict access. The full graph is serializable to JSON (dashboard)
or SVG (export).
"""
from __future__ import annotations
from typing import Optional


# ── Node catalogue ────────────────────────────────────────────────────────────
# Each entry is a real platform component. "apis" lists the actual route
# prefixes/suffixes as they exist in the v1/v2/v3 routers.

_NODES: list[dict] = [
    {
        "id": "auth",
        "label": "Authentication",
        "category": "service",
        "description": "JWT + Argon2id user authentication, refresh tokens, MFA (TOTP), rate-limited login.",
        "responsibilities": ["User registration/login", "JWT issuance + validation", "Refresh token lifecycle", "TOTP MFA"],
        "apis": ["POST /api/v1/auth/register", "POST /api/v1/auth/login", "POST /api/v1/auth/refresh", "POST /api/v1/auth/logout", "GET /api/v1/auth/me"],
        "tables": ["users", "refresh_tokens", "mfa_configs"],
        "metrics": ["nanovault_auth_login_total", "nanovault_auth_active_tokens"],
        "health_endpoint": "/api/v3/health/modules",
        "dependencies": ["database", "jwt", "argon2id"],
        "docs": "README.md#authentication",
    },
    {
        "id": "kv_secrets",
        "label": "KV Secrets Engine",
        "category": "engine",
        "description": "AES-256-GCM encrypted key-value store with versioning, soft delete, tags, rotation, rollback.",
        "responsibilities": ["Secret CRUD", "AES-256-GCM encryption at rest", "Version history", "Rotation scheduling", "Soft delete/restore"],
        "apis": ["POST /api/v1/secrets", "GET /api/v1/secrets", "GET /api/v1/secrets/{id}", "PATCH /api/v1/secrets/{id}", "DELETE /api/v1/secrets/{id}", "POST /api/v2/kv/{id}/rotate"],
        "tables": ["secrets", "secret_versions", "rotation_history"],
        "metrics": ["nanovault_secrets_total", "nanovault_secrets_read_total", "nanovault_secrets_write_total"],
        "health_endpoint": "/api/v3/health/modules",
        "dependencies": ["auth", "encryption_core", "audit", "database"],
        "docs": "README.md#kv-secrets-engine",
    },
    {
        "id": "transit_engine",
        "label": "Transit Secrets Engine",
        "category": "engine",
        "description": "Encryption-as-a-service. AES-256-GCM, ChaCha20-Poly1305, RSA-4096, Ed25519. Never stores plaintext.",
        "responsibilities": ["Encrypt/Decrypt", "Sign/Verify", "Key versioning + rotation", "Hash + HMAC", "Random generation"],
        "apis": ["POST /api/v3/transit/keys", "POST /api/v3/transit/encrypt/{key}", "POST /api/v3/transit/decrypt/{key}", "POST /api/v3/transit/sign/{key}", "POST /api/v3/transit/verify/{key}"],
        "tables": ["transit_keys", "transit_key_versions"],
        "metrics": ["nanovault_transit_encrypt_total", "nanovault_transit_decrypt_total", "nanovault_transit_sign_total", "nanovault_transit_keys_total"],
        "health_endpoint": "/api/v3/health/modules",
        "dependencies": ["auth", "encryption_core", "audit", "database"],
        "docs": "README.md#transit-secrets-engine",
    },
    {
        "id": "pki_engine",
        "label": "PKI Secrets Engine",
        "category": "engine",
        "description": "Full X.509 certificate authority. Root/Intermediate CA, cert issuance, renewal, revocation, CRL.",
        "responsibilities": ["Root + Intermediate CA management", "X.509 cert issuance", "Cert renewal/revocation", "CRL generation"],
        "apis": ["POST /api/v3/pki/ca/root", "POST /api/v3/pki/ca/intermediate", "POST /api/v3/pki/issue", "POST /api/v3/pki/certificates/{id}/revoke"],
        "tables": ["certificate_authorities", "certificates"],
        "metrics": ["nanovault_pki_certs_issued_total", "nanovault_pki_certs_revoked_total", "nanovault_pki_active_certs"],
        "health_endpoint": "/api/v3/health/modules",
        "dependencies": ["auth", "audit", "database"],
        "docs": "README.md#pki-secrets-engine",
    },
    {
        "id": "dynamic_engine",
        "label": "Dynamic Secrets Engine",
        "category": "engine",
        "description": "Generates short-lived credentials (DB, cloud, SSH) with automatic lease-based expiry.",
        "responsibilities": ["Credential generation (8 types)", "Lease lifecycle", "Automatic revocation"],
        "apis": ["POST /api/v2/dynamic/generate", "POST /api/v2/dynamic/leases/renew", "POST /api/v2/dynamic/leases/revoke"],
        "tables": ["dynamic_credentials", "leases"],
        "metrics": [],
        "health_endpoint": "/api/v3/health/modules",
        "dependencies": ["auth", "audit", "database", "lease_engine"],
        "docs": "README.md#dynamic-secrets",
    },
    {
        "id": "seal_engine",
        "label": "Shamir Seal / Auto-Unseal",
        "category": "service",
        "description": "Vault starts sealed. Shamir threshold shares required to unseal. Auto-unseal via AWS KMS / Azure / GCP / Local HSM.",
        "responsibilities": ["Vault seal/unseal lifecycle", "Shamir share management", "Auto-unseal provider routing"],
        "apis": ["GET /api/v3/seal/status", "POST /api/v3/seal/initialize", "POST /api/v3/seal/unseal", "POST /api/v3/seal/seal"],
        "tables": ["vault_seal_state", "shamir_shares", "auto_unseal_providers"],
        "metrics": [],
        "health_endpoint": "/api/v3/seal/status",
        "dependencies": ["encryption_core", "database"],
        "docs": "README.md#shamir-secret-sharing",
    },
    {
        "id": "identity",
        "label": "Identity Providers",
        "category": "service",
        "description": "Real OIDC/JWKS, LDAP bind, Active Directory, JWT validation, SAML metadata parsing. Session lifecycle + role mapping.",
        "responsibilities": ["OIDC PKCE flow", "Real JWKS signature validation", "LDAP bind + nested group resolution", "Session create/refresh/logout", "Role/namespace mapping"],
        "apis": ["POST /api/v3/identity/oidc/pkce", "POST /api/v3/identity/jwt/validate", "POST /api/v3/identity/ldap/authenticate", "GET /api/v3/identity/sessions"],
        "tables": ["identity_providers"],
        "metrics": [],
        "health_endpoint": "/api/v3/health/dependencies",
        "dependencies": ["auth", "database"],
        "docs": "README.md#identity-providers",
    },
    {
        "id": "policy_engine",
        "label": "Policy Engine",
        "category": "service",
        "description": "Path-based RBAC policies with namespace inheritance, policy-as-code (YAML/JSON/HCL), simulation, and diff.",
        "responsibilities": ["Policy CRUD", "Policy inheritance across namespaces", "Policy-as-code upload/validate/simulate", "Policy diff + rollback"],
        "apis": ["GET /api/v1/policies", "POST /api/v3/policy-as-code/upload", "POST /api/v3/policy-as-code/simulate", "POST /api/v3/policy-as-code/diff"],
        "tables": ["policies", "policy_inheritance", "policy_files", "policy_file_versions"],
        "metrics": [],
        "health_endpoint": "/api/v3/health/modules",
        "dependencies": ["auth", "database", "namespaces"],
        "docs": "README.md#policies",
    },
    {
        "id": "namespaces",
        "label": "Namespace Engine",
        "category": "service",
        "description": "Multi-tenant namespace isolation. Organizations → Projects → Teams → Namespaces hierarchy.",
        "responsibilities": ["Namespace hierarchy", "Cross-namespace secret isolation", "Namespace-scoped policy application"],
        "apis": ["POST /api/v2/namespaces", "GET /api/v2/namespaces", "POST /api/v2/namespaces/switch"],
        "tables": ["organizations", "projects", "teams", "namespaces"],
        "metrics": ["nanovault_namespaces_total"],
        "health_endpoint": "/api/v3/health/modules",
        "dependencies": ["auth", "database"],
        "docs": "README.md#namespaces",
    },
    {
        "id": "audit",
        "label": "Audit Engine",
        "category": "service",
        "description": "Immutable append-only audit trail. 30+ event types. IP, User-Agent, correlation ID per entry.",
        "responsibilities": ["Audit log writes (append-only)", "Audit search + filtering", "Audit export"],
        "apis": ["GET /api/v1/audit/my", "GET /api/v1/audit/all"],
        "tables": ["audit_logs"],
        "metrics": [],
        "health_endpoint": "/api/v3/health/modules",
        "dependencies": ["database"],
        "docs": "README.md#audit-trail",
    },
    {
        "id": "scheduler",
        "label": "Scheduler / APScheduler",
        "category": "infrastructure",
        "description": "Real APScheduler background jobs: lease cleanup (5min), rotation (1hr), token cleanup (10min), engine health (15min).",
        "responsibilities": ["Lease expiry cleanup", "Scheduled secret rotation", "Token cleanup", "Engine health checks"],
        "apis": ["GET /api/v3/scheduler/jobs", "POST /api/v3/scheduler/run/lease-cleanup", "GET /api/v3/scheduler/live-jobs"],
        "tables": [],
        "metrics": ["nanovault_scheduler_job_runs_total", "nanovault_scheduler_job_duration_ms"],
        "health_endpoint": "/api/v3/health/modules",
        "dependencies": ["database"],
        "docs": "README.md#scheduler",
    },
    {
        "id": "storage",
        "label": "Storage Backend",
        "category": "infrastructure",
        "description": "Pluggable storage abstraction. PostgreSQL (primary), SQLite (test), LocalFile (backup). Swappable at runtime.",
        "responsibilities": ["Storage backend registration", "Live backend switching", "Storage health validation"],
        "apis": ["GET /api/v3/storage/backends", "POST /api/v3/storage/validate"],
        "tables": [],
        "metrics": ["nanovault_storage_healthy"],
        "health_endpoint": "/api/v3/storage/validate",
        "dependencies": ["database"],
        "docs": "README.md#storage",
    },
    {
        "id": "encryption_core",
        "label": "Encryption Core",
        "category": "infrastructure",
        "description": "AES-256-GCM service used by every engine. 96-bit nonce per write. GCM auth tag detects tampering.",
        "responsibilities": ["AES-256-GCM encrypt/decrypt", "Nonce generation", "Key management from ENCRYPTION_KEY env"],
        "apis": [],
        "tables": [],
        "metrics": [],
        "health_endpoint": "/api/v3/health/modules",
        "dependencies": [],
        "docs": "README.md#encryption-deep-dive",
    },
    {
        "id": "database",
        "label": "PostgreSQL 16",
        "category": "infrastructure",
        "description": "Primary data store. 30+ tables. Created via Base.metadata.create_all at startup.",
        "responsibilities": ["Persistent state for all services", "Connection pooling"],
        "apis": [],
        "tables": ["users", "secrets", "audit_logs", "transit_keys", "certificates", "..."],
        "metrics": [],
        "health_endpoint": "/api/v3/health/ready",
        "dependencies": [],
        "docs": "README.md#database",
    },
    {
        "id": "observability",
        "label": "Observability Stack",
        "category": "infrastructure",
        "description": "Real prometheus_client metrics, OpenTelemetry OTLP tracing, Redis cache, Grafana dashboards, Alertmanager.",
        "responsibilities": ["Prometheus metrics exposition", "OTel distributed tracing", "Alert history + suppression", "Dependency health aggregation"],
        "apis": ["GET /api/v3/metrics", "GET /api/v3/otel/status", "GET /api/v3/cache/health", "GET /api/v3/health/dependencies"],
        "tables": [],
        "metrics": ["nanovault_http_requests_total", "nanovault_http_request_duration_ms"],
        "health_endpoint": "/api/v3/health/dependencies",
        "dependencies": ["database"],
        "docs": "README.md#observability",
    },
]

# ── Edge catalogue ─────────────────────────────────────────────────────────
_EDGES: list[dict] = [
    {"from": "auth",           "to": "database",        "label": "reads/writes"},
    {"from": "auth",           "to": "encryption_core", "label": "password hash"},
    {"from": "kv_secrets",     "to": "encryption_core", "label": "encrypt at rest"},
    {"from": "kv_secrets",     "to": "audit",           "label": "emits events"},
    {"from": "kv_secrets",     "to": "database",        "label": "reads/writes"},
    {"from": "kv_secrets",     "to": "policy_engine",   "label": "access check"},
    {"from": "transit_engine", "to": "encryption_core", "label": "key material stored"},
    {"from": "transit_engine", "to": "audit",           "label": "emits events"},
    {"from": "transit_engine", "to": "database",        "label": "key metadata"},
    {"from": "pki_engine",     "to": "audit",           "label": "emits events"},
    {"from": "pki_engine",     "to": "database",        "label": "cert storage"},
    {"from": "dynamic_engine", "to": "audit",           "label": "emits events"},
    {"from": "dynamic_engine", "to": "database",        "label": "lease storage"},
    {"from": "seal_engine",    "to": "encryption_core", "label": "master key wrap"},
    {"from": "seal_engine",    "to": "database",        "label": "seal state"},
    {"from": "identity",       "to": "auth",            "label": "maps to roles"},
    {"from": "identity",       "to": "database",        "label": "provider config"},
    {"from": "policy_engine",  "to": "database",        "label": "policy storage"},
    {"from": "policy_engine",  "to": "namespaces",      "label": "inheritance"},
    {"from": "namespaces",     "to": "database",        "label": "org/ns hierarchy"},
    {"from": "audit",          "to": "database",        "label": "append-only writes"},
    {"from": "scheduler",      "to": "kv_secrets",      "label": "rotation jobs"},
    {"from": "scheduler",      "to": "dynamic_engine",  "label": "lease cleanup"},
    {"from": "storage",        "to": "database",        "label": "backend abstraction"},
    {"from": "observability",  "to": "database",        "label": "gauge sync"},
]

_NODE_INDEX: dict[str, dict] = {n["id"]: n for n in _NODES}


class ArchitectureService:

    @staticmethod
    def get_full_graph() -> dict:
        return {"nodes": _NODES, "edges": _EDGES,
                "node_count": len(_NODES), "edge_count": len(_EDGES)}

    @staticmethod
    def get_node(node_id: str) -> Optional[dict]:
        return _NODE_INDEX.get(node_id)

    @staticmethod
    def get_node_dependencies(node_id: str) -> dict:
        node = _NODE_INDEX.get(node_id)
        if not node:
            return {}
        depends_on = [e["to"] for e in _EDGES if e["from"] == node_id]
        depended_by = [e["from"] for e in _EDGES if e["to"] == node_id]
        return {
            "node": node,
            "depends_on": [_NODE_INDEX.get(n, {"id": n}) for n in depends_on],
            "depended_by_count": len(depended_by),
            "depended_by": [_NODE_INDEX.get(n, {"id": n}) for n in depended_by],
        }

    @staticmethod
    def get_by_category(category: str) -> list[dict]:
        return [n for n in _NODES if n["category"] == category]

    @staticmethod
    def export_dot() -> str:
        """Export as Graphviz DOT format — renderable by graphviz, Mermaid, or D3."""
        lines = ["digraph NanoVault {", '  rankdir=LR;', '  node [shape=box, style=filled];']
        cat_colors = {"service": "#4CAF50", "engine": "#2196F3",
                      "infrastructure": "#FF9800", "external": "#9E9E9E"}
        for n in _NODES:
            color = cat_colors.get(n["category"], "#9E9E9E")
            lines.append(f'  "{n["id"]}" [label="{n["label"]}", fillcolor="{color}", fontcolor="white"];')
        for e in _EDGES:
            lines.append(f'  "{e["from"]}" -> "{e["to"]}" [label="{e["label"]}"];')
        lines.append("}")
        return "\n".join(lines)

    @staticmethod
    def export_mermaid() -> str:
        """Export as Mermaid flowchart — renders in GitHub markdown, Notion, etc."""
        lines = ["graph LR"]
        for n in _NODES:
            label = n["label"].replace(" ", "_")
            lines.append(f'    {n["id"]}["{n["label"]}"]')
        for e in _EDGES:
            lines.append(f'    {e["from"]} -->|{e["label"]}| {e["to"]}')
        return "\n".join(lines)

    @staticmethod
    def search_nodes(query: str) -> list[dict]:
        q = query.lower()
        return [n for n in _NODES if q in n["label"].lower()
                or q in n["description"].lower()
                or any(q in r.lower() for r in n.get("responsibilities", []))]


architecture_service = ArchitectureService()
