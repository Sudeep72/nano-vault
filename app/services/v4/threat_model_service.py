"""
Threat Modeling Dashboard — NanoVault v4.0

Structures the real STRIDE analysis already documented in THREAT_MODEL.md
into a queryable data model, and maps each mitigation to the actual code
location that implements it — plus OWASP ASVS / NIST CSF / MITRE ATT&CK /
CIS Controls references. This is documentation-as-data, not fiction —
every "mitigation" entry names a real file/function in this codebase.
"""
from __future__ import annotations

FLOW_STAGES = ["User", "Authentication", "Authorization", "Secrets", "Transit", "PKI", "Storage", "Audit"]

_THREATS: list[dict] = [
    {
        "id": "spoofing_credentials",
        "stride_category": "Spoofing",
        "stage": "Authentication",
        "asset": "User credentials, JWT tokens",
        "threat": "Attacker impersonates a legitimate user via stolen/brute-forced credentials or forged tokens.",
        "attack_vectors": ["Credential stuffing", "Brute force login", "JWT token forgery", "Session hijacking"],
        "mitigations": [
            {"control": "Argon2id password hashing", "location": "app/core/security.py"},
            {"control": "HS256 JWT with type+jti claims", "location": "app/core/security.py"},
            {"control": "Rate limiting on auth endpoints (10/min)", "location": "app/main.py — slowapi"},
            {"control": "Brute-force lockout (5 attempts/5min sliding window)", "location": "app/middleware/hardening.py"},
        ],
        "owasp_asvs": ["V2.1 Password Security", "V3.2 Session Binding"],
        "nist_csf": ["PR.AC-1", "PR.AC-7"],
        "mitre_attack": ["T1110 Brute Force", "T1556 Modify Authentication Process"],
        "cis_controls": ["CIS 6 - Access Control Management"],
    },
    {
        "id": "tampering_secrets",
        "stride_category": "Tampering",
        "stage": "Secrets",
        "asset": "Encrypted secret values at rest",
        "threat": "Attacker with DB access modifies ciphertext to corrupt or manipulate stored secrets.",
        "attack_vectors": ["Direct DB write", "SQL injection", "Ciphertext bit-flipping"],
        "mitigations": [
            {"control": "AES-256-GCM authentication tag detects any ciphertext modification", "location": "app/core/encryption.py"},
            {"control": "SQLAlchemy parameterized queries prevent SQL injection", "location": "app/services/*"},
            {"control": "Immutable audit trail records every write", "location": "app/services/audit_service.py"},
        ],
        "owasp_asvs": ["V6.2 Algorithms", "V9.1 Client Communication Security"],
        "nist_csf": ["PR.DS-1", "PR.DS-6"],
        "mitre_attack": ["T1565 Data Manipulation"],
        "cis_controls": ["CIS 3 - Data Protection"],
    },
    {
        "id": "repudiation_actions",
        "stride_category": "Repudiation",
        "stage": "Audit",
        "asset": "Audit trail integrity",
        "threat": "User denies performing an action; no reliable record exists to prove otherwise.",
        "attack_vectors": ["Audit log deletion", "Missing log entries for failed actions"],
        "mitigations": [
            {"control": "Append-only audit_logs table — no UPDATE/DELETE in app logic", "location": "app/models/models.py — AuditLog"},
            {"control": "USER_LOGIN_FAILED written before returning 401", "location": "app/services/auth_service.py"},
            {"control": "Correlation ID + request ID on every log line", "location": "app/middleware/structured_logging.py"},
        ],
        "owasp_asvs": ["V7.1 Log Content"],
        "nist_csf": ["PR.PT-1", "DE.AE-3"],
        "mitre_attack": ["T1070 Indicator Removal"],
        "cis_controls": ["CIS 8 - Audit Log Management"],
    },
    {
        "id": "info_disclosure_enum",
        "stride_category": "Information Disclosure",
        "stage": "Secrets",
        "asset": "Secret existence, other users' resources",
        "threat": "Attacker enumerates valid secret IDs or infers existence of other users' data via response differences.",
        "attack_vectors": ["ID enumeration", "Timing side-channel", "Error message differences"],
        "mitigations": [
            {"control": "404 (not 403) on other users' secrets — no enumeration leak", "location": "app/services/secret_service.py"},
            {"control": "List endpoint never returns decrypted 'value' field", "location": "app/schemas/schemas.py"},
            {"control": "Generic 500 errors — no stack traces or internal paths to client", "location": "app/main.py exception handlers"},
        ],
        "owasp_asvs": ["V4.3 Other Access Control Considerations", "V7.4 Error Handling"],
        "nist_csf": ["PR.DS-5"],
        "mitre_attack": ["T1087 Account Discovery"],
        "cis_controls": ["CIS 3 - Data Protection"],
    },
    {
        "id": "dos_rate",
        "stride_category": "Denial of Service",
        "stage": "Authorization",
        "asset": "API availability",
        "threat": "Attacker floods the API to exhaust connections or CPU (e.g. RSA-4096 key generation).",
        "attack_vectors": ["Request flooding", "Expensive-operation abuse (RSA key gen, PKI issuance)"],
        "mitigations": [
            {"control": "slowapi rate limiting — 60 req/min global, 10 req/min auth", "location": "app/main.py"},
            {"control": "SQLAlchemy connection pool (10/20 overflow) prevents connection exhaustion", "location": "app/db/session.py"},
            {"control": "Request size limits", "location": "app/middleware/security.py — RequestSizeLimitMiddleware"},
        ],
        "owasp_asvs": ["V13.1 Generic Web Service Security"],
        "nist_csf": ["PR.PT-4"],
        "mitre_attack": ["T1499 Endpoint Denial of Service"],
        "cis_controls": ["CIS 13 - Network Monitoring"],
    },
    {
        "id": "elevation_admin",
        "stride_category": "Elevation of Privilege",
        "stage": "Authorization",
        "asset": "Admin-only operations (PKI CA creation, user management, seal control)",
        "threat": "Non-admin user accesses admin-only endpoints (e.g. Root CA creation, vault seal control).",
        "attack_vectors": ["Missing authorization check", "IDOR on admin routes", "Privilege escalation via policy misconfiguration"],
        "mitigations": [
            {"control": "require_admin dependency on every admin route", "location": "app/core/dependencies.py"},
            {"control": "owner_id filter enforced on all secret queries", "location": "app/services/secret_service.py"},
            {"control": "Policy engine evaluates every request against RBAC rules", "location": "app/services/policy_service.py"},
        ],
        "owasp_asvs": ["V4.1 General Access Control Design"],
        "nist_csf": ["PR.AC-4"],
        "mitre_attack": ["T1078 Valid Accounts", "T1548 Abuse Elevation Control Mechanism"],
        "cis_controls": ["CIS 6 - Access Control Management"],
    },
    {
        "id": "transit_key_exposure",
        "stride_category": "Information Disclosure",
        "stage": "Transit",
        "asset": "Transit encryption key material",
        "threat": "Key material is exported or leaked, allowing decryption of all data protected by that key.",
        "attack_vectors": ["Unauthorized key export", "Key material in logs"],
        "mitigations": [
            {"control": "Keys default to non-exportable; export requires explicit exportable=true + admin", "location": "app/engines/transit/engine.py"},
            {"control": "Key material always encrypted at rest under ENCRYPTION_KEY", "location": "app/engines/transit/engine.py"},
            {"control": "Secret redaction regex strips key-shaped values from logs", "location": "app/middleware/hardening.py"},
        ],
        "owasp_asvs": ["V6.4 Secret Management"],
        "nist_csf": ["PR.DS-1"],
        "mitre_attack": ["T1552 Unsecured Credentials"],
        "cis_controls": ["CIS 3 - Data Protection"],
    },
    {
        "id": "pki_ca_compromise",
        "stride_category": "Tampering",
        "stage": "PKI",
        "asset": "Certificate Authority private keys",
        "threat": "CA private key compromise allows attacker to issue arbitrary trusted certificates.",
        "attack_vectors": ["CA private key theft", "Unauthorized intermediate CA creation"],
        "mitigations": [
            {"control": "CA private keys encrypted at rest, never returned in API responses", "location": "app/engines/pki/engine.py"},
            {"control": "CA creation is admin-only", "location": "app/api/v3/endpoints/pki.py"},
            {"control": "CRL generation allows rapid revocation of compromised certs", "location": "app/engines/pki/engine.py"},
        ],
        "owasp_asvs": ["V6.4 Secret Management"],
        "nist_csf": ["PR.DS-1", "PR.AC-4"],
        "mitre_attack": ["T1649 Steal or Forge Authentication Certificates"],
        "cis_controls": ["CIS 3 - Data Protection"],
    },
]


class ThreatModelService:

    @staticmethod
    def get_flow() -> dict:
        return {"stages": FLOW_STAGES,
                "flow": " → ".join(FLOW_STAGES)}

    @staticmethod
    def get_all_threats() -> list[dict]:
        return _THREATS

    @staticmethod
    def get_threats_by_stage(stage: str) -> list[dict]:
        return [t for t in _THREATS if t["stage"].lower() == stage.lower()]

    @staticmethod
    def get_threats_by_stride(category: str) -> list[dict]:
        return [t for t in _THREATS if t["stride_category"].lower() == category.lower()]

    @staticmethod
    def get_threat(threat_id: str) -> dict | None:
        return next((t for t in _THREATS if t["id"] == threat_id), None)

    @staticmethod
    def get_coverage_summary() -> dict:
        stride_counts: dict[str, int] = {}
        stage_counts: dict[str, int] = {}
        for t in _THREATS:
            stride_counts[t["stride_category"]] = stride_counts.get(t["stride_category"], 0) + 1
            stage_counts[t["stage"]] = stage_counts.get(t["stage"], 0) + 1
        return {
            "total_threats": len(_THREATS),
            "by_stride_category": stride_counts,
            "by_stage": stage_counts,
            "total_mitigations": sum(len(t["mitigations"]) for t in _THREATS),
        }

    @staticmethod
    def export_markdown() -> str:
        lines = ["# NanoVault Threat Model — STRIDE Analysis\n", f"Flow: {' → '.join(FLOW_STAGES)}\n"]
        for t in _THREATS:
            lines.append(f"## {t['stride_category']}: {t['id']}")
            lines.append(f"**Stage:** {t['stage']}  \n**Asset:** {t['asset']}\n")
            lines.append(f"**Threat:** {t['threat']}\n")
            lines.append("**Mitigations:**")
            for m in t["mitigations"]:
                lines.append(f"- {m['control']} (`{m['location']}`)")
            lines.append(f"\n**OWASP ASVS:** {', '.join(t['owasp_asvs'])}")
            lines.append(f"**NIST CSF:** {', '.join(t['nist_csf'])}")
            lines.append(f"**MITRE ATT&CK:** {', '.join(t['mitre_attack'])}\n")
        return "\n".join(lines)


threat_model_service = ThreatModelService()
