# NanoVault Threat Model

**System**: NanoVault v1 — KV Secrets Management Platform  
**Method**: STRIDE  
**Date**: 2025-06

---

## 1. System Overview

NanoVault is a REST API that stores encrypted key-value secrets per authenticated user. Components:

```
Client → [Rate Limiter] → FastAPI → [RBAC Policy] → Services → PostgreSQL
                                          ↕
                               AES-256-GCM Encryption Service
                                          ↕
                                      Audit Log
```

**Trust Boundaries**
- External clients (untrusted) ↔ API gateway
- API process (trusted) ↔ PostgreSQL (trusted, internal)
- Admin role ↔ regular user role

---

## 2. Assets

| Asset | Sensitivity | Location |
|---|---|---|
| Secret plaintext values | Critical | In-memory only during request |
| AES-256-GCM ENCRYPTION_KEY | Critical | Env var / secrets manager |
| JWT signing keys | High | Env var |
| Hashed passwords (Argon2id) | High | PostgreSQL |
| Encrypted secret blobs | Medium | PostgreSQL |
| Audit logs | Medium | PostgreSQL |

---

## 3. STRIDE Analysis

### 3.1 Spoofing (Identity)

| Threat | Mitigation |
|---|---|
| Attacker forges JWT | HS256 signing with 256-bit secret; `type` claim validates access vs refresh token |
| Stolen refresh token reuse | Token stored as SHA-256 hash only; revoke-on-logout; expiry enforced in DB |
| Brute force login | Rate limiting (10 req/min on auth routes); Argon2id with time cost |
| Session fixation | New token pair issued on each login; old refresh tokens not automatically invalidated (TODO: family-based rotation) |

**Residual Risk**: Single-device logout does not invalidate all sessions. Recommended: add `session_id` to access token and track active sessions.

---

### 3.2 Tampering (Integrity)

| Threat | Mitigation |
|---|---|
| Attacker modifies encrypted blob in DB | AES-256-GCM authentication tag detects any bit flip; decryption raises exception |
| SQL injection | SQLAlchemy ORM with parameterized queries; no raw SQL |
| Mass assignment / over-posting | Pydantic schemas with explicit field declarations; no wildcard binding |
| Request body manipulation | Pydantic validators enforce key length, password strength, tag limits |

**Residual Risk**: GCM nonce collision (birthday paradox at 2^32 encryptions per key). Recommended: rotate ENCRYPTION_KEY periodically or use envelope encryption with per-secret DEKs.

---

### 3.3 Repudiation (Non-repudiation)

| Threat | Mitigation |
|---|---|
| User denies reading a secret | Immutable `audit_logs` row created on every SECRET_READ, includes IP + user agent |
| User denies failed login attempt | `USER_LOGIN_FAILED` written before raising 401 |
| Admin denies bulk actions | All admin routes log to audit trail |

**Residual Risk**: Audit logs stored in same DB — a compromised DB admin could delete logs. Recommended: stream audit logs to an append-only external sink (Kafka, CloudWatch Logs, WORM S3).

---

### 3.4 Information Disclosure

| Threat | Mitigation |
|---|---|
| Secret value leaks in list endpoint | `GET /secrets` returns `SecretMetaResponse` (no `value` field) |
| Encrypted blob exposed via API | `encrypted_value` field never included in any response schema |
| Error messages leak internals | Global exception handler returns generic 500; specific errors use controlled messages |
| Server header fingerprinting | `Server` and `X-Powered-By` headers stripped by `SecurityHeadersMiddleware` |
| Log injection | User-controlled values never interpolated into log strings |
| Cross-user secret access | Owner check on every secret operation; 404 returned (not 403) to avoid enumeration |

**Residual Risk**: Access tokens are long-lived (30 min). Recommended: implement token revocation list or reduce to 5-minute access tokens with seamless refresh.

---

### 3.5 Denial of Service

| Threat | Mitigation |
|---|---|
| Request flooding | `slowapi` rate limiter: 60 req/min global, 10 req/min on auth routes |
| Large payload attacks | FastAPI default max body size; Pydantic field length validators |
| DB connection exhaustion | SQLAlchemy pool (10 connections, 20 overflow); `pool_pre_ping` |
| Argon2 CPU exhaustion | Rate limiting on `/auth/login`; passlib default cost parameters |

**Residual Risk**: Distributed rate limiting not implemented (per-node, not shared Redis). Recommended: replace `slowapi` in-memory store with Redis backend for multi-instance deployments.

---

### 3.6 Elevation of Privilege

| Threat | Mitigation |
|---|---|
| Regular user accessing admin routes | `require_admin` dependency checks `role == ADMIN`; returns 403 |
| User A reading User B's secrets | `owner_id` filter on all secret queries |
| JWT role tampering | Role encoded in signed JWT; modification invalidates signature |
| Mass user creation for privilege abuse | Registration open by default; recommended: invite-only or email verification |

**Residual Risk**: No first-admin bootstrap protection. The first registered user is a regular user — admin must be set manually in DB. Recommended: environment variable `FIRST_ADMIN_USERNAME` to auto-elevate.

---

## 4. Security Controls Summary

| Layer | Control |
|---|---|
| Transport | HTTPS (enforced by HSTS header); CORS allowlist |
| Authentication | Argon2id password hash; JWT HS256; refresh token revocation |
| Authorization | RBAC (admin/user); per-resource ownership checks |
| Encryption at Rest | AES-256-GCM; fresh 96-bit nonce per write; tag authentication |
| Input Validation | Pydantic v2 with custom validators |
| Rate Limiting | slowapi (token-bucket); tighter limits on auth endpoints |
| Audit | Append-only audit_logs table; IP + UA captured; success/failure flag |
| Headers | CSP, HSTS, X-Content-Type-Options, X-Frame-Options, cache control |
| Error Handling | Generic 500 to client; structured logging server-side |

---

## 5. Out of Scope (v1)

- mTLS between API and DB
- Envelope encryption (per-secret DEKs wrapped by master key)
- HSM / KMS integration (AWS KMS, HashiCorp Vault Transit)
- Secret versioning history (current: version counter only)
- Secret sharing / cross-user access control
- WebAuthn / TOTP second factor
- IP allowlisting per user
