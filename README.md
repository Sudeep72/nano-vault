<div align="center">

# 🔐 NanoVault

**Production-inspired secrets management platform**

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=flat-square&logo=postgresql&logoColor=white)](https://postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-37%20passing-brightgreen?style=flat-square)]()

AES-256-GCM encryption · JWT authentication · RBAC · Immutable audit trail

</div>

---

## What is NanoVault?

NanoVault implements the core security primitives of a production secrets manager — inspired by HashiCorp Vault — built from scratch to demonstrate applied cryptography, secure API design, and detection engineering.

Every secret is encrypted with AES-256-GCM before hitting the database. Every access is logged. Every token is validated, typed, and revocable. Nothing is trusted by default.

Built as a portfolio-grade system for the MS Cybersecurity curriculum at Indiana University Bloomington.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                            CLIENT                                │
│                    curl / Swagger UI / App                       │
└─────────────────────────────┬────────────────────────────────────┘
                              │ HTTP/HTTPS
┌─────────────────────────────▼────────────────────────────────────┐
│                      FASTAPI APPLICATION                         │
│                                                                  │
│  ┌──────────────┐   ┌─────────────────┐   ┌──────────────────┐  │
│  │  Rate Limiter │   │  Secure Headers  │   │   Request ID     │  │
│  │  10/min auth  │   │  CSP·HSTS·XFO   │   │   Middleware     │  │
│  └──────────────┘   └─────────────────┘   └──────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                   RBAC POLICY ENGINE                       │  │
│  │      JWT Validation → Role Check → Route Guard             │  │
│  │      get_current_user()       require_admin()              │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─────────────────┐  ┌──────────────────┐  ┌───────────────┐   │
│  │  AUTH SERVICE   │  │   KV SECRETS     │  │ AUDIT ENGINE  │   │
│  │                 │  │     ENGINE       │  │               │   │
│  │ • Register      │  │ • Create         │  │ • Login logs  │   │
│  │ • Login         │  │ • Read           │  │ • Secret R/W  │   │
│  │ • Refresh token │  │ • Update         │  │ • Auth fails  │   │
│  │ • Logout/Revoke │  │ • Soft delete    │  │ • IP + UA     │   │
│  │ • Argon2id hash │  │ • Tags/Category  │  │ • Append-only │   │
│  └────────┬────────┘  └────────┬─────────┘  └───────┬───────┘   │
│           │                    │                     │           │
│           └────────────────────▼─────────────────────┘           │
│                    ┌───────────────────────┐                     │
│                    │  AES-256-GCM SERVICE  │                     │
│                    │  96-bit nonce/write   │                     │
│                    │  GCM tag = integrity  │                     │
│                    │  base64(nonce||ct+tag)│                     │
│                    └───────────┬───────────┘                     │
└────────────────────────────────┼────────────────────────────────┘
                                 │
┌────────────────────────────────▼────────────────────────────────┐
│                         POSTGRESQL 16                           │
│                                                                  │
│   ┌──────────┐  ┌─────────────────┐  ┌─────────┐  ┌─────────┐  │
│   │  users   │  │ refresh_tokens  │  │ secrets │  │  audit  │  │
│   │          │  │                 │  │         │  │  _logs  │  │
│   │ Argon2id │  │ SHA-256 hash    │  │ AES-GCM │  │ immut.  │  │
│   │ password │  │ only (no raw)   │  │ blob    │  │ trail   │  │
│   └──────────┘  └─────────────────┘  └─────────┘  └─────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Security Design

| Layer | Mechanism | Detail |
|---|---|---|
| Password hashing | Argon2id | PHC winner; time+memory cost |
| Token signing | HS256 JWT | 256-bit secret; `type` + `jti` claims |
| Refresh token storage | SHA-256 hash | Raw token never touches DB |
| Encryption at rest | AES-256-GCM | 96-bit nonce per write; tag detects tampering |
| Input validation | Pydantic v2 | Custom validators; field length limits |
| Rate limiting | slowapi | 10 req/min auth; 60 req/min global |
| Security headers | Middleware | CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| Error messages | Generic 500 | No stack traces, no internal paths to client |
| Audit trail | Append-only | 9 event types; IP + User-Agent per entry |
| Cross-user isolation | Owner check | 404 on other user's secrets (no enumeration leak) |

---

## Encryption Deep Dive

```
plaintext ──► AES-256-GCM encrypt ──► base64(nonce[12] || ciphertext || tag[16])
                    ▲
              96-bit nonce          ← os.urandom(12) per call
              256-bit key           ← from ENCRYPTION_KEY env var
              GCM auth tag          ← detects any bit-level tampering
```

The plaintext value exists **only in memory** during the request. The database stores only the encrypted blob. Losing `ENCRYPTION_KEY` = permanent loss of all secrets.

---

## API Reference

### Authentication
```
POST   /api/v1/auth/register     Register (username, email, password)
POST   /api/v1/auth/login        Login → {access_token, refresh_token}
POST   /api/v1/auth/refresh      Refresh access token
POST   /api/v1/auth/logout       Revoke refresh token
GET    /api/v1/auth/me           Current user profile
```

### KV Secrets Engine
```
POST   /api/v1/secrets           Create secret (encrypted immediately)
GET    /api/v1/secrets           List secrets — metadata only, no values
GET    /api/v1/secrets/{id}      Read secret — decrypted value returned
PATCH  /api/v1/secrets/{id}      Update (bumps version counter)
DELETE /api/v1/secrets/{id}      Soft delete
GET    /api/v1/secrets/admin/all [Admin] All users' secrets
```

### Audit Logs
```
GET    /api/v1/audit/my          My audit log (paginated, filter by action)
GET    /api/v1/audit/all         [Admin] All users' audit logs
```

### Audit Event Types
`USER_REGISTER` · `USER_LOGIN` · `USER_LOGIN_FAILED` · `USER_LOGOUT` · `TOKEN_REFRESH` · `SECRET_CREATE` · `SECRET_READ` · `SECRET_UPDATE` · `SECRET_DELETE`

---

## Database Schema

```sql
users
  id UUID PK | username VARCHAR(64) UNIQUE | email VARCHAR(255) UNIQUE
  hashed_password VARCHAR(255) | role ENUM(admin,user) | is_active BOOL
  created_at TIMESTAMPTZ | last_login_at TIMESTAMPTZ

refresh_tokens
  id UUID PK | user_id UUID FK → users(CASCADE)
  token_hash VARCHAR(255) UNIQUE   -- SHA-256 of raw token only
  issued_at TIMESTAMPTZ | expires_at TIMESTAMPTZ
  revoked BOOL | revoked_at TIMESTAMPTZ

secrets
  id UUID PK | owner_id UUID FK → users(CASCADE) | key VARCHAR(255)
  encrypted_value TEXT             -- AES-256-GCM blob
  description TEXT | category VARCHAR(128) | tags JSON
  version INT | is_deleted BOOL
  created_at TIMESTAMPTZ | updated_at TIMESTAMPTZ
  UNIQUE INDEX (owner_id, key) WHERE is_deleted = false

audit_logs                         -- append-only, no UPDATE/DELETE
  id UUID PK | user_id UUID FK → users | action ENUM
  resource_type VARCHAR(64) | resource_id VARCHAR(255)
  ip_address VARCHAR(64) | user_agent VARCHAR(512)
  metadata JSON | success BOOL | created_at TIMESTAMPTZ
```

---

## Quickstart

### Docker (recommended)

```bash
# 1. Generate secure keys
python scripts/generate_env.py

# 2. Start stack
sudo docker-compose up --build

# API:     http://localhost:8000
# Swagger: http://localhost:8000/docs
# ReDoc:   http://localhost:8000/redoc
# Health:  http://localhost:8000/health
```

### Quick API test

```bash
# Register
curl -s -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"AlicePass1!"}' \
  | python3 -m json.tool

# Login and save token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"AlicePass1!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Store a secret (encrypted immediately)
curl -s -X POST http://localhost:8000/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key":"aws/prod/key","value":"AKIAIOSFODNN7EXAMPLE","category":"cloud","tags":["aws","prod"]}' \
  | python3 -m json.tool

# List secrets — no values in response
curl -s http://localhost:8000/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Read one secret — decrypted on the fly
curl -s http://localhost:8000/api/v1/secrets/<SECRET_ID> \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# View audit trail
curl -s http://localhost:8000/api/v1/audit/my \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

## Project Structure

```
nano_vault/
├── app/
│   ├── api/v1/endpoints/
│   │   ├── auth.py              # Auth router
│   │   ├── secrets.py           # KV secrets router
│   │   └── audit.py             # Audit log router
│   ├── core/
│   │   ├── config.py            # Pydantic settings
│   │   ├── dependencies.py      # RBAC dependency injection
│   │   ├── encryption.py        # AES-256-GCM service
│   │   └── security.py          # JWT + Argon2id
│   ├── db/session.py            # SQLAlchemy async engine
│   ├── middleware/security.py   # Secure headers middleware
│   ├── models/models.py         # SQLAlchemy ORM models
│   ├── schemas/schemas.py       # Pydantic v2 schemas
│   ├── services/
│   │   ├── auth_service.py      # Auth business logic
│   │   ├── audit_service.py     # Audit log writes
│   │   └── secret_service.py    # KV CRUD + encryption
│   └── main.py                  # FastAPI app entry point
├── alembic/                     # Database migrations
│   └── env.py
├── tests/
│   ├── conftest.py              # Shared fixtures (in-memory SQLite)
│   ├── unit/
│   │   ├── test_encryption.py   # AES-256-GCM unit tests
│   │   └── test_security.py     # JWT + Argon2 unit tests
│   └── integration/
│       ├── test_auth.py         # Auth endpoint tests
│       └── test_secrets.py      # Secrets CRUD + isolation tests
├── scripts/
│   └── generate_env.py          # Secure key bootstrap
├── Dockerfile
├── docker-compose.yml
├── THREAT_MODEL.md              # Full STRIDE analysis
├── .env.example
├── pytest.ini
└── requirements.txt
```

---

## Running Tests

```bash
pip install -r requirements.txt aiosqlite
pytest                              # all 37 tests
pytest tests/unit/                  # unit tests only
pytest tests/integration/           # integration tests only
pytest --cov=app --cov-report=html  # with coverage report
```

**Test coverage:**
- `test_encryption.py` — nonce uniqueness, tamper detection, wrong-key rejection, unicode
- `test_security.py` — JWT signing, type enforcement, tampered token rejection, Argon2 hashing
- `test_auth.py` — register, login, duplicate/weak password, refresh, logout + revocation
- `test_secrets.py` — CRUD, version increment, metadata-only list, cross-user isolation, audit trail

---

## Threat Model

Full STRIDE analysis in [THREAT_MODEL.md](THREAT_MODEL.md).

Key mitigations:
- **Spoofing** — Argon2id + rate limiting on auth; JWT `type` + `jti` claims prevent token reuse across types
- **Tampering** — AES-GCM authentication tag detects any ciphertext modification; SQLAlchemy prevents SQL injection
- **Repudiation** — Immutable `audit_logs`; `USER_LOGIN_FAILED` written before returning 401
- **Information Disclosure** — List endpoint never returns `value`; 404 on other users' secrets (no enumeration); generic 500 errors
- **Denial of Service** — slowapi rate limiting; SQLAlchemy connection pool (10/20 overflow)
- **Elevation of Privilege** — `require_admin` dependency on every admin route; `owner_id` filter on all secret queries

---

## Tech Stack

| | Technology |
|---|---|
| Runtime | Python 3.12 |
| Framework | FastAPI 0.111 |
| Database | PostgreSQL 16 |
| ORM | SQLAlchemy 2.0 (async) |
| Migrations | Alembic |
| Password hashing | Argon2id (passlib) |
| Token auth | HS256 JWT (python-jose) |
| Encryption | AES-256-GCM (cryptography) |
| Validation | Pydantic v2 |
| Rate limiting | slowapi |
| Testing | Pytest + httpx + aiosqlite |
| Containers | Docker + Docker Compose |

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
Built by <a href="https://github.com/Sudeep72">Sudeep Ravichandran</a> · MS Cybersecurity @ Indiana University Bloomington
</div>
