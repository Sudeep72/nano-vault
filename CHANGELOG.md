# Changelog

## [v1.0.0] — 2025-06-30

### Initial release

**Authentication Engine**
- User registration with Argon2id password hashing (PHC winner)
- JWT access tokens (HS256, 30-min expiry, `type` + `jti` claims)
- Refresh tokens stored as SHA-256 hashes — raw token never in DB
- Revoke-on-logout with server-side expiry enforcement
- `/register` `/login` `/refresh` `/logout` `/me` endpoints

**KV Secrets Engine**
- AES-256-GCM encryption — fresh 96-bit nonce per write
- GCM authentication tag detects any ciphertext tampering
- Create / read / update / soft-delete per user
- Categories and tags for organisation
- Version counter incremented on every value update
- List endpoint returns metadata only — value never exposed without explicit GET

**RBAC Policy Engine**
- Two roles: `admin` and `user`
- Least-privilege by default — users access only their own secrets
- FastAPI dependency injection: `get_current_user`, `require_admin`

**Audit Engine**
- Immutable `audit_logs` table — no UPDATE/DELETE in service layer
- 9 event types covering auth and secret lifecycle
- IP address and User-Agent captured per entry

**Security**
- Rate limiting: 10 req/min on auth routes, 60 req/min global
- Secure headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- Generic error messages — no stack traces to clients
- Cross-user isolation: 404 on other users' secrets (prevents enumeration)

**Infrastructure**
- Docker + Docker Compose with PostgreSQL 16
- Alembic migrations
- OpenAPI docs at `/docs` and `/redoc`
- Key bootstrap script (`scripts/generate_env.py`)

**Testing**
- 37 tests (unit + integration)
- In-memory SQLite for fast, isolated integration tests
- Coverage: encryption, JWT, auth flows, secret CRUD, cross-user isolation
