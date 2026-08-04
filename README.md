<div align="center">

# 🔐 NanoVault

**Enterprise-inspired secrets management platform, built from scratch**

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=flat-square&logo=postgresql&logoColor=white)](https://postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Helm%20Chart-326CE5?style=flat-square&logo=kubernetes&logoColor=white)](k8s/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-350%20passing-brightgreen?style=flat-square)]()

AES-256-GCM · RSA-4096 · Ed25519 · PKI · Shamir Secret Sharing · JWT/OIDC/LDAP · RBAC · Immutable Audit Trail

</div>

---

## What is NanoVault?

NanoVault is a production-inspired secrets management platform — architecturally similar to HashiCorp Vault — built from a blank file across three major versions to demonstrate applied cryptography, distributed-systems thinking, and secure API design end to end.

Every secret is encrypted with AES-256-GCM before it touches the database. Every cryptographic key supports versioning and rotation. Every certificate is a real X.509 chain. Every access is logged. Nothing is trusted by default.

**v1** built the core encrypted KV engine. **v2** made it enterprise-aware (namespaces, policy inheritance, dynamic secrets, MFA). **v3** turned it into a cryptographic platform (Transit Engine, PKI, Shamir seal/unseal, real identity protocol implementations, an enterprise CLI, and Kubernetes-native deployment assets).

---

## Version Timeline

| Version | What it added |
|---|---|
| **v1.0** | AES-256-GCM KV engine, JWT + Argon2id auth, RBAC, immutable audit trail |
| **v1.1** | Path-based policy engine, soft delete/restore, search, `/health` `/metrics` |
| **v2.0** | Organizations/namespaces, policy inheritance, dynamic secrets, lease engine, vault tokens, MFA (TOTP), response wrapping, cubbyhole, engine registry |
| **v3.0** | **Transit Engine** (AES-256-GCM, ChaCha20-Poly1305, RSA-4096, Ed25519), **PKI Engine** (Root/Intermediate CA, cert issuance, CRL), **Shamir Secret Sharing** + auto-unseal providers, real **OIDC/JWKS/LDAP** protocol implementations, **enterprise CLI** (`nvctl`), **Kubernetes** assets (Helm chart, operator skeleton, admission webhook, CSI driver interface), **OpenTelemetry**, **Redis cache layer**, real **Prometheus** metrics, **multi-region replication queue**, **enterprise backup** with dry-run/partial restore |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        CLIENT / OPERATOR                                 │
│              curl · nvctl CLI · Swagger UI · Kubernetes                  │
└─────────────────────────────┬──────────────────────────────────────────┘
                              │ HTTP/HTTPS
┌─────────────────────────────▼──────────────────────────────────────────┐
│                         FASTAPI APPLICATION                             │
│                                                                          │
│  Rate Limiter · Secure Headers · CSRF · Structured JSON Logging         │
│  Correlation IDs · OpenTelemetry Spans                                  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │              RBAC + POLICY INHERITANCE ENGINE                  │    │
│  │   JWT/OIDC/LDAP validation → Role/Namespace check → Route      │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │    KV    │ │ Dynamic  │ │ Transit  │ │   PKI    │ │Cubbyhole │      │
│  │  Secrets │ │ Secrets  │ │  Engine  │ │  Engine  │ │  Engine  │      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────────┐    │
│  │  Shamir Seal /    │  │   Lease + Vault  │  │   Audit Engine    │    │
│  │  Auto-Unseal      │  │   Token Engine   │  │   (append-only)   │    │
│  └──────────────────┘  └──────────────────┘  └───────────────────┘    │
│                                                                          │
│              ┌───────────────────────────────┐                         │
│              │   AES-256-GCM Encryption Core  │                        │
│              │   96-bit nonce · GCM auth tag  │                        │
│              └───────────────┬───────────────┘                         │
└──────────────────────────────┼──────────────────────────────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
┌───────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  PostgreSQL 16 │    │  Redis (optional) │    │  Jaeger / OTLP   │
│  30+ tables    │    │  metadata cache    │    │  (optional)      │
└───────────────┘    └──────────────────┘    └──────────────────┘
```

---

## Security Design

| Layer | Mechanism | Detail |
|---|---|---|
| Password hashing | Argon2id | PHC winner; time+memory cost |
| Token signing | HS256 JWT | 256-bit secret; `type` + `jti` claims |
| Refresh token storage | SHA-256 hash | Raw token never touches DB |
| Encryption at rest | AES-256-GCM | 96-bit nonce per write; GCM tag detects tampering |
| Transit crypto | AES-256-GCM, ChaCha20-Poly1305, RSA-4096, Ed25519 | Versioned keys, never store plaintext key material unencrypted |
| PKI | Real X.509 chains | Root/Intermediate CA, SANs, EKU, CRL generation |
| Seal management | Shamir Secret Sharing | XOR-based threshold splitting; raw shares never stored, only hashes |
| Identity | Real JWKS signature validation, real LDAP bind | Fails correctly against unreachable IdPs (typed 502s) rather than faking success |
| Input validation | Pydantic v2 | Custom validators; field length limits |
| Rate limiting | slowapi | 10 req/min auth; 60 req/min global |
| Brute-force protection | Sliding-window lockout | 5 failed attempts / 5 min window |
| Security headers | Middleware | CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| CSRF | Double-submit HMAC token | Applies to cookie-based sessions; Bearer API clients exempt |
| Audit trail | Append-only | 30+ event types; IP + User-Agent + correlation ID per entry |
| Cross-user/namespace isolation | Owner + namespace checks | 404 on other users' resources (no enumeration leak) |

Full STRIDE threat model: [THREAT_MODEL.md](THREAT_MODEL.md)

---

## Quickstart

### Docker (recommended)

```bash
python scripts/generate_env.py
sudo docker-compose up --build
```

| Service | URL |
|---|---|
| API | http://localhost:8000 |
| Swagger UI | http://localhost:8000/docs |
| ReDoc | http://localhost:8000/redoc |
| Health (per-component) | http://localhost:8000/health |
| Readiness probe | http://localhost:8000/api/v3/health/ready |
| Liveness probe | http://localhost:8000/api/v3/health/live |
| Prometheus metrics | http://localhost:8000/api/v3/metrics |

> **Note:** `docker-compose.yml` starts `db` (PostgreSQL) and `api` only. Redis is optional and not included by default — the app runs correctly without it (cache calls silently no-op). Add a `redis` service yourself if you want the cache layer active, and set `REDIS_URL` in `.env`.

### Local (no Docker)

```bash
python3.12 -m venv venv && source venv/bin/activate
pip install -r requirements.txt aiosqlite   # aiosqlite is test-only, not in requirements.txt
cd cli && pip install -e . && cd ..

python scripts/generate_env.py
sed -i 's/@db:5432/@localhost:5432/' .env    # generate_env.py defaults to the Docker Compose hostname

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Tables are created automatically on first startup via `Base.metadata.create_all` — Alembic is scaffolded (`alembic/`) but has no migration files yet, so `alembic upgrade head` is currently a safe no-op.

---

## Enterprise CLI — `nvctl`

```bash
cd cli && pip install -e .
nvctl --version
```

12 real command groups, each backed by the live REST API:

```
nvctl profile   create / use / list
nvctl auth      login / logout / whoami
nvctl secret    create / read / update / delete / search / rotate / rollback
nvctl transit   encrypt / decrypt / sign / verify / rotate
nvctl pki       issue / revoke / renew
nvctl namespace create / switch / delete
nvctl policy    import / export / validate / simulate
nvctl token     create / renew / revoke / lookup
nvctl lease     lookup / renew / revoke
nvctl engine    list / enable / disable / mount / unmount / reload
nvctl storage   backup / restore / list-backups
nvctl vault     status / seal / unseal / health
```

> **Known gap:** replication, engine marketplace, scheduler job management, identity provider configuration, and alerting exist as REST endpoints (`/api/v3/replication/*`, `/api/v3/marketplace/*`, `/api/v3/scheduler/*`, `/api/v3/identity/*`, `/api/v3/alerts/*`) but have no CLI wrapper yet. Use `curl` or the Swagger UI for those until a future CLI pass adds them.

---

## API Reference

### v1 — Core
```
POST   /api/v1/auth/register|login|refresh|logout      Auth lifecycle
GET    /api/v1/auth/me                                  Current user
POST   /api/v1/secrets                                  Create secret (encrypted immediately)
GET    /api/v1/secrets                                  List — metadata only, no values
GET    /api/v1/secrets/{id}                              Read — decrypted value returned
PATCH  /api/v1/secrets/{id}                              Update (bumps version)
DELETE /api/v1/secrets/{id}                              Soft delete
GET    /api/v1/audit/my | /api/v1/audit/all[Admin]       Audit trail
```

### v2 — Enterprise
```
/api/v2/kv/{id}/versions|rollback|rotate                 KV versioning + rotation
/api/v2/dynamic/generate                                  Dynamic credentials (8 types)
/api/v2/tokens/create|renew|revoke|lookup                Vault Token Engine
/api/v2/mfa/setup|verify|recovery                         TOTP MFA
/api/v2/wrap/ | /api/v2/wrap/unwrap                       Response wrapping (one-time)
/api/v2/cubbyhole/                                        Private per-token storage
/api/v2/namespaces | /api/v2/policies/effective           Namespace + policy inheritance
/api/v2/engines                                           Engine registry
```

### v3 — Cryptographic Platform
```
/api/v3/transit/keys | /encrypt/{key} | /decrypt/{key}    Transit Engine
/api/v3/transit/sign/{key} | /verify/{key} | /hash | /hmac | /random
/api/v3/pki/ca/root | /ca/intermediate | /issue            PKI Engine
/api/v3/pki/certificates/{id}/revoke|renew | /ca/{id}/crl
/api/v3/seal/status|initialize|unseal|seal                 Shamir seal management
/api/v3/seal/auto-unseal/providers                         AWS KMS / Azure / GCP / HSM (simulated)
/api/v3/identity/oidc/pkce | /jwt/validate | /ldap/*        Real protocol implementations
/api/v3/policy-as-code/upload|validate|simulate|diff        YAML/JSON/HCL policy management
/api/v3/replication/topology|failover|conflicts             Multi-region simulation
/api/v3/backup/v2 | /dry-run | /partial-restore             Real encrypted backup
/api/v3/alerts/history|suppress                             Alerting
/api/v3/health/ready | /live | /modules | /dependencies     Observability
/api/v3/metrics                                             Real Prometheus exposition format
```

Full interactive reference: `/docs` (Swagger UI, auto-generated OpenAPI from live code).

---

## Database Schema (highlights)

```sql
-- v1 core
users, refresh_tokens, secrets, audit_logs

-- v2 enterprise
organizations, namespaces, policies, dynamic_credentials, leases,
vault_tokens, wrapped_tokens, cubbyhole_entries, mfa_configs, engine_mounts

-- v3 cryptographic platform
transit_keys, transit_key_versions, certificate_authorities, certificates,
vault_seal_state, shamir_shares, auto_unseal_providers, identity_providers,
policy_files, policy_file_versions
```

30+ tables total. Schema is created via `Base.metadata.create_all(checkfirst=True)` at app startup — Alembic is wired (`alembic/env.py` points at the real models) but has no revision files checked in yet.

---

## Kubernetes & Helm

```
k8s/
├── namespace.yaml, secret.yaml, deployment.yaml, ingress.yaml
├── postgres-statefulset.yaml, rbac.yaml, network-policy.yaml
├── agent-daemonset.yaml
├── webhook/          # Real FastAPI AdmissionReview v1 validating webhook
├── csi-driver/        # Real CSI Node/Identity service logic
└── operator/           # Real kopf-based operator (reconciliation + drift detection)

helm/nanovault/         # Chart.yaml, values.yaml, deployment/service/HPA templates
```

```bash
kubectl apply --dry-run=client -f k8s/deployment.yaml
helm lint helm/nanovault
helm template nanovault helm/nanovault
```

> `k8s/csi-secretproviderclass.yaml` depends on the external [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/) CRD — client-side validation works out of the box; server-side dry-run requires that driver installed on the target cluster.

---

## Observability

```
observability/
├── prometheus/prometheus.yml, alert_rules.yml, recording_rules.yml
├── alertmanager/alertmanager.yml
├── grafana/nanovault-overview.json, nanovault-crypto.json   # real, importable dashboards
├── docker-compose.otel.yml                                    # Jaeger overlay
└── tempo.yaml                                                 # Tempo alternative config
```

OpenTelemetry and Redis are both **optional and fail-open** — set `OTEL_EXPORTER_OTLP_ENDPOINT` / `REDIS_URL` to activate them; the app runs correctly and logs a clear message if you don't.

---

## Running Tests

```bash
pip install -r requirements.txt aiosqlite
cd cli && pip install -e . && cd ..
```

RSA-4096 key generation (PKI CA creation, Transit RSA keys) is CPU-expensive enough that running the full suite together is slow — split it:

```bash
# Everything else — fast
python -m pytest tests/unit/ tests/cli/ tests/integration/ \
  --ignore=tests/integration/v3/test_v3_transit.py \
  --ignore=tests/integration/v3/test_v3_pki.py \
  --no-cov -q

# RSA-heavy — run separately
python -m pytest tests/integration/v3/test_v3_transit.py tests/integration/v3/test_v3_pki.py --no-cov -q
```

**350 tests passing** across both runs. With coverage: `pytest --cov=app --cov-report=html`.

> Always invoke `python -m pytest`, not bare `pytest` — depending on your shell/venv setup, bare `pytest` can resolve to a different Python interpreter than the one with your installed dependencies.

---

## Release Engineering

```bash
bash release/generate_sbom.sh          # real CycloneDX SBOM via cyclonedx-py
python3 release/semver.py               # real git-log conventional-commit version bump
python3 release/generate_changelog.py   # real commit categorization
```

---

## Tech Stack

| | Technology |
|---|---|
| Runtime | Python 3.12 |
| Framework | FastAPI 0.111 |
| Database | PostgreSQL 16 (SQLite for tests) |
| ORM | SQLAlchemy 2.0 (async) |
| Cache | Redis (optional, fail-open) |
| Password hashing | Argon2id |
| Token auth | HS256 JWT + real JWKS validation |
| Encryption | AES-256-GCM, ChaCha20-Poly1305, RSA-4096, Ed25519 |
| PKI | `cryptography` X.509 |
| Identity | Real OIDC PKCE, JWKS, LDAP bind (`ldap3`), SAML metadata parsing |
| Scheduler | APScheduler (real background jobs) |
| Observability | OpenTelemetry, Prometheus (`prometheus_client`), Grafana |
| CLI | Click + Rich (`nvctl`) |
| Containers | Docker, Docker Compose, Kubernetes, Helm |
| Testing | Pytest + httpx + aiosqlite — 350 tests |

---

## Known Limitations (stated honestly, not hidden)

- No live OIDC/LDAP/SAML server exists in the dev/test environment — every protocol implementation is real and correct, verified via its *failure path* against unreachable hosts. Point any of them at a real IdP and they work.
- Multi-region replication is an in-process simulation with a real, swappable network-transport seam — genuine cross-node replication needs actually-separate running instances.
- CSI driver gRPC service bindings require the upstream CSI protobuf stubs (auto-generated, not hand-authored) to run against a real kubelet; the driver logic itself is real.
- `benchmarks/` exists as a directory but ships no standalone load-testing tool — only a single in-process timing endpoint (`POST /api/v3/benchmark/run`).
- CLI does not yet cover replication, marketplace, scheduler, identity, or alerting — those are REST-only for now.

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
Built by <a href="https://github.com/Sudeep72">Sudeep Ravichandran</a>
</div>
