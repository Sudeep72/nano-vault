<div align="center">

# 🔐 NanoVault

**Secrets management platform, evolved into a Security Operations Platform**

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=flat-square&logo=postgresql&logoColor=white)](https://postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![Gemini](https://img.shields.io/badge/AI-Google%20Gemini-4285F4?style=flat-square&logo=google&logoColor=white)](https://ai.google.dev)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-553%20passing-brightgreen?style=flat-square)]()

AES-256-GCM · RSA-4096 · Ed25519 · PKI · Shamir Secret Sharing · Deterministic Risk Scoring · Event Correlation · Google Gemini · Full Investigation Lifecycle

</div>

---

## What is NanoVault?

NanoVault started as a HashiCorp Vault–inspired encrypted secrets manager and grew, across six versions, into a full **Security Operations Platform**: deterministic risk scoring, multi-event correlation, an AI analyst that explains findings without ever being allowed to change them, and a fully audited investigation workflow.

**v6.0.0 is the final version.** There is no v7 planned — every decision in this last phase was made to leave the system complete, not to leave room for a future rewrite.

Every secret is encrypted with AES-256-GCM before it touches the database. Every risk score comes from a deterministic rule, never from a model. Every state change in an investigation is authorization-checked and audited. Nothing is trusted by default — including the AI layer itself.

---

## Version Timeline

| Version | What it added |
|---|---|
| **v1.0** | AES-256-GCM KV engine, JWT + Argon2id auth, RBAC, immutable audit trail |
| **v2.0** | Organizations/namespaces, policy inheritance, dynamic secrets, lease engine, vault tokens, MFA, response wrapping, cubbyhole, engine registry |
| **v3.0** | Transit Engine (AES-256-GCM/ChaCha20-Poly1305/RSA-4096/Ed25519), PKI Engine, Shamir Secret Sharing + auto-unseal, real OIDC/JWKS/LDAP, enterprise CLI, Kubernetes assets, OpenTelemetry, Redis cache, real Prometheus metrics, multi-region replication, enterprise backup |
| **v4.0** | Architecture Explorer, Secret Dependency Graph, Cryptography Performance Lab, Secret Access Replay + Live Audit Stream, Threat Modeling Dashboard, Interactive API Playground, Enterprise Demo Mode, Documentation Generator, API Collection Generator |
| **v5.0** | AI Security Platform — Google Gemini behind a provider-agnostic abstraction, Security Context Layer with RBAC inherited by construction, prompt-injection guardrails, AI Security Analyst, natural-language search, structured auditable findings |
| **v6.0** | **Security Operations Platform (final)** — Deterministic Risk Engine, Event Correlation Engine, AI Analyst extended to explain (not decide) findings, unified findings model, full Investigation Workflow with a real state machine, proper Alembic migrations |

---

## v6.0 — What's Actually In The Final Release

### Deterministic Risk Engine
Six independent, modular scoring rules run over real audit log data — no AI call anywhere in this path:

| Rule | Signal |
|---|---|
| `repeated_auth_failures` | 3+ or 5+ failed logins in the analysis window |
| `ip_address_churn` | Multiple distinct IP addresses for one entity |
| `failed_then_success_login` | A streak of failures immediately followed by success |
| `high_volume_secret_reads` | Abnormal secret read volume |
| `privilege_sensitive_operations` | Token creation, policy changes, org creation |
| `unusual_activity_timing` | Activity clustered in 00:00–05:00 UTC |

Each triggered rule contributes points toward a 0–100 score, capped and mapped to `low` / `medium` / `high` / `critical`.

### Event Correlation Engine
Looks across *sequences* of events rather than scoring them independently:

- **`login_then_secret_lifecycle`** — login → secret read → secret creation within 30 minutes
- **`failed_burst_success_sensitive_op`** — 3+ failed logins → success → a privilege-sensitive operation within 15 minutes (the classic credential-guessing signature)
- **`new_ip_auth_secret_access`** — login from a genuinely new IP → secret access within 10 minutes

### AI Security Analyst (Gemini) — explains, never decides
Extends the v5 AI pipeline to annotate deterministic findings with plain-language explanation, false-positive assessment, and investigation guidance. Structurally cannot touch `risk_score`, `risk_level`, `triggered_rules`, `correlated_event_ids`, `evidence`, `severity`, or `confidence` — only `explanation` and `recommended_actions` are ever written by the AI path. Verified both by automated test (byte-for-byte field comparison before/after a mocked call) and by hand against a live Gemini response.

### Unified Findings Model
One `AIFinding` table spans v5's pure AI explanations and v6's deterministic risk/correlation findings — `category` distinguishes them (`event_explanation`, `nl_search`, `investigation`, `risk_assessment`, `correlation`), and every v6-only field is nullable so v5 rows remain valid.

### Investigation Workflow
A real, enforced state machine:
```
OPEN ──► INVESTIGATING ──► ACKNOWLEDGED ──► RESOLVED
  │            │                 │
  └────────────┴─────────────────┴──► DISMISSED
```
- Invalid transitions (e.g. `OPEN` → `ACKNOWLEDGED` directly) are rejected with `409` and a clear message
- `RESOLVED` and `DISMISSED` are terminal — every further transition attempt is rejected
- Every actor must be the finding's creator or an admin — enforced consistently across list/get/investigate/acknowledge/resolve/dismiss
- Every transition is audited with from/to status in the audit log
- The pre-existing v5 `PATCH /status` endpoint (admin-only, unconstrained) was deliberately left untouched as an emergency override tool, sitting alongside the new validated workflow

### A Real Bug, Found and Fixed
Building the risk engine surfaced a pre-existing issue dating back to v1: failed-login audit events were being logged, then silently discarded by a rollback in the request's exception path. **Every failed login since v1 was invisible to the audit trail.** Fixed with an explicit commit before the re-raise, covered by a dedicated regression test so it can't silently return.

### Alembic Migrations, Properly Established
v1–v5 relied on `Base.metadata.create_all()` at startup — which is what caused an earlier production issue when a new Postgres enum value couldn't be added to an already-created enum type. v6 establishes a real migration chain:
```
baseline_v5_schema → v6_risk_engine_findings_extension → v6_phase4_investigating_status
```
Both a fresh database and an existing v5 database migrate forward correctly; the enum-evolution migration is dialect-conditional (`ALTER TYPE` on Postgres, correctly a no-op on SQLite, which has no CHECK constraint on that column).

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        CLIENT / OPERATOR                                 │
│              curl · nvctl CLI · Swagger UI · Kubernetes                  │
└─────────────────────────────┬──────────────────────────────────────────┘
                              │
┌─────────────────────────────▼──────────────────────────────────────────┐
│                         FASTAPI APPLICATION                             │
│                                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │    KV    │ │ Transit  │ │   PKI    │ │ Dynamic  │ │Cubbyhole │      │
│  │  Secrets │ │  Engine  │ │  Engine  │ │ Secrets  │ │  Engine  │      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
│                                                                          │
│  ┌───────────────────┐  ┌────────────────────┐  ┌───────────────────┐  │
│  │  Risk Engine        │  │  Correlation        │  │  AI Security      │  │
│  │  (deterministic)    │  │  Engine             │  │  Analyst (Gemini) │  │
│  └──────────┬──────────┘  └──────────┬──────────┘  └─────────┬─────────┘  │
│             └──────────────┬─────────┴──────────────────────┘             │
│                             ▼                                             │
│              ┌───────────────────────────────┐                           │
│              │   Unified Findings + Workflow  │                          │
│              │   (state machine, audited)     │                          │
│              └───────────────┬───────────────┘                           │
│                              │                                           │
│              ┌───────────────▼───────────────┐                          │
│              │   AES-256-GCM Encryption Core   │                        │
│              └───────────────┬───────────────┘                          │
└──────────────────────────────┼──────────────────────────────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
┌───────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  PostgreSQL 16 │    │  Redis (optional) │    │  Google Gemini   │
│  via Alembic   │    │  metadata cache    │    │  (optional, off  │
│  migrations    │    │                    │    │  by default)     │
└───────────────┘    └──────────────────┘    └──────────────────┘
```

---

## Security Design

| Layer | Mechanism | Detail |
|---|---|---|
| Password hashing | Argon2id | PHC winner; time+memory cost |
| Encryption at rest | AES-256-GCM | 96-bit nonce per write; GCM tag detects tampering |
| Transit crypto | AES-256-GCM, ChaCha20-Poly1305, RSA-4096, Ed25519 | Versioned keys |
| PKI | Real X.509 chains | Root/Intermediate CA, SANs, EKU, CRL |
| Seal management | Shamir Secret Sharing | Raw shares never stored, only hashes |
| Risk scoring | Pure deterministic rules | Zero AI involvement in the score itself |
| AI guardrails | Delimiter framing + redaction | Untrusted content explicitly marked as data, not instructions; secret values/credentials never reach the model |
| AI/deterministic boundary | Structural, not just policy | The AI explanation path has no code path capable of writing `risk_score`/`risk_level`/`triggered_rules`/`correlated_event_ids`/`evidence`/`severity`/`confidence` |
| Investigation authorization | Creator-or-admin, enforced everywhere | List, get, investigate, acknowledge, resolve, dismiss all share the same check |
| Audit trail | Append-only, every transition logged | 30+ event types, includes AI explanation runs (without storing prompts) and every status change (with from/to) |
| Schema management | Alembic migrations | Fresh-DB and existing-V5-DB upgrade paths both verified |

Full STRIDE threat model: [THREAT_MODEL.md](THREAT_MODEL.md)

---

## Quickstart

### Docker (recommended)

```bash
cat > .env << 'EOF'
SECRET_KEY=<32+ char random string>
JWT_SECRET_KEY=<32+ char random string>
ENCRYPTION_KEY=<base64-encoded 32 random bytes>
DATABASE_URL=postgresql+asyncpg://nano_vault_user:nano_vault_pass@db:5432/nano_vault_db
ALLOWED_ORIGINS=http://localhost:3000

# AI Security Platform — optional, disabled by default
# AI_ENABLED=true
# AI_PROVIDER=gemini
# AI_MODEL=gemini-2.0-flash
# GEMINI_API_KEY=your-key-here
EOF

sudo docker-compose up --build
```

Generate real random values:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"      # for SECRET_KEY, JWT_SECRET_KEY
python3 -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"  # for ENCRYPTION_KEY
```

| Service | URL |
|---|---|
| API | http://localhost:8000 |
| Swagger UI | http://localhost:8000/docs |
| Health | http://localhost:8000/health |
| Readiness | http://localhost:8000/api/v3/health/ready |
| Prometheus metrics | http://localhost:8000/api/v3/metrics |

### Local (no Docker)

```bash
python3.12 -m venv venv && source venv/bin/activate
pip install -r requirements.txt aiosqlite
cd cli && pip install -e . && cd ..

# .env as above, but with DATABASE_URL host as localhost instead of db
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**If migrating an existing v5 database** that was created before this version's Alembic chain existed:
```bash
alembic stamp <baseline_revision_id>   # see: alembic history
alembic upgrade head
```

---

## Enterprise CLI — `nvctl`

```bash
nvctl profile create local --address http://localhost:8000
nvctl profile use local
nvctl auth login --username <user> --password '<pass>'
```

### Security Operations commands (v6)
```
nvctl security status                       # registered risk rules + correlation chains
nvctl security risk <user_id> [--record]    # preview or persist a risk assessment
nvctl security correlate <user_id> [--record]
nvctl security findings [--category] [--status]
nvctl security finding <id>
nvctl security explain <id> [--question]
nvctl security investigate <id>
nvctl security acknowledge <id>
nvctl security resolve <id> [--note]
nvctl security dismiss <id> [--reason]
```

### Everything else
`nvctl auth`, `secret`, `transit`, `pki`, `namespace`, `policy`, `token`, `lease`, `engine`, `storage`, `vault`, `explore`, `replay`, `bench`, `demo`, `docgen`, `diagnose`, `ai` — see `nvctl --help` for the full tree.

---

## API Reference (highlights)

```
# v6 — Security Operations
GET   /api/v6/security/risk/rules
GET   /api/v6/security/risk/users/{id}                  preview
POST  /api/v6/security/risk/users/{id}/assess            persist [Admin]
GET   /api/v6/security/correlation/rules
POST  /api/v6/security/correlation/users/{id}/assess      persist [Admin]
POST  /api/v6/security/findings/{id}/explain              AI explanation
GET   /api/v6/security/findings                          scoped list (creator or admin)
GET   /api/v6/security/findings/{id}                      scoped get
POST  /api/v6/security/findings/{id}/investigate
POST  /api/v6/security/findings/{id}/acknowledge
POST  /api/v6/security/findings/{id}/resolve
POST  /api/v6/security/findings/{id}/dismiss

# v5 — AI Security Platform
GET   /api/v5/ai/status | /ai/health
POST  /api/v5/ai/explain | /ai/investigate | /ai/search
GET   /api/v5/ai/findings    (risk_level, min_risk_score, has_correlated_events filters added in v6)
PATCH /api/v5/ai/findings/{id}/status    (legacy, admin-only, unconstrained — see note above)
```

Full interactive reference: `/docs`.

---

## Running Tests

```bash
pip install -r requirements.txt aiosqlite greenlet
cd cli && pip install -e . && cd ..
```

RSA-4096 operations are CPU-expensive enough that the full suite is split:

```bash
# Everything else (~2-3 min)
python -m pytest tests/unit/ tests/cli/ tests/integration/ \
  --ignore=tests/integration/v3/test_v3_transit.py \
  --ignore=tests/integration/v3/test_v3_pki.py \
  --no-cov -q

# RSA-heavy (~20 sec)
python -m pytest tests/integration/v3/test_v3_transit.py tests/integration/v3/test_v3_pki.py --no-cov -q
```

**553 tests passing** across both runs — 0 failures, 0 regressions across all six versions.

Just the v6 Security Operations tests:
```bash
python -m pytest tests/unit/v6/ tests/integration/v6/ --no-cov -q
```

---

## Tech Stack

| | Technology |
|---|---|
| Runtime | Python 3.12 |
| Framework | FastAPI 0.111 |
| Database | PostgreSQL 16, managed via Alembic |
| ORM | SQLAlchemy 2.0 (async) |
| Encryption | AES-256-GCM, ChaCha20-Poly1305, RSA-4096, Ed25519 |
| AI | Google Gemini (`google-genai`), provider-agnostic abstraction |
| Identity | Real OIDC PKCE, JWKS, LDAP bind (`ldap3`) |
| Observability | OpenTelemetry, Prometheus (`prometheus_client`), Grafana |
| CLI | Click + Rich (`nvctl`) |
| Containers | Docker, Docker Compose, Kubernetes, Helm |
| Testing | Pytest + httpx + aiosqlite — 553 tests |

---

## Known Limitations (stated honestly)

- No live OIDC/LDAP/SAML server exists in the dev/test environment — every protocol implementation is real and correct, verified via its failure path against unreachable hosts.
- Multi-region replication is an in-process simulation with a real, swappable transport seam.
- The legacy v5 `PATCH /api/v5/ai/findings/{id}/status` endpoint remains admin-only and unconstrained by design — an intentional emergency override, not an oversight, sitting alongside the fully validated v6 workflow.
- CLI coverage does not extend to every REST capability (e.g. replication, marketplace) — those remain REST-only.

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
Built by <a href="https://github.com/Sudeep72">Sudeep Ravichandran</a> · MS Cybersecurity Risk Management @ Indiana University Bloomington

<br><br>

<b>v6.0.0 is the final release. No v7 planned.</b>
</div>
