# NanoVault v5.0.0 — AI Security Platform

v5 = AI intelligence foundation. v6 = Security Operations Platform (deferred). Boundary preserved throughout.

## 1. Modified files (all additive, zero functionality removed)

- `app/main.py` — v5 router imports/registration, version bump 4.0.0 → 5.0.0
- `app/core/config.py` — appended `AI_ENABLED` (default `false`), `AI_PROVIDER`, `AI_MODEL`, `GEMINI_API_KEY`, `AI_REQUEST_TIMEOUT_SECONDS`, `AI_MAX_OUTPUT_TOKENS`, `AI_TEMPERATURE`, `AI_MAX_CONTEXT_ITEMS`
- `app/models/models.py` — appended `AIFinding` model + 4 new `AuditAction` enum values (`AI_ANALYSIS_RUN`, `AI_SEARCH_QUERY`, `AI_FINDING_CREATE`, `AI_FINDING_STATUS_CHANGE`)
- `scripts/generate_env.py` — appended commented-out AI config block (disabled by default, no key ever written)
- `cli/nvctl/main.py` — appended `ai` command group
- `requirements.txt` — appended `google-genai`
- `release/VERSION` — bumped to `5.0.0`

## 2. New files

```
app/services/v5/ai_provider_service.py       # AIProvider ABC + GeminiProvider
app/services/v5/guardrails_service.py        # redaction + prompt-injection defense
app/services/v5/security_context_service.py  # composes existing v1-v4 services
app/services/v5/ai_security_engine.py        # orchestration: context->request->validate->finding->audit
app/services/v5/security_analyst_service.py  # event explanation + investigation Q&A
app/services/v5/ai_search_service.py         # NL search, deterministic source routing
app/services/v5/findings_service.py          # AIFinding CRUD
app/services/v5/ai_metrics_service.py        # Prometheus metrics on the existing registry

app/api/v5/endpoints/ai_status.py            # status, health, metrics
app/api/v5/endpoints/ai_analysis.py          # explain, investigate
app/api/v5/endpoints/ai_search.py            # search
app/api/v5/endpoints/ai_findings.py          # list, get, update status

tests/unit/v5/*.py        (5 files, 32 tests)
tests/integration/v5/*.py (3 files, 18 tests)
tests/cli/test_cli_v5_ai_commands.py (8 tests)
```

## 3. Gemini integration details

- Official SDK: `google-genai`, called via `genai.Client(api_key=...)` → `client.models.generate_content(...)`
- Structured output enforced via `response_mime_type="application/json"` + `response_schema=FINDING_SCHEMA` (Gemini's native JSON-schema-constrained generation)
- `system_instruction` carries the prompt-injection guardrail framing separately from the untrusted context payload (uses Gemini's dedicated parameter rather than concatenating everything into one prompt string)
- Async call wrapped via `asyncio.to_thread` + `asyncio.wait_for(timeout=AI_REQUEST_TIMEOUT_SECONDS)` since the SDK's `generate_content` is synchronous
- Token usage read from `response.usage_metadata` (real, not estimated) and fed into Prometheus counters

## 4. Environment variables

| Variable | Default | Required for AI to work |
|---|---|---|
| `AI_ENABLED` | `false` | Set to `true` |
| `AI_PROVIDER` | `gemini` | Leave as-is (only implemented provider) |
| `AI_MODEL` | `gemini-2.0-flash` | Any valid Gemini model name |
| `GEMINI_API_KEY` | `""` (empty) | **Yes — set to your real key** |
| `AI_REQUEST_TIMEOUT_SECONDS` | `20` | Optional |
| `AI_MAX_OUTPUT_TOKENS` | `2048` | Optional |
| `AI_TEMPERATURE` | `0.2` | Optional |
| `AI_MAX_CONTEXT_ITEMS` | `50` | Optional — caps context size sent per request |

## 5. New REST APIs (`/api/v5`)

```
GET   /api/v5/ai/status                        AI enabled/configured status (any authenticated user)
GET   /api/v5/ai/health                         Provider reachability check [Admin]
GET   /api/v5/ai/metrics                        AI metrics summary pointer [Admin]
POST  /api/v5/ai/explain                        Explain an audit event
POST  /api/v5/ai/investigate                    Free-form investigation Q&A on an event
POST  /api/v5/ai/search                         Natural-language security search
GET   /api/v5/ai/findings                       List findings (filter by category/severity/status)
GET   /api/v5/ai/findings/{id}                  Get one finding
PATCH /api/v5/ai/findings/{id}/status           Triage a finding [Admin]
```

## 6. New CLI commands

```
nvctl ai status
nvctl ai health
nvctl ai explain <audit_log_id> [--question TEXT]
nvctl ai investigate <audit_log_id> <question>
nvctl ai search <query>
nvctl ai findings [--category] [--severity] [--status]
```

## 7. Database changes

New table: `ai_findings` (category, severity, confidence, status, summary, evidence, explanation, recommended_actions, related_entities, ai_provider, ai_model, latency_ms, created_by, timestamps). **No raw prompt or raw model response text is stored anywhere** — structurally guaranteed and tested (`test_findings_never_contain_raw_prompt_or_response`). Created via the existing `Base.metadata.create_all` pattern — no migration file needed, consistent with v3/v4.

## 8. Security / guardrail implementation

- **RBAC inheritance by construction**: `security_context_service` never queries the DB directly for anything sensitive — it calls the same `secret_service`, `policy_service`, `replay_service`, etc. functions a human-facing endpoint already uses, so authorization is inherited rather than reimplemented. `explain`/`investigate` additionally re-check `current_user.id == log.user_id or is_admin` before building context (tested: `test_rbac_cannot_explain_other_users_event`).
- **Field-level redaction**: `strip_forbidden_fields()` recursively removes `password`, `value`, `access_token`, `private_key`, etc. from every context dict before serialization (defense in depth on top of context sources already being metadata-only).
- **Pattern-level redaction**: `redact_ai_context()` extends the existing v3 `secure_redaction` with AI-specific patterns (PEM private key blocks, JWTs, DB connection strings).
- **Prompt-injection defense**: untrusted content is delimited (`<<<UNTRUSTED_SECURITY_CONTEXT_DATA>>>...<<<END...>>>`) with an explicit system instruction that content inside the delimiters is data, never instructions. A found-and-fixed real gap during testing: JSON-escaping a malicious field alone doesn't neutralize delimiter-shaped text for an LLM reading flat text, so `_neutralize_delimiter_spoofing()` strips literal delimiter occurrences from field values before serialization — caught by `test_malicious_context_field_cannot_break_out_of_delimiters`.
- **Deterministic search routing**: `AISearchService._select_sources()` is pure keyword matching — the model never generates or executes a query; it can only receive data from a fixed, pre-approved set of context-gathering functions.
- **Structured output validation**: Gemini's `response_schema` constrains generation at the API level; `AISecurityEngine._validate_finding_shape()` independently re-validates every required field and enum value before anything reaches the findings table.
- **Auditability without leakage**: every AI operation logs `AI_ANALYSIS_RUN` with task/outcome/provider metadata — never the prompt or response content.

## 9. Tests and results — 513 total, 0 failing

| Suite | Count |
|---|---|
| v1-v4 existing (unchanged) | 431 |
| v3 RSA-heavy (unchanged) | 20 |
| v5 unit (provider, guardrails, engine validation, prompt injection, context) | 32 |
| v5 integration (status, analysis w/ mocked Gemini, search, findings, RBAC) | 18 |
| v5 CLI | 8 |
| CLI v4 (unchanged) | 17 |
| **Total** | **513, 0 failed, 0 regressions** |

Per your explicit instruction, **no Gemini API key was fabricated anywhere**. Real code paths tested for real: `AI_ENABLED=false` default (integration tests confirm `/api/v5/ai/status` reports `configured: false` in this environment), unconfigured-provider `AIProviderUnavailableError`, and a genuine `asyncio.wait_for` timeout. Success/malformed-JSON/mocked-generation paths use `unittest.mock` against the SDK client object — never a real network call.

## 10. Exact steps to configure and test with a real Gemini key

```bash
# 1. Get a key from https://aistudio.google.com/apikey

# 2. Set it as an environment variable (never commit it)
export GEMINI_API_KEY="your-real-key-here"
export AI_ENABLED=true
export AI_PROVIDER=gemini
export AI_MODEL=gemini-2.0-flash
# or add the same 4 lines to your .env file (uncomment the block scripts/generate_env.py writes)

# 3. Restart the server so config reloads
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# 4. Verify it's really configured
curl -s http://localhost:8000/api/v5/ai/status -H "Authorization: Bearer $TOKEN"
# expect: {"enabled": true, "configured": true, "provider": "gemini", "model": "gemini-2.0-flash", "message": "OK"}

curl -s http://localhost:8000/api/v5/ai/health -H "Authorization: Bearer $ADMIN_TOKEN"
# expect: {"available": true, "message": "Gemini API reachable", ...}

# 5. Trigger a real explanation against a real audit event
curl -s -X POST http://localhost:8000/api/v1/secrets -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"key":"test/ai","value":"v1"}'
# get the resulting audit_log_id from GET /api/v1/audit/my, then:
curl -s -X POST http://localhost:8000/api/v5/ai/explain -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"audit_log_id":"<id>"}'

# CLI equivalent:
nvctl ai status
nvctl ai explain <audit_log_id>
nvctl ai search "show recent login activity"
```

If the key is invalid, expect `error_type: "auth_error"` in the response — real Gemini rejection, handled cleanly, core NanoVault functionality unaffected either way.

## 11. Features intentionally deferred to v6

Per the v5/v6 boundary: full SOC workflow, incident lifecycle management, alert triage pipelines, case management, automated response/SOAR-style playbooks, cross-system incident coordination, large-scale security operations dashboards. v5 findings are the raw intelligence layer v6 would operationalize into that workflow — nothing here builds toward those v6 features prematurely.
