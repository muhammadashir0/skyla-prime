# RELEASE MANIFEST — SKYLA PRIME v0.2.0

**Release:** v0.2.0 — Security & Reliability Engineering
**Date:** 2026-11-21
**Branch:** `arena/2a497c0e-skyla-prime` (base `cb4cfce`)
**Previous release:** v0.1.0 (`f25201c`), audit fixes (`0a72dfe`)
**Verdict:** **CONDITIONAL GO — internal/staging. NOT PRODUCTION READY.**

---

## 1. Summary of change

v0.2.0 hardens the audited v0.1.0 foundation. It adds isolation, identity, idempotency, context
management, versioned migrations, provider telemetry and observability — **without** rebuilding the
system: routing, orchestration, agents, knowledge and connectors keep their v0.1.0 shape and API.

| Workstream | Delivered | Verified |
|---|---|---|
| 1. Execution isolation | 4 pluggable providers, namespace isolation default | **Yes** — 12 adversarial tests + 7 live probes |
| 2. Auth/authz | users, PBKDF2, TOTP MFA, sessions, scoped tokens, RBAC, per-agent/connector grants, isolation | **Yes** — 16 tests |
| 3. Idempotency | action ledger, fingerprints, replay, conflict/in-flight 409, `unknown` recovery | **Yes** — 16 tests |
| 4. Context | budgets, truncation flags, compaction, orchestrator wiring | **Yes** — 8 tests |
| 5. Database | 4 versioned migrations, `SKYLA_DB_PATH`, backup/restore drill, PG plan | **Yes** — 10 tests; PG migration **not executed** |
| 6. Providers | retries, error normalisation, health, usage/cost, status honesty | **Partial** — mock-verified; **live NOT VERIFIED** |
| 7. Observability | JSON logs, trace ids, metrics, redaction | **Yes** — 7 tests |
| 8. Regression | 36 → 100 tests, clean-venv rerun | **Yes** |

## 2. Files

### Added
```
skyla/auth.py                       175  PBKDF2, TOTP, sessions, scoped tokens, RBAC, grants
skyla/execution/providers.py        187  namespace/container/restricted/disabled providers
skyla/core/context.py                74  context budget, truncation, compaction
skyla/observability.py               99  JSON logs, redaction, metrics, trace ids
tests/unit/test_auth.py             235  16 auth/authz/isolation tests
tests/unit/test_execution_isolation.py 118  12 adversarial sandbox tests
tests/unit/test_idempotency_context.py  62  ledger + context tests
tests/unit/test_idempotency_e2e.py    96  end-to-end idempotency through the API
tests/unit/test_database_recovery.py 124  migrations, concurrency, backup/restore
tests/unit/test_observability_providers.py 130  provider pipeline + observability
SECURITY_HARDENING_REPORT.md
SANDBOX_ARCHITECTURE.md
AUTHORIZATION_ARCHITECTURE.md
IDEMPOTENCY_DESIGN.md
CONTEXT_MANAGEMENT_SPEC.md
DATABASE_MIGRATION_PLAN.md
PROVIDER_VALIDATION_REPORT.md
RELEASE_MANIFEST_v0.2.0.md   (this file)
```

### Modified
```
skyla/api/app.py           501  auth endpoints, RBAC gates, ledger guards, trace middleware,
                                provider health, metrics, Gmail draft endpoint, bootstrap creds
skyla/db.py                385  v0.2.0 tables, migrations 1-4, ledger, usage, grants, recovery
skyla/config.py                 SKYLA_DB_PATH (was hard-coded)
skyla/models/http_provider.py   retries, ProviderError, health_check, usage callback
skyla/core/orchestrator.py      context fitting + usage logging + metrics
apps/web/static/{index.html,app.js,style.css}   real sign-in/MFA flow, in-memory session
tests/conftest.py               isolated temp DB, legacy-token admin, provider env
tests/unit/test_api.py          rewritten for authenticated access
tests/unit/test_audit_fixes.py  regression tests retained
README.md                       v0.2.0 status and quick start
docs/API_REFERENCE.md           auth section, new endpoints, capability requirements
```

## 3. Dependencies

**No new runtime dependencies.** MFA (TOTP), password hashing, token generation and structured logging
were implemented on the standard library (`hmac`, `hashlib`, `base64`, `secrets`, `logging`, `json`).
Rationale: the constraints forbid unnecessary dependencies, and each of these is small enough to own.

`pyproject.toml` is unchanged: fastapi, uvicorn, pydantic, httpx (+ pytest, pytest-asyncio,
python-multipart for dev).

## 4. Test report

Environment: fresh virtualenv, `pip install -e ".[dev]"`, Python 3.11.2, this host.

```
$ python -m pytest tests/ -q
100 passed, 1 warning in 36.48s
```

The single warning is a third-party deprecation notice from `starlette.testclient` about `httpx`
(not from this code).

### 4.1 Distribution

| Test module | Count | Covers |
|---|---:|---|
| `test_api.py` | 12 | health, auth required, dashboard, task flow, idempotent task create, autonomy ceiling, connectors, models, knowledge, workflows, metrics, provider health |
| `test_auth.py` | 16 | hashing, TOTP, login/logout, wrong password, MFA enforcement, RBAC (viewer/operator/admin), scoped tokens, revocation, cross-user isolation, per-agent grants, per-connector grants, scope-escalation refusal, grant persistence |
| `test_execution_isolation.py` | 12 | provider honesty, host FS invisible, host write blocked, workspace writable, **network blocked (real listener)**, subprocess containment, memory limit, timeout, output cap, no inherited secrets, provider selection |
| `test_database_recovery.py` | 10 | schema version, migration idempotency, table presence, concurrency (8×30), backup→loss→restore, integrity check, interrupted task/ledger recovery, usage logging, end-to-end task lifecycle |
| `test_idempotency_e2e.py` | 8 | meeting/telegram/gmail replay, conflict 409, in-flight 409, route-table invariant, no real sends |
| `test_idempotency_context.py` | 8 | ledger state machine, token estimate, truncation flags, instruction priority, compaction, per-model limits |
| `test_observability_providers.py` | 7 | redaction, provider success+usage, retry on 429, error normalisation, metrics, trace id, secret shapes |
| `test_router.py` | 7 | task classification, routing candidates, fallback |
| `test_security.py` | 6 | autonomy ceiling, injection scanning, untrusted content |
| `test_audit_fixes.py` | 4 | sandbox honesty, resource limits, provider reporting, memory delete |
| `test_planner.py` | 3 | decomposition, agent assignment |
| `test_sandbox.py` | 3 | legacy runner contract |
| `test_knowledge.py` | 2 | ingest/search |
| `test_orchestrator.py` | 2 | lifecycle, verification |
| **Total** | **100** | |

### 4.2 Required categories (WS8) — mapping

| Category | Where |
|---|---|
| Unit | all `test_*.py` |
| Integration | `test_api.py`, `test_idempotency_e2e.py`, `test_database_recovery.py::test_end_to_end_task_lifecycle` |
| Security | `test_security.py`, `test_auth.py`, `test_execution_isolation.py` |
| Sandbox | `test_execution_isolation.py`, `test_sandbox.py`, `test_audit_fixes.py` |
| Authentication | `test_auth.py` |
| Concurrency | `test_database_recovery.py::test_concurrent_writes` |
| Database | `test_database_recovery.py` |
| Provider | `test_observability_providers.py`, `test_router.py` |
| Idempotency | `test_idempotency_e2e.py`, `test_idempotency_context.py` |
| End-to-end | `test_end_to_end_task_lifecycle`, `test_task_flow` |
| Failure recovery | `test_backup_and_recovery`, `test_recover_interrupted_*`, `test_interrupted_operation_is_not_silently_reexecuted` |

### 4.3 Live-system verification (running server, not tests)

| Check | Result |
|---|---|
| `GET /api/tasks` without credential | **401** |
| Login with correct password | 200, session token issued |
| Login with wrong password | **401** |
| Task create → poll | `completed`, 4 steps, verification present |
| `GET /api/health` | `execution: {provider: namespace, isolated: true, safe_for_untrusted: true}`, `schema_version: 3`* |
| `GET /api/metrics` | `agent_calls: 4`, `usage: {calls: 4, in_tok: 502, out_tok: 450}` |
| Sandbox: read host `/etc/hostname` | **blocked** (`FileNotFoundError`) |
| Sandbox: write `/etc` | **blocked** (read-only fs) |
| Sandbox: connect to host :8000 | **blocked** (`errno 101`) |
| Sandbox: root listing | only sandbox dirs |
| Sandbox: 3 GB allocation | **MemoryError** |
| Sandbox: infinite loop | killed at timeout |
| Sandbox: env secrets | `[]` |

\* `schema_version` was 3 when that probe ran; migration 4 (grants) was added afterwards and the suite
reports 4. Test `test_schema_version_tracked` asserts the live value matches `max(MIGRATIONS)`.

## 5. Git review

The change set is staged on `arena/2a497c0e-skyla-prime`. Review checklist:

- No secret in any tracked file (`.env.example` holds placeholders only; `data/` is git-ignored,
  including `bootstrap_admin_credential.txt`).
- No force-push, no history rewrite, no branch deletion.
- Existing v0.1.0 work preserved: all v0.1.0 modules remain, tests retained and extended.
- Documentation matches implementation: every endpoint documented in `docs/API_REFERENCE.md` was
  checked against the live route table; every claim in the v0.2.0 documents is backed by a test or a
  recorded probe, and negative claims are labelled NOT VERIFIED.
- `python -m compileall` equivalent: `import skyla.api.app` succeeds in a clean venv.

## 6. Breaking changes / migration notes

| Change | Impact | Action |
|---|---|---|
| Authentication is now required on all `/api/*` except `/api/health` and `/api/auth/login` | clients using no token break | log in, or set `SKYLA_API_TOKEN` for the legacy admin path |
| `SKYLA_ADMIN_PASSWORD` recommended | otherwise a one-time credential file is created at `data/bootstrap_admin_credential.txt` | set the env var in any managed deployment |
| Execution requires the `execute` capability (operator+) | viewers cannot run code | intended |
| Task creation requires `agent:<name>:run` | viewers cannot create tasks | intended; grant per agent if needed |
| New DB tables/columns | automatic, idempotent | none — migrations run at startup |
| `SKYLA_DB_PATH` respected | deployments with a custom path must set it | note the default is unchanged |

## 7. Blockers for production (unchanged criteria)

1. **Independent validation of execution isolation** on the target runtime — no third-party audit of
   v0.2.0 exists. *Blocker: audit engagement.*
2. **Live provider validation** — every live model path is NOT VERIFIED. *Blocker: API credentials.*
3. **Live connector validation** — no safe test tenant/recipient; sending is unauthorised here.
   *Blocker: test accounts + explicit authorisation.*
4. **Open Medium findings** (documented, mitigated, not resolved): no seccomp filter in the namespace
   provider (C-11); no automated provider-side reconciliation for `unknown` ledger entries (C-12).

Additionally recommended before production: login rate limiting (C-13), password policy (C-14), exact
token counting (C-15), Prometheus export (C-16), PostgreSQL cut-over (WS5 plan).

## 8. Release decision

**CONDITIONAL GO for internal/staging.** The implemented controls are tested and behaved correctly in
every probe performed; the defects found during this workstream (C-5, C-6, C-7, C-8, C-9, C-10, plus
the never-connected usage callback) were fixed and regression-tested.

**NO-GO for production**, on the acceptance criteria as written: isolation has not been independently
validated, live providers and connectors are unverified, and two Medium findings remain open. None of
these can be closed in this environment without infrastructure, credentials or authorisation.

No capability has been described as production-ready, live or verified unless a test or recorded probe
supports it.

## 9. How to run

```bash
pip install -e ".[dev]"
export SKYLA_ADMIN_PASSWORD='choose-a-strong-password'
python3 -m uvicorn skyla.api.app:app --host 0.0.0.0 --port 8000
# sign in at http://localhost:8000
python3 -m pytest tests/ -q
```

Optional configuration: `SKYLA_DB_PATH`, `SKYLA_MAX_AUTONOMY`, `SKYLA_EXECUTION_PROVIDER`
(`namespace|container|restricted|disabled`), provider keys per `.env.example`.
