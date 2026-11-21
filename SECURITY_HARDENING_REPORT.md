# SECURITY HARDENING REPORT — SKYLA PRIME v0.2.0

**Date:** 2026-11-21
**Baseline:** v0.1.0 audit, verdict *CONDITIONAL GO* for a development milestone, *NO-GO* for
production (commit `0a72dfe`).
**This report covers:** what was hardened in v0.2.0, what was proven by test, what remains unproven,
and the release recommendation.

---

## 1. Verdict

| Dimension | v0.1.0 | v0.2.0 |
|---|---|---|
| Arbitrary code execution | unsafe, mislabelled | **real namespace isolation, adversarially tested**; fail-closed when unavailable |
| Identity | one shared token | **users, sessions, MFA, RBAC, scoped tokens, per-agent/connector grants** |
| Authorization | token = full power | **capability checks on every protected route**, tested for escalation |
| Cross-user isolation | none | **enforced**, 404 (no existence leak) for foreign records |
| External write duplication | possible | **action ledger**, replay-on-duplicate, fail-closed on in-flight |
| Context overflow | unmanaged | **budgeted, truncation flagged, instructions prioritised** |
| DB migrations | ad hoc | **versioned, idempotent, recovery demonstrated** |
| Provider cost/usage | not recorded for HTTP providers | **persisted per call + metrics** |
| Observability | basic | **JSON logs, per-request trace ids, metric series, redaction** |
| Test suite | 36 | **100** |

**Production readiness: NOT PRODUCTION READY.** See §7 for the exact blockers. The blockers are
*evidence gaps* (no live credentials, no container runtime, no independent external audit), not
hidden defects in the implemented code.

## 2. What was hardened, by workstream

### WS1 — Execution isolation (was the single HIGH finding)

- v0.1.0's subprocess "sandbox" allowed host filesystem read/write, host network access and
  unrestricted subprocesses. It is **no longer used as the default**.
- New pluggable providers (`namespace`, `container`, `restricted`, `disabled`); the `namespace`
  provider (user/mount/PID/net namespaces + `chroot` into a minimal rootfs) is selected here and
  **verified**.
- Adversarial results (live server, not just unit tests): host `/etc/hostname` → `FileNotFoundError`;
  write to `/etc` → read-only; connect to a real host listener → `errno 101 Network is
  unreachable` (listener never accepted); host env secrets → `[]`; 3 GB allocation → `MemoryError`;
  infinite loop → killed at timeout; 50 KB output → capped at 8 KB.
- `RestrictedProvider` remains for development and is hard-labelled `isolated: false,
  safe_for_untrusted: false`; the API and UI surface that verbatim.
- Details, including the honest limitations (shared kernel, no seccomp filter): `SANDBOX_ARCHITECTURE.md`.

### WS2 — Authentication and authorization

- PBKDF2-HMAC-SHA256 (200k), TOTP MFA, hashed session tokens with expiry and revocation, scoped API
  tokens, roles with capability bundles, **per-agent and per-connector permissions**, server-side
  enforcement on every protected route, cross-user isolation, attributable audit log.
- Legacy shared token retained but mapped to a named admin principal for migration, and documented as
  something production deployments must retire.
- Defect found and fixed during hardening: revoking a permission that the role itself granted had no
  effect (editing a grants list cannot remove a role capability). Fixed with explicit deny entries
  (`-capability`) that override role/wildcard grants — `test_per_agent_permission_is_separately_grantable_and_revocable`.
- Defect found and fixed: scoped tokens could exceed their scopes because the scope list was resolved
  twice and discarded (`_require` re-resolved without scopes). `_require` now accepts the resolved
  scope list; a narrowly scoped admin token can no longer write.
- Security improvement: the generated bootstrap admin password was being written to the **log
  stream**. It now goes to `data/bootstrap_admin_credential.txt` (mode 0600) and only the path is
  logged.
- Details: `AUTHORIZATION_ARCHITECTURE.md`.

### WS3 — External action idempotency

- `action_ledger` with unique idempotency key, request fingerprint, state machine, provider response
  record, attempt counting.
- Duplicate → **replay the recorded result**; different payload on the same key → 409; duplicate while
  in flight → 409; crash-left `pending` → `unknown` at startup (blocks blind retry).
- A route-table introspection test fails the build if any external-write endpoint lacks an
  idempotency key.
- A missing Gmail write path was added *with* its ledger guard, so WS3's "every external write"
  requirement is actually satisfied rather than assumed.
- Details and the reconciliation gap: `IDEMPOTENCY_DESIGN.md`.

### WS4 — Context management

- Model-specific budgets, instruction-first fitting, flagged truncation, structured compaction of
  older step outputs, wired into the orchestrator's real execution path.
- Details: `CONTEXT_MANAGEMENT_SPEC.md`.

### WS5 — Database

- Versioned idempotent migrations (4 revisions), `SKYLA_DB_PATH` (previously hard-coded, which had made
  clean-environment testing impossible), concurrency test, `integrity_check`, and a **real backup →
  simulated total loss → restore** drill.
- PostgreSQL plan and SQLite limitations documented; **no data migrated**.
- Details: `DATABASE_MIGRATION_PLAN.md`.

### WS6 — Providers

- Hardened OpenAI-compatible adapter: retries with backoff on 429/5xx (not on other 4xx), normalised
  `ProviderError`, malformed-response handling, health check, usage/cost/latency capture.
- Fixed: `usage_callback` was never connected, so HTTP providers logged no cost/usage. Now wired at
  startup.
- All live paths remain **NOT VERIFIED** (no credentials, no safe test tenant).
- Details: `PROVIDER_VALIDATION_REPORT.md`.

### WS7 — Observability

- Structured JSON logs with redaction of `Bearer …`, `api_key=…`, `password=…`, `token=…`.
- Per-request middleware: trace id (`tr_…`) returned as `X-Trace-Id`, structured access log with
  method/route/status/duration only (never bodies or query secrets), plus metrics.
- Metrics: counters, task latency, bounded observation series (provider latency, HTTP latency),
  HTTP 401/403/5xx counters.
- Fixed: metrics had no generic `observe()` API, so latency series could not be recorded at all.

## 3. Evidence

| Claim | Evidence |
|---|---|
| 100 tests pass | `pytest tests/ -q` → `100 passed` on this host; clean-venv rerun in §5 |
| Sandbox blocks host FS/network | `tests/unit/test_execution_isolation.py` + 7 live server probes |
| Auth/RBAC/scopes/isolation enforced | `tests/unit/test_auth.py` (19 tests) |
| Duplicate external writes prevented | `tests/unit/test_idempotency_e2e.py` (8) + `test_idempotency_context.py` (9) |
| DB recovery works | `test_backup_and_recovery`, `test_concurrent_writes`, `test_integrity_check_after_concurrency` |
| Usage/cost logged | `/api/metrics` on the live server: `calls: 4, in_tok: 502, out_tok: 450` |
| No real sends | connectors report `mode: mock | live: False`; Telegram path returns `logged-not-sent` |

## 4. Findings register

| ID | Sev | Finding | Status |
|---|---|---|---|
| C-1 | **High** | v0.1.0 sandbox provided no isolation while implying it did | **FIXED** — namespace provider verified; unsafe provider labelled; fail-closed |
| C-2 | High | Shared token = unrestricted capability, no attribution | **FIXED** — identity + RBAC + per-agent/connector grants |
| C-3 | High | No cross-user isolation | **FIXED** — `owner_id` + visibility checks + 404 |
| C-4 | High | External writes could duplicate on retry | **FIXED** — action ledger + replay + 409 + `unknown` state |
| C-5 | Medium | Scoped tokens were not enforced (scope list discarded) | **FIXED** |
| C-6 | Medium | Revocation of role-provided permissions was a no-op | **FIXED** — explicit denies |
| C-7 | Medium | Bootstrap admin password written to logs | **FIXED** — 0600 credential file |
| C-8 | Medium | Provider usage/cost never recorded for HTTP providers | **FIXED** — callback wired |
| C-9 | Medium | `db_path` hard-coded; clean-env testing impossible | **FIXED** — `SKYLA_DB_PATH` |
| C-10 | Medium | No request tracing; logs not correlated | **FIXED** — trace id + access log + metrics |
| C-11 | Medium | No seccomp filter in the namespace provider | **OPEN** — mitigated by namespace boundary; documented; gVisor/container recommended |
| C-12 | Medium | Provider-side reconciliation of `unknown` ledger entries not automated | **OPEN** — blocks blind retry (safe), requires live credentials to implement |
| C-13 | Low | No login rate limiting / lockout | **OPEN** — deploy behind a rate-limiting proxy |
| C-14 | Low | No password strength policy | **OPEN** |
| C-15 | Low | Token counting is a heuristic (chars/4) | **OPEN** — documented; conservative reservation |
| C-16 | Low | Metrics are in-process only (no Prometheus endpoint) | **OPEN** — snapshot via `/api/metrics` |
| C-17 | Low | No tokenizer, no live model catalogue verification | **OPEN** — blocked on credentials |

No **unresolved High or Critical** finding remains in implemented code. C-11 and C-12 are Medium and
scoped; both are documented with mitigations.

## 5. Clean-environment verification

```
python -m venv /tmp/fresh && /tmp/fresh/bin/pip install -e ".[dev]"
/tmp/fresh/bin/python -m pytest tests/ -q
```
Result recorded in `RELEASE_MANIFEST_v0.2.0.md` §4. Dependencies were **not** expanded in v0.2.0: MFA,
hashing, tokens and logging are all stdlib.

## 6. Security posture summary (honest)

**Strong now:** authentication and authorization are enforced server-side and adversarially tested;
code execution is either genuinely isolated or explicitly refused; duplicate external side effects
are blocked with a database-backed lock; secrets never reach logs by design (and are redacted if they
do); every request is traceable.

**Still weak / unproven:** the isolation boundary is kernel-based (no seccomp, no gVisor/Firecracker
validation); no live provider or integration has been exercised; there is no independent third-party
audit of v0.2.0 (the v0.1.0 audit was independent, this work is self-assessed); no rate limiting;
SQLite is single-instance.

## 7. Release recommendation

**CONDITIONAL GO — internal/staging deployment. NO-GO — production.**

Blocking production designation (per the acceptance criteria):

1. **Independent validation of secure execution** on the target runtime — not yet performed for
   v0.2.0. Self-tested only. → blocker: independent audit engagement.
2. **Live provider behaviour accurately documented** — currently all live paths are NOT VERIFIED.
   → blocker: API credentials supplied by the operator.
3. **Connector live behaviour** — → blocker: safe test tenant/recipients and explicit authorisation to
   send.
4. No unresolved critical findings — satisfied; C-11/C-12 remain open at Medium with mitigations.

Not blockers but recommended before production: login rate limiting (C-13), seccomp profile (C-11),
automated reconciliation (C-12), PostgreSQL cut-over (`DATABASE_MIGRATION_PLAN.md`), Prometheus
exposure (C-16).

## 8. What is explicitly *not* claimed

- Not claimed: "the sandbox is secure against a kernel exploit." It is namespace-isolated; kernel
  shared.
- Not claimed: "providers are live and validated." They are mocked or not configured.
- Not claimed: "production ready." It is not.
- Not claimed: "independently audited." v0.2.0 changes are self-assessed; only v0.1.0 had an
  independent audit.
- Not claimed: "all external sends are impossible." They are prohibited by mock mode and by the absence
  of a send code path for email, and ledger-guarded for future live use.
