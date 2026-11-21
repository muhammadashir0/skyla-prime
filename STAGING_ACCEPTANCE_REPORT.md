# STAGING ACCEPTANCE REPORT — SKYLA PRIME v0.2.1

**Deployment:** fresh copy of the repository tree into `/tmp/staging` (no `data/`, no prior state),
started with a clean virtualenv.
**Date:** 2026-11-21
**Environment:** single host, Python 3.11.2, unprivileged user (uid 1001), no Docker, no KVM,
no provider credentials.
**Result: 26 checks — 24 PASS · 2 FAIL · 0 NOT VERIFIED**

---

## 1. Deployment procedure used

```bash
rm -rf /tmp/staging && mkdir -p /tmp/staging
cp -a skyla apps pyproject.toml /tmp/staging/       # source only — no data/, no venv
cd /tmp/staging
SKYLA_ADMIN_PASSWORD='Staging-Accept-2026' \
SKYLA_DB_PATH=/tmp/staging/data/staging.db \
  python -m uvicorn skyla.api.app:app --host 0.0.0.0 --port 8020
```

This deliberately mounts a **new database path** so first-run behaviour is observable, and supplies the
admin password by environment so the one-time credential file path can be checked both ways.

## 2. Acceptance checklist

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Fresh start creates the database | **PASS** | `data/staging.db` created; `schema_version: 4` |
| 2 | No credential file when password supplied | **PASS** | `bootstrap_admin_credential.txt` absent (count 0) |
| 3 | Execution provider selection | **PASS** | `namespace` |
| 4 | Health endpoint | **PASS** | `200`, `status: ok` |
| 5 | Unauthenticated access refused | **PASS** | `GET /api/tasks` → `401` |
| 6 | Wrong password refused | **PASS** | `401` |
| 7 | Login issues a session | **PASS** | `sess_…` returned |
| 8 | Authenticated read works | **PASS** | `200` |
| 9 | Dashboard served | **PASS** | `GET /` → `200`, login form present |
| 10 | Static assets served | **PASS** | `/static/app.js` → `200` |
| 11 | Metrics endpoint | **PASS** | `200` with counters |
| 12 | Trace header on every response | **PASS** | `X-Trace-Id: tr_…` |
| 13 | **MFA enrolment** | **PASS** | 32-char secret issued; password-only then → `401`; password+code → `200` |
| 14 | **MFA survives restart** | **PASS** | secret persisted; login with a *new* code succeeded after restart |
| 15 | Task creation + completion | **PASS** | `completed`, 4 steps |
| 16 | Task persistence across crash | **PASS** | 1 task present after `kill -9` + restart |
| 17 | Model fallback / provider reporting | **PASS** | `providers: ["local"]`, health reports `MOCK` |
| 18 | Connectors all in mock mode | **PASS** | `gmail/calendar/telegram` → `mock` |
| 19 | Execution blocks host filesystem | **PASS** | `/etc/passwd` read `BLOCKED`, `isolated: True` |
| 20 | Crash-restart recovery | **PASS** | hard kill → clean start, `schema 4`, 9 audit events, data intact |
| 21 | Audit log populated | **PASS** | 9 events incl. `auth.login`, `auth.mfa.enable`, `task.create` |
| 22 | `SKYLA_DB_PATH` honoured | **PASS** | DB created at the requested path |
| 23 | Observability output | **PASS** | structured JSON logs + access log lines |
| 24 | Graceful behaviour with no provider keys | **PASS** | mock provider used, labelled `MOCK`, no false `LIVE` |
| 25 | **Login throttling under load** | **FAIL** | 12 rapid failures → 12 × `401`, no delay/lockout |
| 26 | **Execution isolation as advertised** | **FAIL** | provider reports `isolated: True, safe_for_untrusted: True` while retaining all capabilities and no resource limits (see `SANDBOX_SECURITY_ASSESSMENT.md`) |

## 3. Crash-recovery drill (detailed)

```
kill -9 <server pid>            → health 000 (process gone)
restart on the same DB path     → health 200
  re-login with MFA             → OK
  tasks persisted               → 1
  MFA secret persisted          → yes
  schema after crash            → 4
  audit events                  → 9
```

The restart also ran the v0.2.0 recovery hooks (`recover_interrupted`,
`recover_interrupted_ledger`) without error. **Durability of committed state across a hard kill is
confirmed** — this is the strongest result of the staging pass.

## 4. First-run observations

- Startup is silent and fast; the one-time credential path was correctly **not** used because
  `SKYLA_ADMIN_PASSWORD` was supplied. (Independently verified earlier in the session that the file is
  written with mode `0600` and that the password never appears in the log stream.)
- The dashboard loads before authentication and shows the sign-in overlay; no protected data is
  fetched pre-login (the client only calls the API after a session exists).
- `data/` is git-ignored, so a staging deploy does not inherit developer state — verified.

## 5. Deficiencies observed during acceptance

1. **The system reports `safe_for_untrusted: true` while demonstrably unable to contain resource
   abuse** (threat model T-02…T-05). A staging operator would reasonably conclude that arbitrary code
   is safe to execute. This is the most consequential acceptance failure: the *reporting* is wrong even
   where the *containment of filesystem/network* is right.
2. **No brute-force protection**, so a staging instance exposed to a network is immediately guessable.
3. A **crash-restart leaves interrupted tasks permanently parked** (`interrupted`), with no resume
   endpoint; operators will see dead tasks and no way to progress them.
4. Shutdown/restart is only safe because SQLite commits per statement; there is no explicit drain of
   in-flight orchestrator tasks. A task mid-step at kill time is parked (safe) but not recovered.

## 6. Verdict

**Staging acceptance: PASS for functional deployment and durability; FAIL for security acceptance.**

Everything needed to *run* the platform on a clean host works: bootstrap, identity, MFA, dashboard,
API, connectors in mock mode, observability, and — notably — **data durability across an ungraceful
kill**. No manual intervention was required to deploy.

It is not acceptable as a *security* baseline for untrusted workloads: the isolation provider
over-reports its guarantees, and authentication has no brute-force protection. Both are itemised with
remediations and are the gating items for the production decision in `PRIME_ASSURANCE_REPORT.md`.
