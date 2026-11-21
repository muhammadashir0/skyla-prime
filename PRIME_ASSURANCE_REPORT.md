# PRIME ASSURANCE REPORT — SKYLA PRIME v0.2.1

**Independent adversarial security and reliability validation of v0.2.0**
**Date:** 2026-11-21
**Target commit:** `6bbb293` (v0.2.0), branch `arena/2a497c0e-skyla-prime`
**Method:** source inspection of the security-critical paths, plus live attack against a running
instance and a fresh staging deployment. The implementer's test suite was **run but not trusted** as
evidence.

---

## 1. Bottom line

> **v0.2.0 is NOT production-ready, and the earlier "conditional GO for staging" was too generous for
> untrusted workloads.** Its cryptographic design, authorization model, database migration discipline and
> idempotency ledger are genuinely good and survived every escalation attempt I made. But the execution
> sandbox **cannot protect its own host**, the injection controls are **advisory rather than
> enforcing**, one endpoint pair **leaks and destroys other users' data**, and a **truncated database is
> reported as a healthy empty system**. During this assessment I crashed the server by design gap, not by
> exotic attack.

**Release decision: FAIL** (defects reproduced). Nothing is marked PASS on the strength of the
implementer's own tests alone.

| Area | Decision |
|---|---|
| Sandbox / execution isolation | **FAIL** |
| Prompt-injection and untrusted-content handling | **FAIL** |
| Cross-user data isolation | **FAIL** |
| Database recovery operations | **FAIL** |
| Authentication (cryptography/structure) | **PASS** |
| Authorization (RBAC, scopes, deny, per-agent/connector) | **PASS** |
| External action idempotency | **PASS** (reconciliation **FAIL**) |
| Provider behaviour | **NOT VERIFIED** |
| Migrations | **PASS** |
| Staging deployment / durability | **PASS** |

## 2. Status vocabulary

Exactly three statuses are used, as required:

- **PASS** — independently reproduced as correct by the assessor.
- **FAIL** — a defect was reproduced, with a procedure that reproduces it.
- **NOT VERIFIED** — the required environment, credential or independent evidence was unavailable.

## 3. The central finding: the test suite does not test the properties it is credited with

The implementer reported 100/100 passing. I re-ran it: **100 passed in 17 s**, on the very tree that
contains every defect below.

Why the suite cannot catch them:

| Defect | Why no test sees it |
|---|---|
| All capabilities retained | no test reads `CapEff`; `test_execution_isolation.py` never checks capabilities |
| 40 unbounded forks | no test forks or reads `RLIMIT_NPROC`; `grep -r "fork\|Popen" tests/` → **nothing** |
| Server killed by OOM | `test_memory_limit_enforced` asserts only that the *child* raises `MemoryError` — a child-side assertion proves nothing about host protection |
| Orphaned processes after timeout | no test inspects the process table after a timeout |
| Cross-user memory leak | `test_cross_user_isolation` covers **tasks only**; memories are never tested across users |
| 0-byte DB silent loss | `test_database_recovery` tests `integrity_check` after writes, never after truncation |
| Injection is advisory | `test_security.py` only asserts that patterns are *detected*, never that detection *blocks* |
| No throttling | no rate-limit test exists |

This is the most important assurance lesson of the exercise: **a green suite measured the code that
exists, not the properties that were claimed.** A test that asserts "the child got a MemoryError" is
silently promoted into "the host is protected" — and that inference is false.

## 4. Findings register

Severity: **C**ritical / **H**igh / **M**edium / **L**ow. Full reproduction detail is in the
per-area reports.

| ID | Sev | Finding | Area | Status |
|---|---|---|---|---|
| A-01 | **High** | Namespace sandbox retains **all 41 capabilities** (`CapEff 1ffffffffff`), `NoNewPrivs: 0`, uid 0; `libc.mount()` returns **rc 0**. Docs claim "dropped capabilities". | sandbox | FAIL |
| A-02 | **High** | **No PID limit** — 40 concurrent forks accepted; an unbounded storm drove host load to **13 989** | sandbox | FAIL |
| A-03 | **High** | **No aggregate memory/concurrency bound** — the API server was **SIGKILLed (exit 137)** by the OOM killer during testing | sandbox | FAIL |
| A-04 | **High** | **Timeout does not kill the process tree** — orphaned `python3 /workspace/script.py`, ppid 1, state `R`, still running after the 4 s timeout | sandbox | FAIL |
| A-05 | **High** | **Cross-user memory disclosure and destruction** — Bob read Alice's `ALICE-PRIVATE-CONTENT-9931` and `DELETE` returned 200 | authz | FAIL |
| A-06 | **High** | **Prompt injection is advisory, not enforced** — flagged task is queued and executed; hostile document is stored and re-served | injection | FAIL |
| A-07 | **High** | **Truncated (0-byte) DB starts cleanly, reports `schema 4`, 0 users, re-bootstraps admin** — silent total data loss reported healthy | database | FAIL |
| A-08 | **High** | **SSRF** — `fetch_url` has no private/loopback range check and follows redirects unvalidated | injection | FAIL (by inspection) / NOT VERIFIED (live) |
| A-09 | Medium | **No seccomp**, `Seccomp: 0` — wide syscall surface (`bpf`, `keyctl`, `io_uring`, `mount`, …) | sandbox | FAIL |
| A-10 | Medium | **No MFA replay protection** — identical TOTP accepted 5/5 times | authn | FAIL |
| A-11 | Medium | **No login throttling/lockout** — 12 rapid failures, no delay | authn | FAIL |
| A-12 | Medium | **Username enumeration by timing** — 3 ms (unknown) vs 77 ms (known) | authn | FAIL |
| A-13 | Medium | **Read-only principals can mint 30-day API tokens** (`POST /api/auth/tokens` gated on `tasks:read`) | authn | FAIL |
| A-14 | Medium | **No automated backup**; naive `cp` of a WAL DB yields `no such table: users` (silently useless backup) | database | FAIL |
| A-15 | Medium | **No startup `integrity_check`** — corruption detection relies on SQLite's own header parse | database | FAIL |
| A-16 | Medium | **No migration downgrade path** despite the plan describing reversible revisions | database | FAIL |
| A-17 | Medium | **Interrupted tasks are parked forever** — docstring claims "resumable"; no resume endpoint | database | FAIL |
| A-18 | Medium | **No CPU quota** — 5 s burn unaffected (docs claim `RLIMIT_CPU`) | sandbox | FAIL |
| A-19 | Medium | **No file quota** — 300 MB written to `/workspace` | sandbox | FAIL |
| A-20 | Medium | **Injection detector evadable** — 8/12 payload families bypass a 7-regex denylist | injection | FAIL |
| A-21 | Medium | **No password policy** — `"x"` accepted | authn | FAIL |
| A-22 | Medium | **Ledger reconciliation not implemented** — `unknown` is terminal; no provider-state adoption | idempotency | FAIL |
| A-23 | Medium | **No LSM confinement** (AppArmor/SELinux), no Landlock | sandbox | FAIL |
| A-24 | Low | Autonomy accepts **negative levels** (`-1` → 200); no range validation | autonomy | FAIL |
| A-25 | Low | Task ledger fingerprint omits `autonomy_level`/`title` (meeting endpoint includes it) — inconsistent | idempotency | FAIL |
| A-26 | Low | No MFA recovery codes; no admin MFA reset | authn | FAIL |
| A-27 | Low | No token rotation endpoint | authn | FAIL |
| A-28 | Low | No per-connector credential revocation endpoint | connectors | FAIL |
| A-29 | Low | Multi-process SQLite / network-FS safety untested (documented) | database | FAIL |
| A-30 | Low | Sandbox latency ~45 s in the worst batch (mount sequence + cold start) | reliability | FAIL |

**Totals: 8 High, 15 Medium, 7 Low (30 findings). No Critical.** One High (A-08) is by-inspection;
its live exploitation was blocked by environment egress with the server down at that moment.

## 5. What is genuinely strong (and should not be regressed)

This is not a system built on sand. Independent testing confirmed:

1. **Filesystem and network containment are real.** A planted host canary at `/tmp/host-canary/secret.txt`
   was unreachable; `/etc/passwd` did not exist; TCP gave `errno 101`; DNS failed; a real host listener
   was never connected to; `/tmp` was an empty private tmpfs. `--make-rprivate` is correct.
2. **Privilege escalation is closed.** A viewer was refused task creation, user creation, and code
   execution — *including* via a token it minted itself with `["execute","tasks:create","*"]`. The
   role ∩ scope intersection is implemented correctly, which is the part most implementations botch.
3. **Explicit-deny grants work.** Revoking a role-provided capability actually takes effect — an
   uncommon, correct refinement.
4. **Per-agent and per-connector authorization is enforced at the route**, before any model call:
   the plan is computed, every agent is checked, and every connector write requires
   `connector:<name>:write`.
5. **Cross-user isolation is correct for tasks and documents** (0 visible, 404 on direct fetch — no
   existence oracle). Only the memory endpoints are broken.
6. **Idempotency is properly implemented.** Duplicates replay the recorded result; fingerprint mismatch
   → 409; in-flight → 409; crash-left `pending` → `unknown` and blind retry is *refused*. The database's
   `UNIQUE` constraint is the arbiter.
7. **The Gmail connector cannot send mail.** Only drafts exist. The most consequential external action
   is absent from the codebase rather than merely disabled.
8. **Migrations are clean and idempotent**, all four of them, including the `PRAGMA table_info` guard.
9. **Data durability across a hard kill is demonstrated**: `kill -9`, restart, tasks + MFA secret +
   audit log + schema all intact.
10. **Secrets do not leak**: sandbox env is empty of credentials, tokens are hashed at rest, the
    bootstrap password goes to a `0600` file rather than the log, and log redaction covers
    `Bearer`/`api_key`/`password`/`token` shapes.

## 6. The pattern behind the High findings

Four of the eight High findings share one root cause: **claims were made in documentation for controls
that were never implemented**, and the tests were written against the *claims* rather than the
*mechanism*.

```
SANDBOX_ARCHITECTURE.md:65  "Dropped capabilities ... no host caps"   → CapEff 1ffffffffff
SANDBOX_ARCHITECTURE.md:68  "Process limit | RLIMIT_NPROC | capped"   → never set; load 13 989
SANDBOX_ARCHITECTURE.md:67  "CPU limit | RLIMIT_CPU"                  → never set
AUTHORIZATION_ARCHITECTURE.md  "cross-user isolation"                 → memories unbounded
DATABASE_MIGRATION_PLAN.md     "reversible migrations"                → no downgrade
```

The v0.2.0 release notes did contain a "known limitations" section, and `IDEMPOTENCY_DESIGN.md` was
scrupulously honest about reconciliation — so the *intent* to be honest was present. But the
sandbox table and the isolation claims drifted from the implementation, and because the tests were
written by the same author against the same mental model, the drift was invisible.

**Recommendation for the process, not just the code:** every security claim in a document should cite
an executable check that fails when the mechanism is removed (mutation-test the claim). A claim with no
such test is a hypothesis, not a control.

## 7. Production gate assessment

Against the stated acceptance criteria:

| Criterion | Result |
|---|---|
| Secure execution isolation independently validated | **FAIL** — 6 sandbox defects; isolation of FS/network only |
| Authentication and authorization tests pass | **PASS** for structure; **FAIL** for cross-user memory leak (High) |
| External action duplication controlled | **PASS** |
| Context handling tested | **PASS** (budget/truncation/compaction; retrieval not tested) |
| Database recovery demonstrated | **FAIL** — silent data loss, no automated backup |
| Provider behaviour accurately documented | **NOT VERIFIED** — no credentials; live paths unexercised |
| No unresolved critical/high findings | **FAIL** — 8 High open |

**Decision: FAIL.** Production is not permitted while any High finding remains open, and eight do.

## 8. What must be true before re-assessment

1. A-01…A-04 closed **and re-tested with mutation-style adversarial tests** (capability read-back,
   fork farm, cgroup enforcement, process-table inspection after timeout).
2. A-05 closed (ownership on memories; 404 for foreign ids).
3. A-06/A-08 closed (enforcement, not detection; SSRF guard).
4. A-07 closed (startup integrity gate; explicit init).
5. A-10…A-13 closed (replay tracking, throttling, passive timing, token mint capability).
6. A-14/A-15 closed (automated verified backup; startup integrity check).
7. A-02/A-03/A-04 re-run **on the release candidate**; the current evidence is that one authenticated
   request can terminate the service.

## 9. Assessment limitations (declared)

- Single assessor. The brief asked for a second independent reviewer; I mitigated the single-reviewer
  risk by deriving every test from **source inspection first** and then attacking the running system,
  and by explicitly searching for tests that the implementer's suite lacks. This is **not** a substitute
  for a second human reviewer + external pen-test, which remains required before production.
- No live provider or connector credentials existed, so provider/connector live behaviour is
  NOT VERIFIED throughout.
- gVisor and Firecracker could not be installed (no root, no KVM, no daemon), so their comparative
  assessment is analytical only.
- The live server was killed mid-assessment (A-03). Subsequent live tests used a fresh staging instance;
  DB files were backed up to `/tmp/db-backup-audit` beforehand and all destructive DB tests ran on
  disposable copies.
