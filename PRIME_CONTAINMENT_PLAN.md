# SKYLA PRIME v0.3.0 — PRIME CONTAINMENT Plan

**Trigger:** the independent v0.2.1 PRIME ASSURANCE audit returned **FAIL** with 30 findings (0 Critical, 8 High, 15 Medium, 7 Low).
**Objective:** close the Critical/High findings with *verified* controls, not asserted ones.
**Constraint:** this release adds **no** new intelligence capability, agent, integration or UI feature. Remediation only.

The audit documents (`PRIME_ASSURANCE_REPORT.md`, `THREAT_MODEL.md`, `SANDBOX_SECURITY_ASSESSMENT.md`, `AUTHENTICATION_REVIEW.md`, `EXTERNAL_ACTION_INTEGRITY.md`, `DATABASE_RECOVERY_REPORT.md`, `STAGING_ACCEPTANCE_REPORT.md`, `RELEASE_MANIFEST_v0.2.1.md`) are **historical evidence and are not modified**.

---

## 1. Missions

| # | Mission | Finding(s) | Priority | Status |
|---|---|---|---|---|
| M1 | Execution host protection | A-01..A-04, A-09, A-18, A-19 | P0 | **PASS** (cgroups **NOT VERIFIED**) |
| M2 | Cross-user memory isolation | A-05 | P0 | **PASS** |
| M3 | Prompt injection & trust enforcement | A-06 | P0 | **PASS** |
| M4 | SSRF protection | A-08 | P0 | **PASS** (egress proxy **NOT VERIFIED**) |
| M5 | DB integrity & recovery | A-07, A-14, A-15, A-16 | P0 | **PASS** (backup drills **NOT VERIFIED**) |
| M6 | MFA & auth hardening | A-10, A-11, A-12 | P1 | **PASS** for replay/throttle/timing; A-13/21/26/27/28 **NOT VERIFIED** |
| M7 | Mutation-based regression tests | — | P0 | **PASS** (13/13 mutations detected) |
| M8 | Documentation & release governance | — | — | this document set |

Execution order was P0-first (M1 → M2 → M3 → M4 → M5 → M7), then M6 (P1), then M8.

---

## 2. Design decisions taken up front

1. **Fail closed, always.** If a contained runtime is unavailable, refuse untrusted execution. No silent degradation to an unprotected provider — the v0.2.0 behaviour that made the audit's sandbox findings possible.
2. **Separate the execution service from the API.** The supervisor is a distinct compiled program exec'd after all controls are installed, with its own resource limits; the API process is never exposed to workload consumption.
3. **Controls must be readable from the kernel.** Every claim is answerable by a workload reading `/proc/self/status`, or by a database query, or by observing an orphan count. "The API said it was isolated" is not evidence.
4. **The security boundary must not depend on classification.** Trust is a property of provenance (where text came from), not of wording (what the text says). This is what makes M3 sound without a perfect detector.
5. **Authority is enforced in the data layer.** Tenant constraints go in the `WHERE` clause, not in a Python filter after a general fetch.
6. **Ambiguity is refusal.** For the database, "I cannot tell whether this is a new deployment" must never resolve to "treat it as new".

---

## 3. Work performed

### M1 — execution host
Wrote `skyla/execution/skyla-sup.c` (C supervisor) and `skyla/execution/workload.py` (Python driver). Control order: fd sanitation → `no_new_privs` → Landlock → `chroot` → rlimits → capability drop with **verified read-back** → seccomp → `execve`. Namespaces created by `unshare -Urmpf -n`. Termination by PID-namespace kill plus a `/proc` sweep, with the result **verified** rather than assumed. Rewrote `providers.py` so `auto` never selects the unsafe provider. Added `service.py` (`CapacityGovernor`) so aggregate concurrency and memory are bounded separately from per-workload limits.

Three order-dependent bugs were found and fixed by measurement, not reasoning:
Landlock must precede `chroot` (rules are inode-based); `chroot` must precede the uid drop; denying `execve` in seccomp breaks the supervisor's own final exec.

### M2 — memory isolation
Migration v5 adds `memories.owner_id NOT NULL` and backfills legacy rows. All memory operations replaced with tenant-scoped SQL. Added `GET /{id}`, `PATCH /{id}` and `memory-export` so no endpoint is left unscoped. Foreign ids return **404**, not 403, so existence stays private.

### M3 — trust boundary
New `skyla/trust.py`: provenance ranks, action floors, `TrustedText`, `require_authority`, `risk_score`. The injection scanner is demoted to a risk signal that can only make the system stricter. Gates added to task creation, code execution and every connector write; documents are labelled `UPLOADED_DOC` with `authority: none`.

### M4 — SSRF
New `skyla/netguard.py`: resolve-then-vet, blocked IPv4/IPv6 ranges (including IPv4-mapped), metadata hosts, non-web ports, credential-bearing URLs, ambiguous numeric hosts. Rewrote `research.fetch_url` to walk redirects manually with per-hop revalidation.

### M5 — database
New `skyla/dbguard.py`: 7-state fail-closed classification, `PRAGMA integrity_check`, checksums, read-only inspection, explicit bootstrap. Wired into API startup before any write. The database is now created `0600` in a `0700` directory.

### M6 — auth
TOTP replay protection via an atomic conditional `UPDATE` on `users.mfa_last_step` (migration v6). New `skyla/throttle.py` for per-account lockout and per-source throttling. Unknown users pay a dummy-hash cost to close the timing oracle.

### M7 — regression suite
131 security tests asserting against live kernel/DB state, plus 13 mutations (5 built from mutated C source) that prove each control is load-bearing.

### M8 — documentation
This document set. Each finding is recorded below with its original reproduction, root cause, remediation, coverage, independent retest and status.

---

## 4. Finding register

Legend: **Status** is `PASS` / `FAIL` / `NOT VERIFIED` per the release vocabulary. "Retest" = what an independent reviewer must run.

### High

| ID | Finding | Root cause | Remediation | Test coverage | Independent retest | Status |
|---|---|---|---|---|---|---|
| A-01 | Capabilities retained in sandbox | rlimits only; no capability drop | PR_CAPBSET_DROP loop + capset + read-back verification (exit 112 on mismatch) | `test_capabilities_are_actually_zero`, `test_bounding_set_is_empty`, mutation | run workload printing `CapEff`; must be `0000000000000000` | **PASS** |
| A-02 | No PID limit | no `RLIMIT_NPROC` | `RLIMIT_NPROC` set, read back, bounded probe | `test_process_limit_is_enforced` + mutation | bounded 40-attempt fork probe must stop below 40 | **PASS** |
| A-03 | No aggregate memory/concurrency limit | no ceiling on N sandboxes | `CapacityGovernor` (BoundedSemaphore, 429 on saturation) + memory clamp | governor tests, `stats()` in every response | 3 concurrent requests → 429 | **PASS** (per-worker) |
| A-04 | Timeout leaves orphans | only the direct child was killed | PID-namespace kill + `/proc` sweep + verified boolean | `test_double_forked_grandchild_is_killed` | double-fork, 5 s timeout, assert 0 survivors | **PASS** |
| A-05 | Cross-user memory access | no owner column | `owner_id NOT NULL`, tenant predicates in SQL, 404 on foreign ids | 11 tenant tests + mutation | create as A, attempt read/update/delete/export as B | **PASS** |
| A-06 | Prompt injection advisory only | detection returned to caller, task ran anyway | provenance-based authority; untrusted provenance cannot authorize | 25 trust tests (40 injection cases) + mutation | inject into a document, attempt a connector write | **PASS** |
| A-07 | 0-byte DB silently re-initialised | new/existing indistinguishable | 7-state fail-closed guard, read-only inspection, explicit bootstrap | 17 DB tests + mutation | truncate DB, restart; must refuse and preserve bytes | **PASS** |
| A-08 | SSRF in research fetcher | no URL validation, redirects followed | resolve-then-vet netguard, per-hop revalidation | 45 SSRF tests + mutation | fetch `http://169.254.169.254/`, and a public→loopback redirect | **PASS** |

### Medium

| ID | Finding | Status | Note |
|---|---|---|---|
| A-09 | seccomp absent/false | **PASS** | allowlist filter; `Seccomp: 2` from procfs; socket/ptrace/bpf/keyctl/mount denied |
| A-10 | TOTP replay accepted | **PASS** | atomic monotonic claim; 8-thread race admits exactly one |
| A-11 | No login throttling | **PASS** | per-account + per-source, 429 + `Retry-After` |
| A-12 | Timing enumeration | **PASS** | dummy-hash path equalises unknown-user cost |
| A-13 | 30-day viewer token | **NOT VERIFIED** | TTL unchanged; see `MFA_REPLAY_PROTECTION.md` §7 |
| A-14 | Naive WAL copy backup | **NOT VERIFIED** | checksums done; online-backup API not wired in |
| A-15 | No `integrity_check` | **PASS** | `PRAGMA integrity_check`; page corruption detected |
| A-16 | No downgrade guard | **PASS** | `SCHEMA_TOO_NEW` refuses |
| A-17 | Tasks unresumable | **NOT VERIFIED** | out of P0 scope; unchanged |
| A-18 | No CPU quota | **PASS** | `RLIMIT_CPU` + wall-clock backstop (per-process) |
| A-19 | No file quota | **PASS** | `RLIMIT_FSIZE`; 64 MB write → `EFBIG` |
| A-20 | Detector evades ~9/12 | **PASS (by inversion)** | detection is no longer the boundary; evasion grants nothing |
| A-21 | No password policy | **NOT VERIFIED** | unchanged |
| A-22 | No ledger reconciliation | **NOT VERIFIED** | unchanged |
| A-23 | No LSM | **PASS** | Landlock ABI 2 write-confinement |
| A-25 | Fingerprint omits autonomy | **NOT VERIFIED** | unchanged |
| A-26 | No MFA recovery | **NOT VERIFIED** | unchanged |
| A-27 | No token rotation | **NOT VERIFIED** | unchanged |
| A-28 | No connector revocation | **NOT VERIFIED** | unchanged |
| A-29 | Multi-process SQLite untested | **NOT VERIFIED** | single-process assumption documented |
| A-30 | ~45 s sandbox latency | **NOT VERIFIED** | latency not re-measured; containment costs startup |

### Low

A-24 (negative autonomy) — **NOT VERIFIED**, unchanged.

---

## 5. Release criteria assessment

| # | Criterion | Verdict |
|---|---|---|
| 1 | Secure isolation on the actual target runtime | **PASS** here; **NOT VERIFIED** for a different host without Landlock ≥ 2 + user namespaces |
| 2 | Per-task and aggregate resource controls | **PASS** per-task; aggregate is per-worker (`NOT VERIFIED` for multi-worker) |
| 3 | Complete workload termination | **PASS** (0 orphans, verified) |
| 4 | Zero cross-tenant memory access | **PASS** |
| 5 | Effective trust-boundary enforcement | **PASS** |
| 6 | SSRF protection across redirects/DNS | **PASS** at the application layer; no egress proxy (**NOT VERIFIED**) |
| 7 | Fail-closed DB recovery | **PASS** (classification/refusal); backup/restore drills **NOT VERIFIED** |
| 8 | MFA replay protection | **PASS** |
| 9 | Mutation-tested controls | **PASS** (13/13) |
| 10 | Clean-environment reproducibility | **NOT VERIFIED** — needs a fresh host + `pip install -e .` + full suite |

**Decision: production NO-GO maintained.** All P0 findings that gate untrusted execution, tenant isolation, authorization, SSRF and database recovery are remediated and mutation-tested, but criteria 1, 2, 6, 7 and 10 carry `NOT VERIFIED` components requiring independent review on the target runtime.
