# RELEASE MANIFEST — SKYLA PRIME v0.2.2 (PRIME QUALIFICATION)

**Release type:** evidence programme. No new AI capabilities, no UI expansion.
**Date:** 2026-11-22
**Branch:** `arena/2a497c0e-skyla-prime`
**Base:** `cb4cfce` (`main`)
**Release commits:** `872647b` (M2/M3/M4) · `381795e` (M5) · `0356454` (cgroup wiring
+ M6) · `278eb73` (M8 docs) · `3ab461d` (fail-closed cgroups, B-08) · `f669668`
(reproduction corrections)
**Decision:** **NO-GO for production. GO for a dedicated staging environment, with
the conditions in §6.**

> Three of the ten release-gate items cannot be satisfied in this environment and are
> recorded as **NOT VERIFIED**, not as passes: second-host isolation, live connector
> behaviour, and independent external review. A fourth (egress) fails as a perimeter.
> Two High findings (B-01 egress perimeter, B-02 cross-worker scheduler lease) remain
> open. No finding was downgraded to reach this verdict.
>
> Two High defects were found **during** documentation and fixed before this
> manifest was written: **B-08** (the cgroup governor failed open — limits were
> written without checking, and the API was told enforcement was enabled) and a
> **reproduction-script error** that would have reported a false PASS on the
> idempotency gate. Both are recorded with the regression test that now catches
> them. The release is stronger for having found them, and the fact that both were
> invisible to the existing green suite is itself the finding.

---

## 1. What is in this release

### Code (24 files, 4 818 insertions / 20 deletions since `41614fc`)

| Area | Files | What changed |
|---|---|---|
| OS resource governance (M2) | `skyla/execution/cgroups.py` (new, 492) · `scripts/cgroup_bootstrap.sh` · `scripts/skyla-run.sh` · `providers.py` · `workload.py` | cgroup v2 per-job and aggregate limits; kernel—not application—enforcement; workload self-placement; `cgroup.kill` termination |
| Network egress (M3) | `skyla/egress.py` (new, 414) | default-deny forward proxy; allowlist before DNS; dial the vetted IP; JSONL audit |
| DB backup (M4) | `skyla/backup.py` (new, 329) | SQLite online backup, verification, atomic publication, guarded restore |
| Multi-worker (M5) | `skyla/db.py` · `skyla/api/app.py` | atomic `ledger_begin`, `in_flight`/`duplicate`/`conflict` semantics, `ledger_reap_stale`, `is not None` replay checks |
| Connector tests (M6) | `tests/security/test_connector_reliability.py` | 16 tests asserting mock/live separation and provider-error propagation |
| **Fail-closed cgroups (B-08)** | `skyla/execution/cgroups.py` · `tests/security/test_cgroup_failclosed.py` (new, 15) | every limit write is checked; a failed limit refuses the workload instead of running it unbounded. Found by review, not by the suite — `test_cgroups.py` skips without privileges, so the fail-open path was never exercised |
| Backup test hardening | `tests/security/test_backup.py` | 16 tests; naive-copy and torn-pair defects reproduced deterministically, plus a mutation-verified WAL-only case |

### Qualification documents (8, as specified)

| # | Document | Verdict |
|---|---|---|
| 1 | `SECOND_HOST_VALIDATION.md` | **NOT VERIFIED** |
| 2 | `CGROUPS_VALIDATION.md` | **PASS** (with §7 limits) |
| 3 | `EGRESS_PROXY_ASSESSMENT.md` | **PASS** for the proxy; **FAIL** for perimeter enforcement (B-01) |
| 4 | `WAL_BACKUP_RECOVERY_REPORT.md` | **PASS** for backup/restore; **NOT VERIFIED** for scheduled operation |
| 5 | `MULTI_WORKER_CAPACITY_REPORT.md` | **PASS** idempotency; **FAIL** auto worker recovery; **NOT VERIFIED** scheduler lease |
| 6 | `CONNECTOR_RELIABILITY_REPORT.md` | **PASS** mock/live separation; **NOT VERIFIED** live providers |
| 7 | `INDEPENDENT_REVIEW_PACKAGE.md` | package complete; **review not performed** |
| 8 | `RELEASE_MANIFEST_v0.2.2.md` | this file |

## 2. Evidence base

| Type | Count | Where |
|---|---|---|
| Automated tests, full suite | **322 passed, 18 skipped, 0 failed** (340 collected, 41 s) | `pytest tests/ -q -rs` |
| Security test suite | 239 | `tests/security/` |
| Live process/API deployments | 6 | 4-worker uvicorn, cgroup subtree, egress proxy, backup drill, connector stubs, mutation harness |
| Independent probes (outside the suite) | ~25 | `/tmp/hostprobe.sh`, `/tmp/e2e_cgroup.py`, `/tmp/pidcheck.py`, `/tmp/mwprobe.py`, `/tmp/mwbench.py`, `/tmp/mwrecover2.py`, `/tmp/egress_probe.py`, `/tmp/thr.py` |
| Kernel-counter measurements (not app-reported) | 12 | `memory.peak`, `memory.events`, `pids.peak`, `cpu.stat`, `cgroup.procs`, procfs caps/seccomp |

The 18 skips are **all** `test_cgroups.py`, and all skip for one reason: the test
process runs in `/user`, outside the delegated subtree `/sys/fs/cgroup/skyla`. They
were run to completion (18/18 pass) inside the delegated subtree — see
`CGROUPS_VALIDATION.md`. A skip reported as a pass would be exactly the failure mode
this programme exists to prevent.

That skip also hid a defect, which is why `tests/security/test_cgroup_failclosed.py`
exists as a **separate, non-skipping** module: it needs no kernel privileges, and it
caught a governor that returned a job object while every limit write had failed
(§4, finding B-08).

## 3. Release gate — final state

| # | Criterion | Verdict | Evidence |
|---|---|---|---|
| 1 | Host isolation independently verified | **NOT VERIFIED** | no second host obtainable; `SECOND_HOST_VALIDATION.md` |
| 2 | Per-job + aggregate resource protection demonstrated | **PASS** | OOM `rc=-9` @128 MB, `pids.max` bounded, CPU throttled, 4th job refused; `CGROUPS_VALIDATION.md` |
| 3 | Process-tree cleanup reliable | **PASS** | `cgroup.kill` + pid namespace; 0 survivors after timeout, incl. double-forked grandchild |
| 4 | Egress demonstrably controlled | **PASS** (proxy) / **FAIL** (perimeter, B-01) | pypi 200 via 48.9 MB tunnel; denied hosts refused before DNS; metadata blocked — but no host firewall exists, so the control is a chokepoint, not a perimeter |
| 5 | Cross-user boundaries intact | **PASS** | 7/7 API attacks refused; record intact (v0.3.0 parity) |
| 6 | DB integrity + backup restoration proven | **PASS** | `counts_match=True`, `critical_ok=True`, `schema_version=6`, `integrity_check ok`; **A-14 CLOSED** |
| 7 | Multi-worker idempotency proven | **PASS** | 16 concurrent / 1 key → executed=1, replayed=15, 0×409; survives restart |
| 8 | Live connectors verified in authorised accounts | **NOT VERIFIED** | no credentials; no authorised test account |
| 9 | Critical/High findings closed | **FAIL** | 0 Critical; **B-01, B-02 High open**; A-13/A-17/A-21/A-22 Medium open |
| 10 | Independent external review completed | **NOT VERIFIED** | `INDEPENDENT_REVIEW_PACKAGE.md` has an empty sign-off block |

**Gate result: 5 PASS, 2 FAIL, 3 NOT VERIFIED.** Production requires all ten; the
release is therefore **NO-GO for production**. (Gate 4 passes as a proxy but fails
as a perimeter, and is counted once on the failing side — counting the favourable
reading of a split verdict is how a gate list becomes a marketing document.)

## 4. Findings ledger

### Closed in v0.2.2

| ID | Was | Now | How |
|---|---|---|---|
| **A-14** | naive WAL copy loses all committed rows | **CLOSED** | SQLite online backup + verification + atomic publish; defect reproduced first as a regression test |
| **A-29** | multi-process SQLite untested | **CLOSED** | 4-worker uvicorn on one WAL database; 47 req/s, `integrity_check ok` |
| v0.3.0 cgroup gap | limits application-only | **CLOSED** | kernel enforcement wired into `NamespaceProvider.run()`; measured peaks |
| **B-08** | cgroup governor failed **open**: `create_job()` / `ensure_aggregate()` ignored the result of every limit write, so a job whose `memory.max`, `pids.max`, `cpu.max` were absent was returned and reported to the API as `cgroup.enabled = true` | **CLOSED** | every write checked; a failed limit removes the cgroup and raises `CgroupUnavailable`; regression test `test_cgroup_failclosed.py` fails 13/15 on the old code |

### Open — High

| ID | Finding | Impact |
|---|---|---|
| **B-01** | No host firewall; a process that ignores `HTTPS_PROXY` is not stopped | egress policy is a chokepoint, not a perimeter |
| **B-02** | No cross-worker scheduler lease; multi-worker task execution may duplicate | duplicate external action possible at the *task* level (connector level is protected) |
| A-13 | `tasks:read` principal can mint a 30-day API token | privilege escalation |
| A-17 | Interrupted tasks are not resumable, yet status implies they are | correctness / trust |
| A-21 | No password policy | weak credentials accepted |
| A-22 | No ledger reconciliation; `unknown` is terminal | stuck external actions require manual repair |

### Open — Low / Medium (carried)

A-24 (negative autonomy levels), A-25 (fingerprint omits `autonomy_level`/`title`),
A-26 (no MFA recovery codes), A-27 (no token rotation), A-28 (no connector
credential revocation), A-30 (sandbox latency), B-03 (aggregate admission is
`workers × max`), B-04 (throttle state per worker), B-05 (SIGKILLed worker not
respawned), B-06 (API-side fetcher keeps a DNS-rebinding window), B-07 (no scheduled
backup, no off-site copy).

**Nothing was downgraded.** A-22 in particular remains `MEDIUM`, not "mitigated",
because a replayed-`unknown` action can still become a duplicate external write.

## 5. What the release does prove

1. A workload cannot exceed its memory, pid or CPU budget — enforced by the kernel,
   verified from kernel counters, and the API server survives beside it.
2. A workload's process tree dies at timeout, including double-forked grandchildren,
   because `cgroup.kill` is used rather than a pid walk.
3. Egress *passed to the proxy* to a non-allowlisted destination is refused **before**
   a socket is opened, and the connection is made to a vetted IP rather than a
   re-resolved name. (This does not prove that all egress passes the proxy — see B-01.)
4. A backup taken during concurrent writes is consistent, checksummed, and restores
   to a database the application will accept — and the original is never touched.
5. Two workers cannot independently execute the same external action; this holds
   across a full worker-pool restart.
6. A mock connector cannot present its result as a real external action.

## 6. Conditions for staging

Staging is authorised **on this host only**, with:

1. Service started via `scripts/skyla-run.sh` (inside `/sys/fs/cgroup/skyla/service`)
   — otherwise every cgroup control silently reports `enabled: false`.
2. `SKYLA_ALLOW_UNSAFE_EXECUTION` unset.
3. All egress routed through the proxy; direct egress blocked at the edge if the
   staging network can do so (B-01).
4. A single scheduler process; do not run the task scheduler in more than one worker
   until B-02 is closed.
5. Live connectors remain **disabled**; no `GOOGLE_*` / `TELEGRAM_*` credentials.
6. Backups scheduled externally and copied off-box (B-07).
7. A named reviewer works through `INDEPENDENT_REVIEW_PACKAGE.md` before any
   production discussion.

## 7. Not verified in this release — do not read these as passes

* Second-host portability, any kernel other than 6.1.158+, any other LSM stack.
* Live Gmail/Calendar/Telegram authentication, token renewal, revocation, scopes,
  provider-confirmed state.
* Host-level network isolation; a real firewall.
* Multi-worker task scheduling; worker counts above 4.
* Scheduled/off-site backup, restore of a production-sized database.
* Anything under sustained load beyond ~47 req/s.
* Any claim about untrusted code from an unauthenticated or lower-privilege principal
  on a shared host — the containment was measured, not stress-tested to destruction.

## 8. Repository state

- Branch `arena/2a497c0e-skyla-prime`; **no force-push, no history rewrite**.
- Frozen v0.2.1 audit documents **byte-identical** to `9f4db1f`
  (`PRIME_ASSURANCE_REPORT.md`, `THREAT_MODEL.md`,
  `SANDBOX_SECURITY_ASSESSMENT.md`, `AUTHENTICATION_REVIEW.md`,
  `EXTERNAL_ACTION_INTEGRITY.md`, `DATABASE_RECOVERY_REPORT.md`,
  `STAGING_ACCEPTANCE_REPORT.md`, `RELEASE_MANIFEST_v0.2.1.md`).
- No real external communication was sent; no account was modified; no credential
  was created, requested, or stored.
- All destructive tests used disposable databases under `/tmp`; the working database
  at `data/skyla.db` was never the target of a destructive probe.
- No fork storm was left running; the largest was bounded by `pids.max` and reaped.

## 9. Reproduction

```bash
pip install -e ".[dev]"
python -m pytest tests/ -q -rs              # 322 passed, 18 skipped

sudo scripts/cgroup_bootstrap.sh            # one-time delegation
sudo scripts/skyla-run.sh --workers 4       # service inside the delegated subtree
python -m pytest tests/security/test_cgroups.py -q   # 18 passed (no skips)
```

## 10. Decision

**Production: NO-GO.** Gate items 1, 8 and 10 are unsatisfiable in this environment;
item 9 fails because B-01 and B-02 are open High findings.

**Dedicated staging: GO**, under the seven conditions in §6. The controls that *were*
measured are real: kernel-enforced resource limits, process-tree termination, a
default-deny egress chokepoint, verified restorable backups, and global idempotency
across workers. That is a materially stronger position than v0.2.1, where 8 High
findings were open and none of these controls existed.

It is not a production position. Two High findings are open, three gates are
unproven, and no independent reviewer has looked at any of it.
