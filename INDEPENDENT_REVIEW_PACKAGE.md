# INDEPENDENT REVIEW PACKAGE — SKYLA PRIME v0.2.2

**Mission 7.** Everything a second reviewer needs to inspect the controls of this
release **without trusting the implementing agent's claims**.

> **The review has not happened.** This document is the *package*, not the outcome.
> Mission 7 is complete only when a named reviewer signs a verdict against it.
> Release criterion 10 — independent external review — is **NOT VERIFIED**.

---

## 0. Ground rules for the reviewer

1. **Do not accept this package's PASS/FAIL vocabulary as evidence.** Re-derive each
   verdict. Where a claim and a test disagree, the test loses: read the source.
2. **The tests were written by the implementing agent.** They encode the same
   assumptions as the code. Every security-relevant claim below names the *source
   location* you should read instead. If a control is only proven by a test, treat
   it as unproven until you have exercised it yourself.
3. **A skip is not a pass.** `pytest -rs` prints skip reasons. `test_cgroups.py`
   skips wholesale outside a delegated cgroup subtree — that is "not verified on
   this host", not "fine".
4. **Frozen historical documents must stay byte-identical** (see §7). If they differ
   from the commit below, the review is invalid.
5. Write findings as `FAIL` with a reproduction, or `NOT VERIFIED` with the missing
   precondition. Do not write "mostly fine".

## 1. Exact artifact identification

| Item | Value |
|---|---|
| Branch | `arena/2a497c0e-skyla-prime` |
| Base | `cb4cfce` (`main`) |
| Release commits | `872647b` (M2/M3/M4), `381795e` (M5), `0356454` (cgroups + M6) |
| Prior remediation | `b29c8f5` (v0.3.0), `41614fc` (v0.3.0 docs) |
| Prior audit (frozen) | `9f4db1f` (v0.2.1, verdict FAIL) |
| Python | 3.11+, `pip install -e ".[dev]"` |
| Verify tree is unmodified | `git status --short` must show only untracked `*.md` you were given |

```bash
git log --oneline cb4cfce..HEAD          # 3 release commits + 2 prior
git diff --stat cb4cfce..HEAD            # full change surface
```

## 2. Read these sources, in this order

| # | File | Lines | Why |
|---|---|---|---|
| 1 | `skyla/execution/skyla-sup.c` | 307 | The only code that runs before untrusted code. Control order is the security property. |
| 2 | `skyla/execution/workload.py` | 336 | How the supervisor is invoked, cgroup self-placement, process-tree termination. |
| 3 | `skyla/execution/cgroups.py` | 465 | Per-job and aggregate kernel limits; failure mode when cgroups are absent. |
| 4 | `skyla/execution/providers.py` | 244 | `NamespaceProvider.run()` — the API-facing execution path. |
| 5 | `skyla/egress.py` | 414 | Egress proxy decision order (allowlist before DNS; dial the vetted IP). |
| 6 | `skyla/netguard.py` | 171 | URL-level SSRF guard used by API-side fetchers. |
| 7 | `skyla/db.py` | 513 | Schema v6, `ledger_begin` atomic claim, `ledger_reap_stale`. |
| 8 | `skyla/api/app.py` | 758 | `_ledger_guard()` around line 614; where replay/in-flight/conflict is decided. |
| 9 | `skyla/backup.py` | 329 | Online backup, verification, atomic publication, restore guards. |
| 10 | `skyla/dbguard.py` | 177 | Startup integrity gate (blocks truncated-DB re-init). |
| 11 | `skyla/auth.py`, `skyla/throttle.py`, `skyla/trust.py` | — | MFA replay, lockout, untrusted-content labelling. |

**Specific things to check by reading, not by test:**

* `skyla-sup.c`: is every control's return value checked, and does a failure `_exit(111)`
  before `execve`? Is `capset` called *after* Landlock and seccomp (order matters)?
* `workload.py`: is `cgroup.kill()` reachable when the pid-namespace teardown hangs?
  Is the `echo $$ > cgroup.procs` self-placement the *first* thing the inner shell does?
* `egress.py`: is the classification of every resolved address (`all()`, not `any()`)
  done before the dial? Does the dial use the vetted IP?
* `db.py`: is `ledger_begin` a single `INSERT` under `UNIQUE`, or still check-then-insert?
* `app.py`: are all replay checks `is not None` rather than truthiness?
* `backup.py`: does `verify()` catch `sqlite3.DatabaseError`? Can `restore()` write to
  the live DB without an explicit flag?

## 3. Runtime configuration under review

```
SKYLA_DB_PATH                 path to the SQLite file (WAL)
SKYLA_API_TOKEN               shared API token (must be non-empty in staging)
SKYLA_EXECUTION_PROVIDER      namespace | local
SKYLA_ALLOW_UNSAFE_EXECUTION  must NOT be set anywhere reachable in staging
SKYLA_CGROUP_ROOT             /sys/fs/cgroup/skyla
SKYLA_AGG_MEMORY_MB           aggregate memory ceiling
SKYLA_AGG_PIDS                aggregate pid ceiling
SKYLA_AGG_CPU_QUOTA_US        aggregate CPU quota
SKYLA_MAX_CONCURRENT_EXECUTIONS
SKYLA_EGRESS_ENABLED / _POLICY / _PORT / _AUDIT
GOOGLE_OAUTH_* , GOOGLE_REFRESH_TOKEN , TELEGRAM_BOT_TOKEN   (must be UNSET)
```

Required deployment shape: **start the service inside the delegated subtree**
(`scripts/skyla-run.sh`), otherwise every cgroup control silently reports
`enabled: false`. Verify with `cat /proc/<pid>/cgroup`.

## 4. Reproduce the suite

```bash
pip install -e ".[dev]"
python -m pytest tests/ -q -rs           # expect 304 passed, 16 skipped
```

Per-area counts (security-relevant):

| Area | File | Tests |
|---|---|---|
| Host containment (caps/seccomp/Landlock/rlimits) | `tests/security/test_host_containment.py` | 20 |
| Egress proxy | `tests/security/test_egress.py` | 22 (2 hit the live network; skip if blocked) |
| Database integrity | `tests/security/test_db_integrity.py` | 17 |
| cgroups | `tests/security/test_cgroups.py` | 16 (all skip outside the delegated subtree) |
| Backup/restore | `tests/security/test_backup.py` | 13 |
| Connector mock/live separation | `tests/security/test_connector_reliability.py` | 16 |
| MFA / throttling | `tests/security/test_auth_mfa.py` | 12 |
| SSRF | `tests/security/test_ssrf.py` | 45 |
| Memory tenant isolation | `tests/security/test_memory_tenant.py` | 11 |
| Trust boundary | `tests/security/test_trust_boundary.py` | 25 |
| Multi-worker idempotency | `tests/security/test_multiworker.py` | 9 |
| Mutation harness | `tests/security/test_mutation_harness.py` | 13 |

Security suite total 219, unit suite 101, **320 collected** (304 run + 16 skipped).

## 5. Adversarial cases the implementer did **not** cover

These are the highest-value uses of a reviewer's time. Each is a plausible bypass
that no existing test asserts against:

1. **Capability regain via file capabilities.** `CapBnd=0` is verified, but nothing
   tests a binary on the rootfs carrying `security.capability` xattrs. Confirm the
   rootfs cannot contain one (it is copied per run — check the copy source).
2. **Landlock scope.** The ruleset confines writes. Is *read* confinement configured,
   or can the workload read `/etc/passwd` inside the chroot? Check what the minimal
   rootfs actually contains.
3. **Seccomp allowlist breadth.** Enumerate the allowed syscalls. Does it permit
   `socketpair`, `io_uring_setup`, `open_by_handle_at`, `userfaultfd`, `process_vm_readv`?
   A single omission re-opens A-09.
4. **Egress via raw sockets.** The proxy is a policy boundary. If a workload can call
   `socket()`, the proxy is bypassed. Confirm seccomp denies network syscalls *and*
   that the net namespace has no interfaces.
5. **DNS rebinding through the proxy's own resolver.** The proxy dials the vetted IP
   (verified). Does it also send the original `Host` header? A vetted IP with the
   original Host is correct; a vetted IP with a *resolved* Host would be a bug.
6. **Aggregate cgroup escape.** Create jobs until the aggregate is full, then check
   whether a *directly created* process under `/skyla/service` escapes the aggregate
   accounting. Only the provider path is wired in.
7. **Ledger key collision across tenants.** Send the same idempotency key as two
   different users. Does the second get a replay of the first user's provider
   response? Check whether the key is scoped by owner in the `UNIQUE` index.
8. **`unknown` ledger states.** Kill a worker mid-action; the row stays `pending`
   until reaped as `unknown`. Is `unknown` ever re-executed? A re-execution is a
   duplicate external write (this is A-22, still open).
9. **Restore of a backup taken during a schema migration.** Migrate v5→v6 while a
   backup runs; restore and open. Migration compatibility was tested but not
   concurrently with backup.
10. **Throttle evasion by worker rotation.** `LoginThrottle` is per process; with 4
    workers the lockout is `4 × N`. Confirm and record as a finding.
11. **`SKYLA_AGG_*` unset.** What happens when the aggregate limits are not
    configured? Fail closed or unlimited? Read the code path.

## 6. Live probes to run (not unit tests)

```bash
# 1. cgroups actually applied to a real workload
SKYLA_CGROUP_ROOT=/sys/fs/cgroup/skyla python /tmp/e2e_cgroup.py   # pids_peak, memory_peak_mb

# 2. egress: allowlisted host works, denied host is refused before TCP
cat > /tmp/run_egress.py <<'EOF'
from skyla.egress import POLICIES, EgressProxy
p = EgressProxy(host="127.0.0.1", port=8118, policy=POLICIES["research"]).start()
print("proxy on", p.url, flush=True)
import time; time.sleep(600)
EOF
python /tmp/run_egress.py &
curl -x http://127.0.0.1:8118 https://pypi.org/simple/ -o /dev/null -w '%{http_code}\n'   # 200
curl -x http://127.0.0.1:8118 https://github.com/   -o /dev/null -w '%{http_code}\n'      # 403

# 3. multi-worker duplicate prevention
SKYLA_DB_PATH=/tmp/mw/app.db SKYLA_INIT_DB=1 \
  python -m uvicorn skyla.api.app:app --port 8031 --workers 4
# then 16 concurrent identical requests -> 1 executed, 15 replayed, 0 errors

# 4. backup during writes, then restore to a new path and compare counts
python -m pytest tests/security/test_backup.py -q

# 5. worker kill behaviour (expect: NOT respawned without SIGHUP)
kill -9 <worker-pid>; curl -s localhost:8031/health
```

## 7. Frozen files — must be byte-identical to `9f4db1f`

```
PRIME_ASSURANCE_REPORT.md      THREAT_MODEL.md
SANDBOX_SECURITY_ASSESSMENT.md AUTHENTICATION_REVIEW.md
EXTERNAL_ACTION_INTEGRITY.md   DATABASE_RECOVERY_REPORT.md
STAGING_ACCEPTANCE_REPORT.md   RELEASE_MANIFEST_v0.2.1.md
```

```bash
git diff 9f4db1f -- PRIME_ASSURANCE_REPORT.md THREAT_MODEL.md ...   # must be empty
```

These record a **FAIL**. They are not historical curiosities: they are the baseline
the reviewer measures the remediation against. Editing them would erase the record of
what was actually broken.

## 8. Finding ledger the reviewer must close out

Still open from v0.2.1, with this release's status:

| ID | Sev | Status in v0.2.2 |
|---|---|---|
| A-14 | Medium | **CLOSED** — online backup, verified restore (§`WAL_BACKUP_RECOVERY_REPORT.md`) |
| A-29 | Low | **CLOSED** — 4-worker SQLite deployment proven (§`MULTI_WORKER_CAPACITY_REPORT.md`) |
| A-13 | Medium | OPEN — `tasks:read` can still mint 30-day tokens |
| A-17 | Medium | OPEN — interrupted tasks are not resumable |
| A-21 | Medium | OPEN — no password policy |
| A-22 | Medium | OPEN — no ledger reconciliation; `unknown` is terminal |
| A-24 | Low | OPEN — negative autonomy levels accepted |
| A-25 | Low | OPEN — ledger fingerprint omits `autonomy_level`/`title` |
| A-26 | Low | OPEN — no MFA recovery codes |
| A-27 | Low | OPEN — no token rotation |
| A-28 | Low | OPEN — no connector credential revocation |
| A-30 | Low | OPEN — sandbox latency |

Plus newly identified in this release (not in the v0.2.1 numbering):

| ID | Sev | Finding | Where |
|---|---|---|---|
| B-01 | High | No host firewall; egress bypasses the proxy | `EGRESS_PROXY_ASSESSMENT.md` §6 |
| B-02 | High | No cross-worker scheduler lease — task execution may duplicate | `MULTI_WORKER_CAPACITY_REPORT.md` §5 |
| B-03 | Medium | Aggregate admission is per worker (`workers × max`) | same §5 |
| B-04 | Medium | Approval gates throttle state per worker | same §5 |
| B-05 | Medium | External `SIGKILL` of a worker is not recovered | same §4 |
| B-06 | Medium | API-side fetchers keep a DNS-rebinding window | `EGRESS_PROXY_ASSESSMENT.md` §6 |
| B-07 | Medium | No scheduled backup; no off-site copy | `WAL_BACKUP_RECOVERY_REPORT.md` §5 |

## 9. Questions the reviewer must answer

1. Does any untrusted code path execute **before** `capset`/seccomp/Landlock in
   `skyla-sup.c`?
2. Can a workload allocate memory, CPU or pids **without** a cgroup? (i.e. is there a
   provider or code path that skips `CgroupGovernor`?)
3. Is the *aggregate* limit enforced by the kernel, or only by the in-process governor?
4. Can any code path reach an internal address, or a non-allowlisted host, without
   passing `egress`/`netguard`?
5. Is global idempotency atomic at the storage layer, or does it rely on a Python lock?
6. Does a mock connector return a status that a caller could plausibly treat as a
   real external action?
7. Can the original database be modified or deleted by any backup/restore path
   without an explicit flag?
8. **Are the five release-gate items below genuinely satisfiable, or unsatisfiable
   in this environment?**

## 10. Release gate — reviewer-verifiable state

| # | Gate | Status | Evidence |
|---|---|---|---|
| 1 | Host isolation independently verified | **NOT VERIFIED** | single host only — `SECOND_HOST_VALIDATION.md` |
| 2 | Per-job + aggregate resource protection | **PASS** | `CGROUPS_VALIDATION.md` |
| 3 | Process-tree cleanup reliable | **PASS** | `CGROUPS_VALIDATION.md` §5 (cgroup.kill + pid namespace) |
| 4 | Egress demonstrably controlled | **PARTIAL** | `EGRESS_PROXY_ASSESSMENT.md` — proxy yes, perimeter no (B-01) |
| 5 | Cross-user boundaries intact | **PASS** | v0.3.0 A-05 parity suite |
| 6 | DB integrity + backup restoration | **PASS** | `WAL_BACKUP_RECOVERY_REPORT.md` |
| 7 | Multi-worker idempotency proven | **PASS** | `MULTI_WORKER_CAPACITY_REPORT.md` (lease gap B-02 separately open) |
| 8 | Live connectors verified | **NOT VERIFIED** | no authorised accounts — `CONNECTOR_RELIABILITY_REPORT.md` |
| 9 | Critical/High findings closed | **FAIL** | B-01, B-02 High; A-13/A-17/A-21/A-22 Medium |
| 10 | Independent external review completed | **NOT VERIFIED** | this package has no signer |

## 11. What the reviewer should produce

A signed document containing, per gate item: verdict, the command run, the observed
output, and either a reproduction or the missing precondition. Plus, for each of
`B-01`…`B-07` and every open A-item: agree, downgrade-with-argument, or reject. Any
Downgrade must be argued on the basis of demonstrated control, not convenience.

Then, separately and before production: an **external penetration test** against a
staging deployment with real credentials for throwaway accounts.

## 12. Sign-off block (empty — do not pre-fill)

```
Reviewer name      : ______________________
Organisation       : ______________________
Date               : ______________________
Commit reviewed    : ______________________  (must be 0356454 or a later descendant)
Host / kernel      : ______________________
Gate 1  : ____   Gate 2  : ____   Gate 3  : ____   Gate 4  : ____   Gate 5  : ____
Gate 6  : ____   Gate 7  : ____   Gate 8  : ____   Gate 9  : ____   Gate 10 : ____
Findings opened    : ______________________
Overall verdict    : PRODUCTION / STAGING ONLY / REJECT
Signature          : ______________________
```
