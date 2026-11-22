# B-02 Remediation Report

**Finding:** B-02 — no cross-process execution lease; identical tasks execute more than once (High)
**Status:** **CLOSED** — fixed, regression-tested, mutation-verified
**Commit:** `b4ba0a8`
**Date:** 2026-11-22 · host `e2b.local`

---

## 1. The finding, as written

From `MULTI_WORKER_CAPACITY_REPORT.md` §5 (v0.2.2, frozen and unaltered):

> **No distributed execution leases.** … **NOT VERIFIED** — this is the most significant remaining multi-worker gap.

The v0.2.2 report described a *gap in capacity planning*. The identifier alone would not have told anyone that the consequence is **silent duplicate execution**, so the finding was reproduced first.

## 2. Reproduction

A reproducer (`/tmp/b02work/repro.py`) starts N processes that each call `Orchestrator.run_task(tid)` for the **same** task id against one SQLite database, then counts `task_steps` rows. A correctly serialised task produces exactly **2** rows (the task's two steps).

**On unfixed code** (`4df7abc`):

| processes | step rows produced | expected | processes exiting 0 |
|---|---|---|---|
| 2 | **4** | 2 | 2 / 2 |
| 3 | **6** | 2 | 3 / 3 |
| 4 | **8** | 2 | 4 / 4 |

Every process reported success. No error, no warning, no audit record — the task simply ran two, three, four times. This is worse than a crash: the duplicate side effects are indistinguishable from legitimate work.

**Root cause — check-then-act in `Orchestrator.run_task`:**

```python
if status in ("completed", "failed"):   # CHECK
    return
update_task(task_id, status="planning")  # ACT
```

Two processes can both pass the check before either performs the act. The window is per-request on the API path, because `app.py:347` does `asyncio.create_task(orchestrator.run_task_async(tid))` for every accepted request — so concurrent POSTs to the same task are the normal trigger, not an unusual race.

## 3. Affected paths

| Path | Effect |
|---|---|
| `POST /api/tasks` → `asyncio.create_task(...)` (`app.py:347`) | one execution attempt per request, unbounded |
| `Orchestrator.run_task` | the check-then-act window |
| `skyla/db.py` `update_task` | no conditional update, so the write cannot arbitrate |
| every tool with an external side effect (connectors, messages, writes) | **duplicated** |

Adjacent surfaces checked: the worker-recovery path (M5, `381795e`) and the global idempotency ledger. The ledger de-duplicates **identical request payloads**; it does not stop two workers from picking up the same queued task. Different mechanism, different gap — B-02 was not covered by it.

## 4. Two rejected fixes

Recorded because both looked correct and both failed under the reproducer. A finding is not closed because the first patch makes the symptom quieter.

**v1 — lease row + `DELETE` on release.** Claim by inserting into `task_leases`; release by deleting the row. Rejected: when the holder finishes and deletes its lease, the task returns to a claimable state and a later worker runs it again. Sequentially duplicated.

**v2 — compare-and-set accepting `('queued','planning')`.** Rejected: a worker whose status is already `planning` can re-enter. Measured **2 duplicates out of 8 runs at n=4**. The window moved, it did not close.

**The rule that emerged: only `status = 'queued'` may ever be claimable.** Any state a running task can be in must be outside the claimable set, or re-entry is a matter of timing.

## 5. The fix (`b4ba0a8`)

The gate is a single conditional UPDATE, so the database — not application logic — arbitrates:

```sql
UPDATE tasks SET status = 'executing' WHERE id = ? AND status = 'queued'
```

- **Rows affected = 1** → this process owns the execution. Verdict `acquired`.
- **Rows affected = 0** → someone else owns it. Verdict `held`, and the caller returns without side effects.
- `task_leases` holds `(task_id, owner, pid, host, acquired_at, expires_at)` as **crash-recovery metadata only** — it is never the gate, precisely because a lease row can be deleted and recreated without serialising anything (v1's failure).
- `release_task()` clears the lease **without touching `status`**. Reopening the task is a separate, explicit decision; v1's implicit reopen is what allowed sequential duplication.
- `reap_expired_tasks()` parks a dead holder's task as **`interrupted`** and writes a `task_recovery` row. It **never auto-reruns**: re-execution after an unknown partial state is its own hazard (A-17, still open). A human or a policy decides.
- Verdicts are `acquired` / `held` / `terminal` — a caller can tell "someone else is running it" from "it is finished".

## 6. Verification

**Deterministic, 30 clean runs:**

| processes | runs | step rows per run | duplicates |
|---|---|---|---|
| 2, 3, 4, 6, 8 | 30 | **exactly 2** in every run | **0** |

**The verdict is validated by its side effect, never by the API's return value.** An earlier iteration returned `held` correctly while still executing the task — the lease API was right and the system was wrong. Counting `task_steps` rows is the only measurement that cannot be fooled.

**Live end-to-end through the API** (4 workers, port 8041): 16 concurrent identical requests → `{200: 16}`, `executed=1`, `replayed=15`, `integrity_check ok`.

## 7. Regression tests — 10, in `tests/security/test_task_lease.py` (all pass)

| Test | Asserts |
|---|---|
| `test_concurrent_claims_yield_one_execution` | N processes, exactly one `acquired` |
| `test_execution_side_effects_occur_once` | exactly 2 `task_steps` rows across processes |
| `test_an_executing_task_cannot_be_reacquired` | `executing` is not claimable |
| `test_a_completed_task_cannot_be_reacquired` | `completed` is not claimable |
| `test_a_failed_task_cannot_be_reacquired` | `failed` is not claimable |
| `test_release_does_not_reopen_a_task` | release leaves `status` intact |
| `test_lease_records_the_owner` | owner/pid/host/expiry recorded |
| `test_expired_lease_is_reaped_to_interrupted` | expiry → `interrupted`, not `queued` |
| `test_reaping_does_not_rerun_the_task` | no auto-rerun after a crash |
| `test_a_held_verdict_skips_execution` | `held` performs no work |

## 8. Mutation testing — proof the tests catch the original defect

| # | Mutation | Result | Caught? |
|---|---|---|---|
| A | restore the original `orchestrator.py` from `git show HEAD` (check-then-act) | **4 failed, 6 passed** | **yes** |
| B | `db.py` CAS accepts `status IN ('queued','planning')` | `test_an_executing_task_cannot_be_reacquired` **FAILED** | **yes** |
| C | `release_task` additionally resets `status='queued'` | `test_a_completed_task_cannot_be_reacquired` **FAILED** | **yes** |

Mutation A is the important one: it *is* the original vulnerable code, so the suite demonstrably fails on the defect it was written for. Mutations B and C pin the two specific mistakes made while developing the fix — the exact regressions a future maintainer is most likely to reintroduce.

Each mutation was reverted from a saved snapshot (`/tmp/b02_orch_fixed.py`, `/tmp/b02_db_fixed.py`) and the suite re-run to confirm `10/10` before proceeding.

## 9. Verdict

**B-02: CLOSED.**

- Reproduced before fixing: 4/6/8 step rows on unfixed code.
- Root cause identified in code, not inferred from the identifier.
- Two incorrect fixes rejected by measurement.
- Fixed with a single database-arbitrated gate.
- 30/30 clean runs; 10 regression tests.
- Three mutations caught, including the original vulnerable code.
- Full suite at the closing commit: **332 passed, 18 skipped**.

One residual, deliberately not fixed here and not hidden: **A-17** (a task `interrupted` by a crash is not automatically resumed). Auto-resume after an unknown partial state would trade a duplicate-execution bug for a duplicate-side-effect bug, so the task is parked for an explicit decision instead. That is a capacity/operability gap, not a B-02 regression.
