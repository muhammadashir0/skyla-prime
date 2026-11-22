# MULTI-WORKER CAPACITY REPORT — v0.2.2 PRIME QUALIFICATION

**Mission 5.** Real concurrent deployment: shared ledger, global idempotency,
duplicate prevention, database locking, worker recovery, throughput and
resource consumption.

## Verdict

> **PASS** for global idempotency — two workers cannot independently execute the
> same external action, measured on 4 real uvicorn worker processes.
> **FAIL** for automatic worker recovery: an externally `SIGKILL`ed worker is not
> respawned by the uvicorn master; capacity returns only on `SIGHUP` or a
> process-manager restart. SIGHUP recovery itself is **PASS**.

---

## 1. Tested hardware and configuration

| Item | Value |
|---|---|
| Host | `e2b.local`, Debian 12, kernel 6.1.158+ |
| CPU / RAM | 2 vCPU / 3939 MB |
| Server | `uvicorn 0.54.0`, `--workers 4` (spawn), one shared SQLite file |
| Journal mode | `WAL` (asserted; rollback journal would serialise all readers) |
| Load driver | httpx, thread pool 8–16, all requests concurrent |
| Database | `/tmp/mw/app.db`, disposable |

## 2. The defect that made this mission necessary

v0.2.0/v0.3.0 `ledger_begin()` was **check-then-insert**:

```python
existing = query("SELECT ... WHERE idempotency_key=?")   # both workers read "none"
if existing: ...
insert(...)                                              # both insert
```

Six concurrent processes on one key produced:

```
worker 0: new
worker 1: IntegrityError   <- uncaught, becomes HTTP 500
worker 2: IntegrityError
worker 3: IntegrityError
worker 4: IntegrityError
worker 5: IntegrityError
```

Uniqueness survived only because of the `UNIQUE` constraint. The *semantics* were
wrong: a 500 tells a client "retry", and the retry re-enters the action path. On a
connector that is a duplicate external write.

A second, more serious variant was found in `_ledger_guard()`: it returned `None`
for a fresh claim and call sites used `if replay:`. A duplicate whose recorded
provider response was an empty body would replay `{}` → falsy → **the action would
execute a second time**, with a ledger row saying it did not.

## 3. The fix

Ownership is decided by a single atomic `INSERT`; SQLite serialises writers, so
exactly one succeeds. Every other caller learns why it lost:

| Status | Meaning | HTTP |
|---|---|---|
| `new` | this caller owns the action | proceed |
| `in_flight` | another worker holds an uncompleted claim | **409** + `Retry-After` |
| `duplicate` | completed earlier; replay the recorded provider response | 200, body marked `duplicate: true` |
| `conflict` | same key, different payload | 409 |

Plus `if replay is not None:` at all three connector call sites (was `if replay:`),
so an empty replay body cannot fall through.

`ledger_reap_stale()` recovers claims abandoned by a crashed worker: a `pending` row
younger than the threshold blocks the key; older ones move to `unknown` and are
audited, so a dead worker cannot poison an idempotency key permanently.

## 4. Results on the live 4-worker deployment

### Global idempotency

```
16 simultaneous identical requests (one idempotency key), 4 workers
  HTTP 200: 16
  executed (not duplicate): 1
  replayed (duplicate)    : 15
  in-flight (409)         : 0
  ledger rows for the key : 1   state=completed
  duplicate keys in DB    : 0
```

After a `SIGHUP` restart (**new** worker processes, same database), the same probe:

```
executed: 1   replayed: 11   errors: []
```

So idempotency is **global**, not process-local: a worker that never saw the
original request still refuses to repeat the action.

### Throughput and latency

| Operation | Rate | Latency |
|---|---|---|
| Connector action (distinct keys) | **47 req/s** | p50 308 ms, p95 520 ms, max 616 ms |
| Task creation (heavier write path) | **34 tasks/s** | — |
| Ledger claim+complete (in-process) | **712 ops/s** | — |

24 tasks and 120 connector actions completed with **zero** non-200 responses and
`PRAGMA integrity_check: ok` on the resulting database (343 ledger rows).

### Worker failure

```
4 workers + master, SIGKILL one worker mid-load
  requests during the kill window : 60/60 succeeded (200)
  throughput with 3 workers       : 48 req/s  (vs 47 with 4)
  workers after 3 s               : 4 (was 5 incl. master) -> NOT respawned
  SIGHUP restart                  : all 4 workers respawned, health 200
```

**Finding (documented, not fixed):** uvicorn's `Multiprocess` supervisor treats a
child that dies unexpectedly as a shutdown signal (`remove_dying_workers()`), so an
external `SIGKILL` permanently reduces capacity until a restart signal is sent. This
is a property of the chosen runner, not of SKYLA's logic — in-flight requests were
unaffected because the socket was shared and the remaining workers served them.

## 5. Known limits

* **Concurrency admission is per worker.** `CapacityGovernor`'s
  `max_concurrent_jobs` is an in-process counter, so the effective global execution
  cap is `workers × max`. The kernel aggregate cgroup still enforces the memory
  ceiling, but the *number* of admitted jobs is not globally capped.
  **Multi-worker aggregate admission: NOT VERIFIED.**
* **SQLite is the shared state store.** WAL gives concurrent readers and a single
  writer; under high write concurrency writers queue. This is adequate at 47 req/s
  on this hardware and was not tested beyond it.
* **Auth throttling is per process.** `LoginThrottle` state is in-process, so with
  N workers the effective lockout threshold is `N × max_per_account`. **NOT
  VERIFIED** as a global limit; a shared store is required.
* **No distributed execution leases.** Tasks are claimed by a single scheduler loop
  in the deploying process; there is no cross-worker lease table. With multiple
  workers each running its own scheduler, task execution could duplicate.
  **NOT VERIFIED** — this is the most significant remaining multi-worker gap.
* **Worker counts above 4 were not tested**, nor was a failure of the database host.

## 6. Supported configuration

| Setting | Tested value | Notes |
|---|---|---|
| Worker count | 4 | 8+ untested |
| CPU | 2 vCPU | throughput is CPU-bound |
| Memory | 3.9 GB | 4 workers ≈ 57 MB RSS each at idle |
| Database | single SQLite file on local disk | WAL required |

## 7. Reproduction

```bash
# unit/process-level
python -m pytest tests/security/test_multiworker.py -q     # 9 passed

# live deployment
SKYLA_DB_PATH=/tmp/mw/app.db SKYLA_INIT_DB=1 \
  python -m uvicorn skyla.api.app:app --port 8031 --workers 4
```

## 8. Residual risk

| Risk | Severity | Note |
|---|---|---|
| No global scheduler lease | High | multi-worker task execution may duplicate |
| External SIGKILL not recovered | Medium | use a real process manager (systemd `Restart=always`) |
| Per-worker throttle/capacity | Medium | N× the configured limit in practice |
| SQLite write contention | Medium | single-writer; measured only to 47 req/s |
