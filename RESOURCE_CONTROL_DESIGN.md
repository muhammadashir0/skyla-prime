# PRIME CONTAINMENT — Resource Control Design

**Scope:** the resource dimensions of Mission 1 — A-02 (no PID limit), A-03 (no aggregate memory/concurrency limit), A-04 (orphans after timeout), A-18 (no CPU quota), A-19 (no file quota).
**Status:** per-process controls **PASS**; per-cgroup aggregate controls **NOT VERIFIED**.

---

## 1. Two layers, deliberately

Resource control is split because the two layers are enforced by different mechanisms with different blast radii.

```
        request
           |
           v
  +--------------------+     aggregate: concurrency + total memory budget
  | CapacityGovernor   |     in the API process, per-process BoundedSemaphore
  | (skyla/execution/  |     -> refuses with HTTP 429 rather than queueing forever
  |  service.py)       |     -> capacity is a SEPARATE quota from the workload's own
  +--------------------+
           |
           v
  +--------------------+
  | skyla-sup          |     per-workload: rlimits + namespaces + seccomp
  | (C supervisor)     |     -> one workload cannot exceed its slice
  +--------------------+
           |
           v
      workload (untrusted)
```

The audit's A-03 was that "N sandboxes × M MB each" was unbounded: there was no ceiling on N. `RLIMIT_AS` bounds M but says nothing about N. The governor is what bounds N.

---

## 2. Per-workload limits (enforced in `skyla-sup.c`)

| Resource | Mechanism | Default | Notes |
|---|---|---|---|
| CPU time | `RLIMIT_CPU` | `SKYLA_EXEC_CPU_S` (10 s) | per-process; threads share the process rlimit |
| Address space | `RLIMIT_AS` | 256 MB, clamped by governor | a hard ceiling, not a soft one |
| Processes | `RLIMIT_NPROC` | 24 | per-uid; inside the namespace this is the workload uid |
| File size | `RLIMIT_FSIZE` | 32 MB | write beyond it fails with `EFBIG` (Errno 27) |
| Core dumps | `RLIMIT_CORE` | 0 | no dumps may be written |
| Open files | `RLIMIT_NOFILE` | 256 | fd exhaustion bounded |
| Wall clock | parent timeout | `SKYLA_EXEC_TIMEOUT_S` (15 s) | backstop when the workload sleeps instead of burning CPU |

`RLIMIT_CPU` does **not** bound a sleeping process, which is why the wall-clock timeout is a separate control and why the termination path (§4) exists.

### Why these values

`RLIMIT_AS = 256 MB` is enough for CPython plus a modest workload and far below host capacity. `RLIMIT_NPROC = 24` permits a thread pool while making a fork bomb produce `OSError` quickly (measured: the bounded 40-iteration probe stops at 10 under a limit of 12).

---

## 3. Aggregate limits (enforced in `CapacityGovernor`)

```python
SKYLA_MAX_CONCURRENT_EXECUTIONS=2   # BoundedSemaphore size
SKYLA_EXEC_MAX_MEMORY_MB=512        # hard ceiling on any single request
governor.acquire_timeout_s = 5      # saturation -> CapacityExceeded -> HTTP 429
```

Properties that matter and are tested:

1. **Bounded, not queued.** A saturated deployment answers `429` with `Retry-After` instead of accumulating requests until the host exhausts memory. Backpressure is explicit.
2. **Fails closed.** The context manager releases in `finally`, so a raising workload cannot leak a permit.
3. **Clamped, not rejected.** A request asking for more than the ceiling is clamped and the effective value is returned in the response, so the caller sees what it actually got.
4. **Observable.** `governor.stats()` is included in every execution response.

The governor is a process-local primitive. Its limit is therefore *per API worker*, and the effective global ceiling is `workers × SKYLA_MAX_CONCURRENT_EXECUTIONS`. This must be sized by the operator; it is **NOT VERIFIED** for multi-worker deployments and is called out in `PRIME_CONTAINMENT_ACCEPTANCE_REPORT.md`.

---

## 4. Complete workload termination (A-04)

The v0.2.0 timeout killed the direct child only. A double-forked grandchild was reparented to init and survived — 4 orphans were observed.

Termination now proceeds in three steps and then **verifies**:

```
1. kill the process group          (covers same-group children)
2. kill the PID namespace          any member of the namespace dies with it,
                                   including processes reparented inside it
3. sweep /proc for descendants     host view, catches anything the namespace
                                   bookkeeping missed
4. verify: re-read /proc           terminate_and_verify() returns a BOOLEAN;
                                   the caller asserts it, it is not assumed
```

Because the workload runs in its own PID namespace, `kill -9` of the namespace's init (the supervisor) makes the kernel terminate every process in that namespace. A grandchild cannot escape: there is no process outside the namespace to reparent to.

**Measured (A-04 regression, `test_double_forked_grandchild_is_killed`):**

```
timed_out=True  terminated=True  processes_killed=4  surviving_orphans=0
```

This is the "cgroup-level or equivalent verified workload-level termination" requirement. It is equivalent in *effect* (whole tree dies, verified) but different in *mechanism* (`cgroup.kill` is unavailable here). The mechanism is recorded explicitly rather than presenting PID-namespace kill as cgroups.

---

## 5. Coverage of the required controls

| Requirement | Where | Status |
|---|---|---|
| per-job PID limits | `RLIMIT_NPROC` + PID namespace | **PASS** |
| per-job memory limits | `RLIMIT_AS` | **PASS** |
| CPU quotas | `RLIMIT_CPU` + wall clock | **PASS** (per-process) |
| max execution duration | parent timeout | **PASS** |
| max concurrent workloads | `CapacityGovernor` | **PASS** |
| global execution capacity | governor + memory clamp | **PASS** (single worker) |
| complete workload termination | namespace kill + `/proc` sweep + verification | **PASS** |
| automatic cleanup, success and failure | `finally:` in `run_isolated` | **PASS** |
| cgroups v2 aggregate enforcement | — | **NOT VERIFIED** |

## 6. Residual risk

* **Aggregate memory is a budget, not a hard kernel cap.** N concurrent workloads can each reach `RLIMIT_AS`; the governor bounds N so the product is bounded, but there is no kernel object that refuses the allocation at the aggregate level. With cgroups v2 that object would be `memory.max`.
* **`RLIMIT_NPROC` is per-uid.** All sandbox workloads share uid 65534 in their namespace, which is fine because each runs in its own PID namespace; on a host where the same uid is shared *without* PID isolation this would over-count.
* **CPU is time-limited, not rate-limited.** A workload can saturate a core for its full slice. There is no shares/quota mechanism without cgroups.
