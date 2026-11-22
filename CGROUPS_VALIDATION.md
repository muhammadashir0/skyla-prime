# CGROUPS VALIDATION — v0.2.2 PRIME QUALIFICATION

**Mission 2.** OS-enforced resource governance; per-job and aggregate protection
demonstrated with real workload concurrency.

## Verdict

> **PASS** on this host, for the controls measured below, with two documented
> limitations (§7): `pids.max` bounds *concurrent* tasks (not forks over time), and
> the aggregate ceiling is enforced by the kernel but the *concurrency* count is
> still an application-side admission decision.

This closes the v0.3.0 `NOT VERIFIED` cgroup finding. The claim is narrow and
measured: every number below came from the kernel's own counters
(`memory.events`, `memory.peak`, `pids.peak`, `cpu.stat`) or from a workload's exit
status, never from an application-layer summary.

---

## 1. Why delegation needed root, exactly once

An unprivileged process cannot create cgroups under a root-owned parent, and it
cannot delegate to itself. Measured:

```
$ mkdir /sys/fs/cgroup/user/qtest
mkdir: cannot create directory ... Permission denied
$ echo "+memory" > /sys/fs/cgroup/user/cgroup.subtree_control
Permission denied
```

The cgroup v2 rule is stronger than "the target must be writable": migration
requires write access along the ancestor chain up to the common ancestor of source
and destination. Since the service starts in `/user` and the destination is under
`/skyla`, the root cgroup is always in the path — and `/sys/fs/cgroup/cgroup.procs`
is root-owned (`555`).

**Design consequence.** One privileged step at install time
(`scripts/cgroup_bootstrap.sh`), after which the subtree is owned by the service
user. There is **no runtime sudo**. If delegation is absent,
`CgroupGovernor.probe()` returns false → `create_job()` **raises**
`CgroupUnavailable` → the API refuses the workload. It never runs uncontained.

The service must also *start inside* the delegated subtree (cgroup v2 cannot move a
process into a subtree it did not come from). `scripts/skyla-run.sh` places it
there; `placement_ok()` detects the failure and refuses workload creation rather
than silently enforcing nothing.

## 2. Availability is proved by doing

`probe()` does not check that a directory exists. It creates a probe cgroup, writes
`memory.max` and `pids.max`, **reads them back**, requires `cgroup.kill` to exist,
then removes it. A cgroup2 mount that merely exists is not evidence of enforcement.

## 3. Per-job enforcement (kernel counters)

Measured as uid **1001**, inside the delegated subtree, on 2 vCPU / 3939 MB.

### Memory

```
alloc 600 MB under memory.max = 128 MB
  -> rc = -9 (SIGKILL), "ALLOCATED" absent from stdout
  -> memory.peak = 128.0 MB
  -> memory.events: oom_kill >= 1
```

This is kernel OOM, not a Python `MemoryError`. The distinction matters: v0.3.0's
evidence for the memory control was a `MemoryError`, which the audit correctly
refused as proof of host protection. `memory.oom.group=1` is set so the whole group
dies rather than one arbitrary task, and `memory.swap.max=0` prevents swapping
around the limit.

### PIDs

```
pids.max = 8, 60 concurrent forks attempted
  -> 7-8 simultaneous processes, pids.peak = 8, pids.events: max 1
```

Verified across limits 4/8/16 → `simultaneous = pids.max` each time.

### CPU

```
cpu.max = "20000 100000" (20% of one core), 2-3 s spin
  -> cpu.stat: nr_throttled = 21, throttled_usec = 1622863
```

The quota is enforced by the CFS bandwidth controller, evidenced by the kernel's
own throttle counter — not by elapsed wall time.

## 4. Aggregate enforcement (protects the API and other tenants)

A per-job limit alone lets N jobs each take their slice. The aggregate cgroup is the
deployment-wide ceiling:

```
aggregate memory.max = 384 MB, jobs request 128 MB each
  job 1 admitted
  job 2 admitted
  job 3 admitted
  job 4 REFUSED: AggregateCapacityExceeded:
      "4 concurrent jobs x 128 MB would exceed the 384 MB aggregate ceiling"
```

`AggregateCapacityExceeded` → HTTP 429 with `Retry-After`, so the caller is told to
back off instead of queueing until the host is exhausted.

### API survivability

The mission requires that one workload cannot starve the API. Measured
(`test_api_is_not_affected_by_a_runaway_workload`): while a workload is being
OOM-killed in an adjacent cgroup, the supervising process completes 20 000
trivial iterations in **< 5 s**. The controller and the API are separately
accounted, so the killed workload's memory is not charged against the API.

## 5. Complete termination via `cgroup.kill`

```
double-forked grandchild (escapes process-group kill), cgroup.kill = 1
  -> cgroup.procs empty immediately
  -> /proc sweep for the marker env var: 0 survivors
```

`cgroup.kill` is the primary mechanism now; the v0.3.0 PID-namespace kill remains
as a second line. Both run, and the result is ANDed:
`termination: "cgroup-kill+pid-namespace"`.

## 6. Integration with the execution path — three bugs found by measuring

Enforcement existing in a module is not enforcement in the product. Wiring the
governor into `NamespaceProvider.run()` exposed three defects that all read as
"working" until the kernel counters were inspected:

1. **The workload was never in the cgroup.** Attaching the `Popen` pid placed only
   the `unshare` parent there; `unshare(1)` forks, so children stayed outside
   (`pids_peak = 0`, `memory_peak_mb = 0.0`). An 800 MB allocation succeeded and a
   fork storm was unbounded *while the API reported `cgroup.enabled = true`*.
   Fixed by having the final process place **itself** in the job cgroup, verified
   to move parent and child together (`pids_peak = 2`) — whereas attaching the
   outer pid did not.
2. **Peak counters were read before sampling**, so they always reported `0.0` even
   when enforcement had worked. Reordered.
3. The PID test asserted `forked < 8` and passed only because unreaped zombies
   accumulated. Corrected (§7).

After the fix, through the real provider:

```
normal run  -> pids_peak=2, memory_peak_mb=2.93, termination=cgroup-kill+pid-namespace
fork storm  -> pids_peak=24 (bounded by pids.max=24)
memory bomb -> no ALLOCATED; refused under the combined limits
```

## 7. Limitations (not downgraded, stated)

* **`pids.max` counts concurrent tasks, not total forks.** A loop that forks and
  immediately reaps is never limited — only one child exists at a time. Verified:
  `forked 100` with `pids.max=8` when reaping, versus 7 when not. Both behaviours
  are correct; the first version of the test conflated them. Zombies count toward
  the limit, which is why the original test passed for the wrong reason.
* **Concurrency admission is still application-side.** The kernel enforces the
  aggregate memory ceiling (exceeding it triggers group OOM), but *deciding how
  many jobs to admit* is `max_concurrent_jobs` in `CapacityGovernor`. With multiple
  API workers that count is per-process, so the effective global ceiling is
  `workers × max_concurrent_jobs`. A true global cap needs either a single
  execution service or a shared admission counter. **Multi-worker aggregate
  admission: NOT VERIFIED.**
* **`io` and `cpuset` are not delegated**, so disk and cache pressure are not
  bounded. Not required by this release, but a workload can still saturate I/O.
* **Swap is disabled per job** (`memory.swap.max=0`); this is deliberate but means
  the aggregate is memory-only.
* **Single host.** See `SECOND_HOST_VALIDATION.md`.

## 8. Reproduction

```bash
sudo scripts/cgroup_bootstrap.sh                       # once
scripts/skyla-run.sh python -m pytest tests/security/test_cgroups.py -q
# 16 passed
```

Outside the delegated subtree the module **skips** (16 skipped) and that skip is
`NOT VERIFIED` — it is not a pass, and it is what a misconfigured deployment will
look like.
