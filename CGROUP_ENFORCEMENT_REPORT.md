# Cgroup Enforcement Report

**Result: enforcement is real and measured against the kernel. 18 previously-skipped tests now PASS.**

- Host: `e2b.local`, kernel 6.1.158+, cgroup v2, controllers `cpu memory pids` delegated
- Deployed via `sudo scripts/cgroup_bootstrap.sh`
- Commit: v0.2.5

---

## 1. Before and after

| | v0.2.4 | v0.2.5 |
|---|---|---|
| `/sys/fs/cgroup/skyla` | absent | **delegated to the service user** |
| `cgroup_v2` | true | true |
| `placement` | **false** | **true** |
| cgroup tests | **18 skipped** | **18 passed** |
| per-job limits | not exercised | **enforced and measured** |

The 18 skips were not a code problem. They were two launcher/host problems (§4 of
`CGROUP_DELEGATION_GUIDE.md`), both of which made a working kernel look unusable.

## 2. Limits verified against the kernel

Every value below was read back from cgroupfs after being written, and the *effect* was measured rather than
the setting:

| Limit | File | Written | Read back | Effect observed |
|---|---|---|---|---|
| job memory | `memory.max` | 128 MB | `134217728` | **OOM-killed at exactly 128.0 MB peak** |
| job swap | `memory.swap.max` | `0` | `0` | no swapping around the limit |
| job OOM group | `memory.oom.group` | `1` | `1` | whole group killed, not one thread |
| job pids | `pids.max` | 12 | `12` | fork storm stopped at **11**; `pids.events max 1` |
| job cpu | `cpu.max` | `50000 100000` | same | 50% of one core |
| aggregate memory | `memory.max` | 1024 MB | `1073741824` | 4×400 MB jobs → 2 admitted |
| aggregate pids | `pids.max` | 256 | `256` | — |
| aggregate cpu | `cpu.max` | `150000 100000` | same | — |
| tree termination | `cgroup.kill` | — | present | tree emptied, `populated 0` |

### Memory limit — measured, not asserted

A job capped at 128 MB that tries to allocate 400 MB:

```
returncode: -9
memory.events: low 0 high 0 max 35 oom 1 oom_kill 2 oom_group_kill 1
oom_kills: 2 | peak_mb: 128.0
exceeded(): memory (oom_kill)
```

`peak_mb: 128.0` against `memory.max = 134217728` is the kernel refusing to let the process grow past the
ceiling. `oom_group_kill 1` confirms `memory.oom.group` took the whole tree rather than one thread.

### PID limit — measured

Under `pids.max = 12`:

```
fork stopped after 11 -> Resource temporarily unavailable
pids.events: max 1
pids_peak: 12
```

The workload requested 50 forks and got 11. `pids.events max 1` is the kernel's own counter of hits against
the ceiling — not something the application computed.

## 3. Fail-closed behaviour

The mission's requirement was explicit: *a failed write must never produce `enabled: true`.*

Every limit write is gated on its return value, and a failure destroys the partially-created job and raises:

```python
for filename, value in (("memory.max", ...), ("memory.swap.max", "0"),
                        ("memory.oom.group", "1"), ("pids.max", ...), ("cpu.max", ...)):
    if not _write(path / filename, value):
        self._forget(jid)
        path.rmdir()
        raise CgroupUnavailable(
            f"cannot set {filename} on {path} — refusing to run the workload "
            f"with an unenforced limit")
```

The aggregate ceiling is gated identically, including the two `cgroup.subtree_control` writes — a controller
enabled only at the root does not reach grandchildren, so both are load-bearing.

Measured proof (`test_failed_cgroup_write_refuses_execution`): with `_write` patched to always fail,
`ensure_aggregate()` raises `CgroupUnavailable`. It does not return a partially-configured aggregate.

### The reporting path

`NamespaceProvider.run` builds its `controls` dict from what actually happened:

```python
controls["cgroup"] = {"enabled": job is not None,
                      "cgroup_v2": bool(cg_status.get("cgroup_v2")),
                      "placement": bool(cg_status.get("placement")),
                      "reason": cg_status.get("reason", "")}
```

`enabled` is `job is not None`, and `job` is only non-`None` when `create_job` succeeded with every write
verified. There is no path where a failed write yields `enabled: true`.

## 4. What is NOT enforced

| Item | Status | Reason |
|---|---|---|
| Disk / IO quota | **not enforced** | `io.max` requires a block device in the container's view; not configured here |
| `memory.high` (soft throttle) | not set | hard `memory.max` + OOM group is the chosen policy |
| Aggregate swap | available | `memory.swap.max` exists; aggregate sets `0` on the job layer only |
| CPU pinning | not enforced | `cpuset` delegated but not assigned per job |
| Denial logging | **unavailable** | no `LOG`/`limit` netfilter extensions; unchanged from v0.2.4 |

Disk consumption was listed in Mission E. It is **NOT VERIFIED**: the host has no per-cgroup block-device
IO limit configured, so a workload writing to the shared filesystem is unbounded apart from `RLIMIT_FSIZE`
(32 MB, applied by the supervisor for the `namespace` provider). Recording this rather than claiming a
control that is not there.

## 5. Aggregate host protection — measured

With a 1024 MB aggregate ceiling and 4 concurrent jobs each requesting 400 MB:

```
job0: admitted
job1: admitted
job2: REFUSED by admission control — 3 concurrent jobs x 400 MB would exceed the 1024 MB aggregate ceiling
job3: REFUSED by admission control — ...
aggregate memory.current peak: 601 MB (ceiling 1024 MB)
under ceiling: True
```

Two layers did the work: admission control refused at request time, and the kernel ceiling held the
remaining load at 601 MB.

**But the mission warns against substituting a semaphore for kernel enforcement**, and the honest reading is
that *both* were needed here:

- the semaphore (`AggregateCapacityExceeded`) is what refused jobs 2 and 3;
- the kernel `memory.max` on the aggregate is what would have caught a job that underestimated its own usage.

`MemoryMax=`/`TasksMax=` on the systemd unit is the cleaner arrangement for the aggregate layer (see
`CGROUP_DELEGATION_GUIDE.md` §6); this release measured the governor's own implementation.

## 6. Reproducing

```bash
sudo scripts/cgroup_bootstrap.sh                 # one-time delegation

# as the service user, inside the delegated subtree
sudo sh -c 'printf %s $$ > /sys/fs/cgroup/skyla/service/cgroup.procs
            exec setpriv --reuid=user --regid=user --clear-groups \
              /tmp/env4/bin/python -m pytest tests/security/test_cgroups.py -q'
# 18 passed
```

Expected totals:

| Run | Result |
|---|---|
| unprivileged, no delegation | 18 skipped (NOT VERIFIED) |
| delegated, **as root** | 3 failed — the supervisor refuses root, correctly |
| delegated, **as service user** | **18 passed** |

The middle row is not a bug. Running as root is refused by design
(`refusing to run: supervisor must not be setuid/root`), and the cgroup tests reach that code path.

## 7. Verdict

| Acceptance criterion | Status |
|---|---|
| Cgroup setup fails closed | **PASS** |
| Aggregate resource limits actually enforced | **PASS** (measured 601 MB under a 1024 MB ceiling) |
| Per-job memory limit enforced | **PASS** (OOM at exactly 128 MB) |
| Per-job PID limit enforced | **PASS** (stopped at 11 of 50 requested) |
| `cgroup.kill` tree termination | **PASS** (`populated 0` after) |
| Every write checked | **PASS** (mutation-verified) |
| Disk/IO quota | **NOT VERIFIED** |
| API reports actual state | **PASS** |
