# Aggregate Resource Tests

> **The adversarial tests described in Mission E were NOT run.** Only the aggregate-ceiling and
> API-responsiveness tests were performed. Everything not measured is marked NOT VERIFIED.

- Commit: v0.2.5 · Host: `e2b.local`, kernel 6.1.158+, 2 vCPU, 3939 MB
- Aggregate ceiling used: 1024 MB memory / 256 pids / 150% CPU

---

## 1. What the mission asked for, and what I actually did

| Requested | Status | Note |
|---|---|---|
| Multiple memory-intensive tasks | **PASS** | 4×400 MB against a 1024 MB ceiling |
| CPU-intensive tasks | **PASS** (bounded) | 6 concurrent busy loops, aggregate `cpu.max` set |
| Process creation | **PASS** | `pids.max=12` per job stopped a 50-fork storm at 11 |
| **Large output generation** | **NOT VERIFIED** | only the supervisor's `RLIMIT_FSIZE=32MB` was exercised |
| **Disk consumption** | **NOT VERIFIED** | no `io.max` configured; no test |
| **Maximum concurrency** | **PARTIAL** | 6 requested, 4 admitted — the configured limit, not a measured maximum |
| Simultaneous API requests | **PASS** | 1197 requests during saturation, p99 15 ms |
| Application semaphore substituted for kernel limit | **avoided** | both layers present and separately evidenced |

I did not run a disk-exhaustion test. Filling the filesystem of the machine I am working on, to prove a
control that is **not configured**, would risk the environment to produce a FAIL I already know the answer
to. The honest entry is NOT VERIFIED.

## 2. Memory ceiling — measured

Four jobs, each requesting 400 MB, against a 1024 MB aggregate:

```
job0: admitted
job1: admitted
job2: REFUSED by admission control — 3 concurrent jobs x 400 MB would exceed the 1024 MB aggregate ceiling
job3: REFUSED by admission control — ...
aggregate memory.current peak: 601 MB (ceiling 1024 MB)
under ceiling: True
```

Requesting 4×400 MB = 1600 MB against a 1024 MB ceiling would overcommit by 56%. Admission control refused
the third job *by arithmetic*, before any process started.

This is the semaphore layer working. The kernel layer is separate evidence: the aggregate's own `memory.max`
is 1024 MB, and the OOM behaviour of a job cgroup was measured directly at exactly its limit
(`CGROUP_ENFORCEMENT_REPORT.md` §2).

## 3. Per-job enforcement — measured

| Test | Limit | Observed |
|---|---|---|
| 400 MB allocation | `memory.max=128MB` | killed, `peak_mb: 128.0`, `oom_group_kill 1` |
| 50 forks | `pids.max=12` | stopped at 11, `pids.events max 1` |
| busy loop | `cpu.max=50000 100000` | 50% of one core |

The memory result is the strongest: a process cannot exceed `memory.max` by allocating. Peak usage equals the
limit to one decimal place because the kernel kills it the moment it tries to grow.

## 4. API responsiveness under saturation — measured

With the aggregate saturated and 4 jobs running 120 MB + busy loops:

```
/api/health: n=1197 p50=4ms p99=15ms max=35ms status=200
API responsive (<1s): True
```

1197 requests over ~6 seconds with a 15 ms p99. The API stays responsive because workloads run in separate
process trees under separate cgroups — the API is not competing for the same ceiling as a member.

**Methodological note:** my first attempt probed `/health`, which does not exist, and reported `status=404`
with excellent latency. A latency benchmark against a 404 measures routing, not health. Corrected to
`/api/health` and re-measured. Worth stating because "1197 requests succeeded" would have been true and
meaningless.

## 5. What would have broken the API, and did not

The failure mode this control prevents (audit finding A-03) is that N concurrent executions each received
their own allowance and the **API process** was selected by the OOM killer. Under saturation:

- the API kept serving at p99 15 ms;
- the aggregate stayed at 601 MB of a 1024 MB ceiling;
- no OOM kill was attributed to the API process.

## 6. Concurrency limits

| Setting | Value | Source |
|---|---|---|
| `max_concurrent_jobs` | 4 | governor default |
| `SKYLA_MAX_CONCURRENT_EXECUTIONS` | 2 | `CapacityGovernor` semaphore |
| `agg_memory_mb` | 1024 | governor |
| `agg_pids` | 256 | governor |

Two limits apply to different layers: the execution semaphore bounds workloads in flight, the aggregate
bounds resources. In the measured run the *memory arithmetic* bound first, which is the intended precedence —
the tighter constraint wins.

## 7. Isolation of the test environment

Tests ran as the service user inside the delegated subtree, in job cgroups under the aggregate ceiling, so
the adversarial load was itself bounded. The stress script could not exhaust the host because its own
workloads were subject to the same `memory.max`/`pids.max` being tested. That is the correct arrangement: an
unbounded test of a bounding mechanism proves nothing about the mechanism.

## 8. Reproducing

```bash
sudo scripts/cgroup_bootstrap.sh
# as the service user, inside the delegated subtree:
sudo sh -c 'printf %s $$ > /sys/fs/cgroup/skyla/service/cgroup.procs
            exec setpriv --reuid=user --regid=user --clear-groups \
              /tmp/env4/bin/python /tmp/stress.py'
```

## 9. Verdict

| Criterion | Status |
|---|---|
| Aggregate limit enforced and not exceeded | **PASS** (601 MB of 1024 MB) |
| Per-job limits enforced by the kernel | **PASS** |
| Admission control refuses overcommit | **PASS** |
| API responsive under bounded stress | **PASS** (p99 15 ms) |
| Kernel enforcement, not only a semaphore | **PASS** (both layers evidenced separately) |
| Large output / disk exhaustion | **NOT VERIFIED** |
| Maximum concurrency determined empirically | **NOT VERIFIED** |
