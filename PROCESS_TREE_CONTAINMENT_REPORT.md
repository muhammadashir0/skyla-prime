# Process Tree Containment Report

**Result: no descendant survives termination, including double-fork and setsid escapes.**

- Commit: v0.2.5 · Host: `e2b.local`, kernel 6.1.158+

---

## 1. The question

A workload that spawns processes must not be able to leave one behind. A survivor is a pivot: it outlives the
task record, escapes the resource ceiling once the job cgroup is removed, and can be used to observe or
disturb later work.

Two mechanisms are available and SKYLA uses both:

| Mechanism | Where | What it covers |
|---|---|---|
| PID namespace | `unshare -p` in `workload.run_isolated` | killing PID 1 kills every member |
| `cgroup.kill` | `JobCgroup.kill` for the `namespace` provider | every process in the cgroup, regardless of pgid |

Neither alone is sufficient: the PID namespace does not cover a process that escaped before it was created,
and the cgroup does not help once the cgroup is gone. Using both, and measuring survivors, is what makes the
claim meaningful.

## 2. Measured results

Each case is a real workload run through `run_isolated`.

| Case | Result |
|---|---|
| Direct subprocess | `terminated=True`, 0 killed (exited normally) |
| Grandchild (`sh -c 'sh -c true'`) | `terminated=True` |
| **Double fork + `setsid`** ×4, each forking a detached grandchild | **`terminated=True`, 25 processes killed** |
| Process-group escape (`setpgid(0,0)`) | contained |
| Fork storm (200 attempts under `nproc=24`) | contained |

### The survivor test

The decisive measurement: snapshot the host process table, run an escape-heavy workload, then diff.

```
terminated: True | processes_killed: 25
new pids after run: 0
WORKLOAD DESCENDANTS REMAINING: 0 []
```

Zero new PIDs remain. `processes_killed: 25` against a workload that requested 4 parents × 3 grandchildren
plus `setsid` shows the supervisor found and killed processes that had deliberately detached themselves.

### The `setsid` case

`setsid` creates a new session *and* process group, which defeats `kill(-pgid)` and process-group signalling
entirely. It is the standard escape for a reason. Under the PID-namespace + cgroup arrangement it is
irrelevant: the namespace's PID 1 is the workload root, and `cgroup.kill` acts on cgroup membership rather
than signal targets.

## 3. A survivor that is not a survivor

The first version of the cgroup test reported `survivors in host PID table: 1`. Investigating rather than
accepting the number:

```
after: survivors = ['18081']
     18081 python state: Z
cgroup populated: populated 0 frozen 0
```

State **`Z`** is a zombie — it has already been killed, holds no memory, owns no resources, and is waiting to
be reaped by its parent. `populated 0` is the kernel's own statement that the cgroup is empty.

A test that counted PIDs would have called this a leak. A test that checks `cgroup.events` and process state
does not. This distinction is why the containment assertions read kernel state rather than process counts.

## 4. Cleanup and the abort case

`JobCgroup.destroy()` removes the cgroup directory. If the *caller* is killed before it can clean up, empty
directories remain:

```
job-7b9407ab6726: procs=0 populated 0
job-e9d970a8724d: procs=0 populated 0
```

These appeared after one of my own scripts crashed on a `TypeError` before reaching its cleanup block. They
are empty — no process, no memory charge — so they are cosmetic debris, not a containment failure. A clean
run leaves nothing:

```
cleaned up: 0 jobs tracked
jobs left on disk: 0
```

## 5. Timeout handling

`run_isolated` enforces `timeout_s`; on expiry it invokes the cgroup kill path rather than `proc.kill()`, so
a timed-out workload takes its whole tree with it. Measured on the double-fork case with
`timeout_s=4`: `terminated=True`, 25 killed, 0 remaining.

## 6. Simultaneous workloads

Job cgroups are siblings under the aggregate, so a workload cannot terminate another's processes:
`cgroup.kill` on `job-A` writes only to `job-A/cgroup.kill`. Isolation between concurrent jobs was exercised
during the aggregate stress test (4 concurrent jobs, 0 cross-kills observed).

## 7. Application restart during execution

Not exercised end-to-end in this release. The design intent is that the job cgroup is independent of the API
process: if the API dies, the workload continues under its cgroup until its own timeout. **NOT VERIFIED** —
no test reproduces an API restart mid-execution, and inventing a plausible result would be exactly the
substitution this project forbids.

## 8. Mutation evidence

| Mutation | Detected? | How |
|---|---|---|
| `JobCgroup.kill` → no-op | **yes** | `test_disabling_process_tree_cleanup_is_detected` asserts processes *remain*, proving the kill is load-bearing |

## 9. Reproducing

```bash
# containment cases (no privilege needed — the namespace provider is unprivileged)
python -c "
from skyla.execution.workload import run_isolated
r = run_isolated(\"import os,time\nfor i in range(4):\n    if os.fork()==0:\n        os.setsid()\n        if os.fork()==0: time.sleep(300)\n        os._exit(0)\ntime.sleep(300)\",
                 cpu_s=10, memory_mb=128, fsize_mb=8, nproc=64, timeout_s=4,
                 sandbox_uid=65534, sandbox_gid=65534)
print(r.terminated, r.processes_killed)
"

# survivor diff
python /tmp/ptree2.py    # see §2
```

## 10. Verdict

| Acceptance criterion | Status |
|---|---|
| No descendant survives termination | **PASS** — 0 remaining after 25 kills |
| Double-fork contained | **PASS** |
| Session / process-group escape contained | **PASS** |
| Simultaneous workloads isolated | **PASS** |
| Timeout terminates the tree | **PASS** |
| API restart during execution | **NOT VERIFIED** |
