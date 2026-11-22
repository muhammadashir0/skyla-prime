# Cgroup v2 Delegation Guide

How to delegate cgroup v2 controllers to the SKYLA PRIME service user, what each step actually does, and —
importantly — the two failure modes that produce a *convincing but false* success.

- Host: `e2b.local`, kernel 6.1.158+, Debian 12, cgroup2fs
- Applies to: v0.2.5

---

## 1. Why a privileged step exists at all

cgroup v2 will not let an unprivileged process create a cgroup whose ancestors are not delegated to it, and
**it cannot delegate to itself**. So exactly one privileged operation is required at install time. After that
the service owns its subtree and performs every controller operation unprivileged.

This is the same contract systemd provides with `Delegate=yes`: the privilege is spent once, by an
administrator, and the runtime never needs it.

## 2. Host facts (measured)

| Property | Value |
|---|---|
| cgroup v2 mounted | yes — `cgroup2 on /sys/fs/cgroup (rw,...,nsdelegate,memory_recursiveprot)` |
| controllers available | `cpuset cpu io memory hugetlb pids` |
| root `cgroup.subtree_control` | `cpuset cpu io memory pids` |
| `/sys/fs/cgroup` ownership | `root:root`, `dr-xr-xr-x` |
| our shell's cgroup | `/user`, owned `root:root` |
| `cgroup.kill` | **present** (kernel ≥ 5.14) |
| systemd | PID 1, `degraded` state, `Delegate=yes` accepted |
| `memory.swap.max` | present |

## 3. The bootstrap

```bash
sudo scripts/cgroup_bootstrap.sh
```

What it does, in order:

1. requires `uid 0` and `cgroup2fs` at `/sys/fs/cgroup`;
2. verifies `memory`, `pids`, `cpu` exist in `/sys/fs/cgroup/cgroup.controllers`;
3. enables them in the **root** `cgroup.subtree_control`;
4. recreates `/sys/fs/cgroup/skyla` from scratch (idempotent);
5. enables the same controllers on that new subtree;
6. `chown -R` the subtree to the service user;
7. prints the resulting controller sets.

Measured result:

```
delegated: /sys/fs/cgroup/skyla -> user
root subtree_control: cpuset cpu io memory pids
skyla subtree_control: cpu memory pids
controllers: cpuset cpu io memory pids
```

## 4. Failure mode 1 — POSIX `-w` lies on cgroupfs

`test -w` on a cgroup file returns **success** while the actual write returns `EPERM`:

```
$ test -w /sys/fs/cgroup/skyla/service/cgroup.procs && echo WRITABLE
WRITABLE
$ echo $$ > /sys/fs/cgroup/skyla/service/cgroup.procs
bash: echo: write error: Permission denied
```

Why: cgroupfs applies checks in its write handler that the mode bits do not represent (notably "every
ancestor must be delegated"). `/user` is `root:root`, so no amount of ownership on the *leaf* helps.

**This is why `scripts/skyla-run.sh` was fixed in v0.2.5.** It previously trusted `-w`, discarded the write
error with `|| true`, and launched unplaced while appearing to succeed. It now attempts the write and then
confirms the result against `/proc/self/cgroup`, warning loudly on failure.

## 5. Failure mode 2 — the "no internal processes" rule

A cgroup with member processes cannot have controllers enabled on itself. The kernel reports this as
**`ENOENT` on opening `cgroup.subtree_control`**, which reads like a missing file rather than a policy
refusal:

```
fd = os.open(branch + "/cgroup.subtree_control", os.O_WRONLY)
OSError: [Errno 2] No such file or directory
```

`os.path.exists()` on the same path returns **True**. The error number is misleading; the cause is

```
branch_procs: 3      # processes still inside → cannot enable controllers here
```

Two ways out, both valid:

- **enable top-down before placing processes** — create the subtree, enable controllers, *then* start work;
- **move work into a leaf** — processes live in `.../job-N/`, controllers are enabled on `.../` itself.

SKYLA does both: the bootstrap enables controllers before the service starts, and jobs go into leaf cgroups.

## 6. Recommended launcher for production

The simplest correct arrangement is systemd, which owns the placement:

```ini
# /etc/systemd/system/skyla-prime.service
[Service]
Type=simple
User=user
ExecStart=/opt/skyla/venv/bin/uvicorn skyla.api.app:app
Delegate=yes
MemoryMax=1G          # the aggregate ceiling, enforced by systemd itself
TasksMax=256
```

With `Delegate=yes` the service's own cgroup becomes writable by the service user, so `create_job` can make
child cgroups without any further privilege. This is the supported path the mission asked for, and it avoids
the manual bootstrap entirely.

**Measured caveat on this host:** `systemd-run --scope -p Delegate=yes` creates the scope but leaves it
`root:root`, and root cannot enable controllers on it while it holds the scope's own members. A chown plus a
leaf move is required. Because the manual bootstrap already works here, that path is what this release uses
and what the evidence was gathered against. A host using the unit above should be re-qualified through
`scripts/skyla-host-qualify.sh`.

## 7. Running with delegation

```bash
# one-time
sudo scripts/cgroup_bootstrap.sh

# launch inside the delegated subtree
scripts/skyla-run.sh python -m pytest tests/security/test_cgroups.py -q
# or, when the service user cannot perform the move itself:
SKYLA_LAUNCH_VIA_SUDO=1 scripts/skyla-run.sh <command>

# authorised: root places, then drops to the service user for the workload
sudo sh -c 'printf %s $$ > /sys/fs/cgroup/skyla/service/cgroup.procs
            exec setpriv --reuid=user --regid=user --clear-groups <command>'
```

The last form is what the qualification evidence uses: **root does exactly one thing** (places the process),
and everything afterwards runs unprivileged. The supervisor refuses to run as root
(`refusing to run: supervisor must not be setuid/root`), which is a control, not an obstacle — so cgroup tests
must be run as the service user, not as root.

## 8. Verifying it worked

```bash
cat /sys/fs/cgroup/skyla/cgroup.controllers        # must list memory, pids, cpu
cat /sys/fs/cgroup/skyla/cgroup.subtree_control    # same
ls /sys/fs/cgroup/skyla/cgroup.kill                # termination support
sed -n 's/^0:://p' /proc/self/cgroup               # must start with /skyla/
```

Then, unprivileged:

```bash
python -c "from skyla.execution.cgroups import governor_from_env as g; print(g().status())"
# cgroup_v2: True, placement: True
```

If `placement` is false, the service is outside the subtree — nothing else matters until it is fixed.

## 9. Without delegation

The application does not silently elevate and does not pretend. With no delegation:

- `probe()` returns `False` with a reason;
- `create_job` raises `CgroupUnavailable`;
- `NamespaceProvider.run` refuses untrusted execution;
- the API reports `cgroup: {enabled: false, reason: "..."}`.

That is the intended behaviour: an unenforced ceiling is not a ceiling, so the workload does not run.

## 10. Cleanup

```bash
sudo sh -c 'rmdir /sys/fs/cgroup/skyla/aggregate/job-* 2>/dev/null
            rmdir /sys/fs/cgroup/skyla/aggregate 2>/dev/null
            rmdir /sys/fs/cgroup/skyla 2>/dev/null'
```

Job cgroups are removed by `JobCgroup.destroy()`. Leftovers only appear when the *caller* dies before cleanup
— measured: an aborted test script left empty (`populated 0`) directories, never processes.
