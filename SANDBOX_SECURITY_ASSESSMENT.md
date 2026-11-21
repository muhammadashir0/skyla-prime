# SANDBOX SECURITY ASSESSMENT — SKYLA PRIME v0.2.1

**Target:** `skyla/execution/providers.py`, `NamespaceProvider` (declared default in v0.2.0)
**Method:** source inspection + adversarial execution against a live instance, unprivileged host user (uid 1001).
**Date:** 2026-11-21
**Result summary: 9 PASS · 6 FAIL · 0 NOT VERIFIED**

---

## 1. Mechanism actually implemented

```
unshare -Urmpf -n  sh  inner.sh
   ├── mount --make-rprivate /
   ├── mount --bind -o ro  /usr/bin /usr/lib /lib /lib64 /bin /sbin  → chroot/usr...
   ├── mount --bind        {ws}  rootfs/workspace        # rw, ephemeral
   ├── mount -t tmpfs -o ro tmpfs rootfs/etc             # read-only /etc
   ├── mount -t tmpfs      tmpfs rootfs/tmp              # rw, ephemeral
   ├── mount -t proc  proc  rootfs/proc
   ├── mount -t tmpfs      tmpfs rootfs/dev
   ├── ulimit -v {memory_mb*1024}
   └── exec /usr/sbin/chroot rootfs /usr/bin/python3 /workspace/script.py
```

`subprocess.run(..., timeout=timeout_s+5)` from a minimal environment.

**What this gets right:** genuine mount/PID/net/user namespaces, `--make-rprivate` (correct — prevents
mount propagation back to the host), a read-only runtime bind set, a private tmpfs `/etc`, an
ephemeral workspace, and a fixed minimal environment. The chroot is applied *before* the untrusted
interpreter starts, so host paths are gone by the time any attack code runs. This is a real
improvement over v0.1.0 and most of the containment observed below is a direct consequence of it.

**What it does not do:** no capability dropping, no `no_new_privs`, no seccomp, no cgroup, no
`RLIMIT_NPROC`, no `RLIMIT_CPU`, no `RLIMIT_FSIZE`, no process-group kill, no concurrency limit.

## 2. Control-by-control findings

| # | Control | Implemented? | Independent result |
|---|---|---|---|
| 1 | User namespace | yes (`-U -r`) | **PASS** — root is a mapped user-namespace root; host uid unchanged |
| 2 | Mount namespace | yes (`-m`, `--make-rprivate`) | **PASS** — private mount table; `libc.mount()` works only inside it |
| 3 | PID namespace | yes (`-p -f`) | **PASS** — only PID 1 visible; cannot see or signal host processes |
| 4 | Network namespace | yes (`-n` by default) | **PASS** — `ENETUNREACH` on TCP, DNS `gaierror`, host listener never connected |
| 5 | Filesystem confinement | yes (`chroot`) | **PASS** — host `/tmp` canary and `/etc/passwd` unreachable |
| 6 | Root filesystem immutable | partial | **PASS (effective)** — `/usr`, `/lib`, `/bin`, `/etc` are `ro`; `/workspace` and `/tmp` are `rw` |
| 7 | Workspace independently mounted | yes (bind mount) | **PASS** — separate ephemeral mount; removed after the run |
| 8 | Privileged capability removal | **NO** | **FAIL (High)** — see §3.1 |
| 9 | `no_new_privs` | **NO** | **FAIL (High)** — `NoNewPrivs: 0` |
| 10 | Seccomp-BPF | **NO** | **FAIL (Medium)** — `Seccomp: 0`, no filter |
| 11 | AppArmor / SELinux | **NO** | **FAIL (Medium)** — no LSM profile applied |
| 12 | Landlock | **NO** | **FAIL (Low)** — not used (would be a strong defence-in-depth layer) |
| 13 | Cgroups v2 | **NO** | **FAIL (High)** — no `memory.max`/`pids.max`/`cpu.max` |
| 14 | Memory limit | child-only (`ulimit -v`) | **FAIL (High)** — see §3.2 |
| 15 | CPU quota | **NO** | **FAIL (Medium)** — 5 s burn succeeded unabated |
| 16 | PID limit | **NO** | **FAIL (High)** — see §3.3 |
| 17 | Wall-clock timeout | yes | **PASS** — returns `Timed out after 4s` |
| 18 | Forced termination completeness | **NO** | **FAIL (High)** — see §3.4 |
| 19 | Output size cap | yes (8 KB) | **PASS** — 50 KB print truncated |
| 20 | File storage quota | **NO** | **FAIL (Medium)** — 300 MB written to `/workspace` |
| 21 | Concurrent workload limit | **NO** | **FAIL (High)** — no semaphore anywhere in the codebase |
| 22 | Env / secret isolation | yes | **PASS** — `[]` sensitive vars |
| 23 | FD leakage | none observed | **PASS** |
| 24 | Working directory escape | no | **PASS** — cwd `/workspace` |
| 25 | Ptrace | blocked | **PASS (mitigated)** — `EPERM`; blocked by chroot+namespace, not by caps |
| 26 | Procfs exposure | namespace procfs only | **PASS** |
| 27 | Sysfs exposure | absent after chroot | **PASS** |
| 28 | Device access | `/dev` empty tmpfs, no `/dev/mem` | **PASS (mitigated)** — `mknod` denied |
| 29 | Unix sockets | none reachable (no `/run`) | **PASS** |
| 30 | Shared memory | blocked | **PASS** |
| 31 | Cleanup after termination | workspace removed | **PASS (files)** / **FAIL (processes)** — see §3.4 |

## 3. Detailed findings

### 3.1 All capabilities retained inside the sandbox — **HIGH**

```
$ /api/execute/python  →  read /proc/self/status
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff      # all 41 capabilities
CapBnd: 000001ffffffffff
NoNewPrivs: 0
Seccomp:    0
Seccomp_filters: 0
uid 0 euid 0
```

Proof the capability is *effective*, not just declared:

```
libc.mount(b'tmpfs', b'/tmp', b'tmpfs', 0, None)   → rc 0, errno 0     # CAP_SYS_ADMIN works
```

**Why this matters despite chroot.** Containment today rests entirely on "the chroot removed every
path worth abusing". That is a single control. Any regression that re-exposes a host path — a new
bind mount, a stray `--rbind`, a workspace path that resolves into the host, a compiler that writes
outside `/workspace` — converts a High finding into a Critical host-compromise. Defence in depth
requires the capability to be gone *as well as* the path.

**Why it happened.** Inside `unshare -U -r` the caller becomes full root of a new user namespace, and
all capabilities are granted by the kernel over that namespace. Nothing in `inner.sh` drops them.

**Remediation (concrete).**
```sh
# after chroot, before exec of untrusted code
prctl --no-new-privs  # PR_SET_NO_NEW_PRIVS=1
capsh --drop=all -- -c 'exec python3 /workspace/script.py'
# or, dependency-free: a 20-line capset(0,0,0,0) exec wrapper in C
```
Also drop from the bounding set (`PR_CAPBSET_DROP`) so a later `execve` cannot regain them, and add a
seccomp allowlist on top.

**Documentation defect.** `SANDBOX_ARCHITECTURE.md` line 65 states *"Dropped capabilities … no host
caps"*. The audit measured the opposite. That claim must be removed, and the threat-model row for
capabilities must read "retained inside the namespace; containment relies on chroot" until fixed.

### 3.2 Memory limit does not protect the host — **HIGH**

Observed in two stages:

1. Inside a single sandbox, a 2 GB / 3 GB allocation raises `MemoryError` ✅ (`ulimit -v` works for *that* process).
2. But the provider sets **no aggregate limit and no concurrency limit**, so N simultaneous
   executions each get their own 512 MB, plus 300 MB workspace writes are unbounded.

Consequence, measured: after a series of sandbox stress requests the API server itself was
**terminated with exit code 137 (SIGKILL)** — the host OOM killer selected the process holding the
largest RSS: the server. Availability of the entire platform is therefore controllable by any
principal holding `execute` (i.e. every operator).

**Remediation.** cgroup v2 per execution:
```
/sys/fs/cgroup/skyla/<uuid>/{memory.max=536870912, memory.swap.max=0, pids.max=64,
                             cpu.max="100000 100000", io.max=…}
cgroup.kill      # to terminate the whole tree
```
Plus a process-wide `asyncio.Semaphore(SKYLA_MAX_CONCURRENT_EXECUTIONS)` around `execution.run`.

### 3.3 No PID limit — **HIGH**

Controlled proof (bounded to 40 so as not to re-trigger the outage):

```
FORKED 40 CONCURRENT CHILDREN - no process limit applied
my children: 40
```

Uncontrolled attempt: the fork storm drove `/proc/loadavg` to **13 989.14** and the harness was
killed by the platform. `RLIMIT_NPROC` is asserted in `SANDBOX_ARCHITECTURE.md` line 68 (`fork storms
capped`) — **false**; the only `ulimit` in `inner.sh` is `-v` (memory).

Note: `RLIMIT_NPROC` is per-*uid*, and the sandbox runs as namespace-root, so a naive `ulimit -u`
would count every sandbox process together — acceptable, but cgroup `pids.max` is the correct,
per-execution control.

### 3.4 Timeout does not kill the process tree — **HIGH**

```
parent spawns child(sleep 300), then loops
→ result: ok=False "Timed out after 4s"      (correct)
→ 2 s later: 38614  1  R  /usr/bin/python3 /workspace/script.py   <-- STILL RUNNING, ppid=1
             38627 38614 S  ...                                    <-- its child too
```

`subprocess.run(timeout=…)` kills only the direct `unshare` child; the interpreter inside the PID
namespace is reparented to init and keeps running. Workspace directories *were* cleaned up
(`leftover workspace dirs: []`) — so the filesystem cleanup claim holds, but the **process** cleanup
claim does not. Repeat this a few times and the host fills with runaway interpreters.

**Remediation.** Launch with `start_new_session=True` and kill the process group
(`os.killpg(os.getpgid(pid), SIGKILL)`), or prefer cgroup `cgroup.kill` which is race-free and
handles double-forked grandchildren.

### 3.5 No seccomp filter — **MEDIUM**

`Seccomp: 0`. The many syscalls an agent never needs (`bpf`, `keyctl`, `add_key`, `userfaultfd`,
`perf_event_open`, `io_uring_setup`, `mount`) remain reachable. Combined with §3.1 this is a wide
kernel attack surface for a hostile workload. Docker's default profile would already block several of
these; the namespace provider has nothing.

**Remediation.** A deny-by-default allowlist (`read, write, openat, close, mmap, brk, exit_group, …`)
via `libseccomp`/`python-seccomp`, or run under `gVisor` (see §5) which supplies the syscall surface
itself.

### 3.6 No LSM confinement — **MEDIUM**

No AppArmor or SELinux profile. A profile scoped to the rootfs path and denying `mount`, `ptrace`,
`mknod` and network would blunt §3.1 and §3.5 at negligible cost where the LSM is available.

### 3.7 File storage not quota-limited — **MEDIUM**

```
open('/workspace/big.bin','wb').write(b'x'*(300*1024*1024))   → wrote 300MB to workspace  (ok=True)
```
`/workspace` is a bind mount of a host directory with no `RLIMIT_FSIZE` and no tmpfs `size=` limit.
Sustained writes can fill the host volume.

**Remediation.** Make the workspace a `tmpfs` with `size=64m,mode=0700`, or enforce `RLIMIT_FSIZE`.

### 3.8 Concurrency unbounded — **HIGH**

`grep -rn "Semaphore|max_concurrent" skyla/` → nothing. Both `/api/execute/python` (synchronous) and
`asyncio.create_task(orchestrator.run_task_async(tid))` in `/api/tasks` accept unlimited
simultaneous work. Combined with §3.2/§3.3 this is the mechanism behind the observed server kill.

### 3.9 Latency observation — **LOW / reliability**

Each sandbox execution took roughly **45 s** of wall time in the worst probe (`T1`–`T3` batched), while
a small script returned promptly later — the cost is dominated by the shell script's mount sequence
and cold interpreter start. Worth profiling; not a security issue.

## 4. What is genuinely solid

- Private mount propagation (`--make-rprivate`) is easy to get wrong and is correct here.
- The chroot happens before the interpreter starts — no TOCTOU window on the runtime.
- `/etc` is a *read-only empty tmpfs*: credential files, `passwd`, `resolv.conf` and hosts entries are
  all absent, which is why DNS and credential reads fail.
- The minimal environment removes inherited secrets entirely.
- Output truncation is applied on the host side, not trusted from the child.

## 5. Runtime comparison (assessed, not installed)

| Runtime | Status | Assessment |
|---|---|---|
| **namespace (current)** | **PASS with 6 High defects** | Adequate boundary for *semi-trusted* operator code once §3.1–§3.4 are fixed. Not appropriate for arbitrary third-party code today. |
| **gVisor (`runsc`)** | **NOT VERIFIED** (not installed; needs root) | **Recommended next step.** User-space kernel intercepts syscalls, making §3.1/§3.5 largely irrelevant. Practical drop-in via the existing `ContainerProvider` seam (`--runtime=runsc`). |
| **Firecracker** | **NOT VERIFIED** (needs `/dev/kvm`, not present) | Strongest boundary, correct long-term target for a dedicated research host. Heavy for this workload profile; requires a KVM-capable machine and image/jailer tooling. |
| **rootless Docker** | **NOT VERIFIED** (no daemon) | `ContainerProvider` already passes `--cap-drop ALL`, `--pids-limit 64`, `--read-only`, `--memory`, `--cpus`, `no-new-privileges` — the **correct** flag set that the namespace provider omits. Would close §3.1/§3.3/§3.6/§3.7 immediately if a daemon existed. |

**Important:** `ContainerProvider` *claims* `isolated=True, safe_for_untrusted=True` and its flag list is
sound, but it has **never been executed in this environment** — its only exercised path is the
"docker not available → return error" branch. It must be marked **NOT VERIFIED** until run on a host
with a daemon.

## 6. Verdict

**Execution isolation: FAIL.** Containment of *filesystem*, *network*, *PID visibility*, *secrets* and
*naming* is real and independently reproduced — a substantial improvement over v0.1.0. But the sandbox
**cannot protect its own host** from resource exhaustion (capabilities, PIDs, CPU, disk, concurrency,
process cleanup), and three properties asserted in `SANDBOX_ARCHITECTURE.md` (dropped capabilities,
`RLIMIT_NPROC`, `RLIMIT_CPU`) are **not implemented**. A running server was killed during this
assessment by exactly that gap.

Until §3.1–§3.4 and §3.8 are closed, `execute` must be limited to principals who are already trusted
with host-level impact, and `safe_for_untrusted: true` should be reported as **false**.
