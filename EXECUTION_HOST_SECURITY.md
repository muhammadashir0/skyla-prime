# PRIME CONTAINMENT — Execution Host Security

**Scope:** Mission 1. Remediation of audit findings **A-01, A-02, A-03, A-04, A-09, A-18, A-19**.
**Status vocabulary:** `PASS` / `FAIL` / `NOT VERIFIED`. Only the first is a claim of verified capability.
**Environment measured on:** Linux 6.1.158+, x86_64, unprivileged user (uid 1000), no `newuidmap`, no writable cgroup2 hierarchy.

---

## 1. What changed and why

The v0.2.0 sandbox was `subprocess` + `resource.setrlimit` in the same process tree as the API, sharing the host filesystem, network and credentials. The audit demonstrated that a workload could read the host canary file, retain capability bits, and leave orphaned process trees after a timeout. `RestrictedProvider` described itself honestly as dev-only, but the provider selector would still choose an unisolated path.

v0.3.0 removes the possibility of a silent unsafe path. Isolation is established by a **compiled supervisor**, `skyla/execution/skyla-sup.c`, which is a *different program* from the API process and is exec'd after every control is installed.

**Fail-closed selection (`providers.get_execution_provider`)**

| Runtime available | Provider selected | Untrusted execution |
|---|---|---|
| `skyla-sup` builds and verifies | `namespace` | allowed, contained |
| container runtime present | `container` | allowed, contained |
| neither | `disabled` | **refused (HTTP 503)** |
| explicit `restricted` + `SKYLA_ALLOW_UNSAFE_EXECUTION=1` | `restricted` | allowed, **reports `isolated: false`** |

`auto` never returns `RestrictedProvider`. This is asserted by
`tests/security/test_mutation_harness.py::test_mutation_execution_fallback_is_load_bearing`.

---

## 2. Control order inside the supervisor

Order is not stylistic; three of these steps are order-dependent and each was a real bug during implementation.

```
 1. close_inherited_fds()                 nothing leaks in from the parent
 2. prctl(PR_SET_NO_NEW_PRIVS, 1)         setuid binaries cannot regain privilege
 3. create_landlock_ruleset(rootfs)       MUST precede chroot: rules are inode-based
 4. chroot(rootfs); chdir("/workspace")   MUST precede the uid drop (CAP_SYS_CHROOT)
 5. setrlimit CPU/AS/NPROC/FSIZE/CORE/NOFILE
 6. setgroups/setgid/setuid -> 65534      best-effort (see §4)
 7. drop_all_capabilities()               bounding set + capset, then READ BACK
 8. install_seccomp()                     LAST: must not filter our own setup
 9. execve("/usr/bin/python3", script)
```

Namespace creation happens outside the supervisor:
`unshare -Urmpf -n sh inner.sh`, where `inner.sh` builds a private mount tree
(`mount --make-rprivate /`, read-only bind mounts of the runtime, an empty
read-only `/etc`, an ephemeral `/workspace`).

---

## 3. Control-by-control evidence

Evidence was captured by running a workload that reads its own kernel-visible state. The probe is `/tmp/adv-results.json` in the build session and is reproduced by `pytest tests/security/test_host_containment.py`.

| # | Control | Mechanism | Measured evidence | Status |
|---|---|---|---|---|
| 1 | Explicit capability dropping | `PR_CAPBSET_DROP` loop + `capset` zeros + read-back | `CapEff=0000000000000000`, `CapBnd=0000000000000000`, `CapPrm=0000000000000000` | **PASS** |
| 2 | No new privileges | `PR_SET_NO_NEW_PRIVS` (set twice: explicit + inside Landlock setup) | `NoNewPrivs: 1` | **PASS** |
| 3 | Syscall filtering | seccomp BPF allowlist | `Seccomp: 2` (FILTER); `socket()→-1 EACCES`, `ptrace→EPERM`, `bpf→EPERM`, `keyctl→EPERM`, `mount→EPERM` | **PASS** |
| 4 | Mandatory access control | Landlock ABI 2, write-confinement to `/workspace` | write to `/usr` → `EROFS`; write to `/tmp` (tmpfs, writable) → denied by Landlock | **PASS** |
| 5 | cgroups v2 enforcement | *requested* | `mkdir /sys/fs/cgroup/user/...` → `EPERM`; private cgroup2 mount → `EPERM` | **NOT VERIFIED** |
| 6 | Per-job PID limits | `RLIMIT_NPROC` | `RLIMIT_NPROC=(12,12)`; bounded fork probe stops at 10 | **PASS** |
| 7 | Per-job memory limits | `RLIMIT_AS` | 2 GB allocation → `MemoryError`; `RLIMIT_AS` reads back as configured | **PASS** |
| 8 | CPU quotas | `RLIMIT_CPU` (+ wall-clock timeout) | `RLIMIT_CPU` reads back as configured; busy loop is cut off | **PASS (per-process)** |
| 9 | Max execution duration | wall-clock timeout in `run_isolated` | `timed_out=True` at the configured 5 s | **PASS** |
| 10 | Max concurrent workloads | `CapacityGovernor` (`BoundedSemaphore`) | 3rd concurrent request → `CapacityExceeded` → HTTP 429 | **PASS** |
| 11 | Global execution capacity | same governor + memory clamp | `stats()` exposes limits; memory clamped to `SKYLA_EXEC_MAX_MEMORY_MB` | **PASS** |
| 12 | Network disabled by default | network namespace + seccomp | `socket()` → `EACCES`; DNS → `gaierror`; host listener received no connection | **PASS** |
| 13 | Restricted filesystem | chroot into a synthetic rootfs | `/etc/passwd` → `FileNotFoundError`; host canary → `FileNotFoundError` | **PASS** |
| 14 | Read-only rootfs | `mount --bind -o ro` of the runtime tree | write to `/usr/bin/...` → `EROFS` | **PASS** |
| 15 | Ephemeral writable workspace | fresh temp dir per run, deleted after | `/workspace` writable; gone after completion | **PASS** |
| 16 | FD sanitation | `close_inherited_fds()` | `/proc/self/fd` = `{0,1,2,3}` only | **PASS** |
| 17 | Process-tree termination | PID-namespace kill + `/proc` sweep | double-forked grandchild: `killed=4`, **0 surviving orphans** | **PASS** |
| 18 | Cleanup on success *and* failure | `finally:` in `run_isolated` | verified for both paths; `terminate_and_verify()` returns a boolean that is asserted, not assumed | **PASS** |

### Deviation 1 — cgroups v2 is not available on this host

The requested design specified `cgroup.kill`-style enforcement and *aggregate* memory/PID limits. On this host the cgroup2 hierarchy is not delegable to an unprivileged user (`mkdir` → `EPERM`; mounting a private `cgroup2` → `EPERM`; `newuidmap` absent). Consequence:

* limits are **per-process** (`RLIMIT_*`), not per-cgroup aggregate;
* termination uses **PID-namespace kill**, which is verified to kill the whole tree;
* the API-layer `CapacityGovernor` provides the aggregate *concurrency* and *memory* ceiling that cgroups would otherwise provide.

Per the release rules this control is recorded **NOT VERIFIED**, not "equivalent". `containment_status()` reports `cgroup_v2: false` and the API response includes it, so a caller can see the limitation rather than trust a summary.

### Deviation 2 — the workload runs as namespace-root

Without `newuidmap(1)` only one uid can be mapped, so the process is root *inside its own user namespace*. `setuid(65534)` returns `EINVAL` and is tolerated. Namespace-root is not host root: it holds no authority over any object outside the namespace. What matters for containment — **zero capabilities** — is enforced and *verified from procfs*, and the supervisor exits 112 if verification fails (so the workload never starts with a partial drop). This is documented rather than hidden, and `getuid()==0` inside the namespace is expected.

---

## 4. Credential and secret isolation

The supervisor constructs a fixed environment:

```
PATH=/usr/bin:/bin  HOME=/tmp  LANG=C.UTF-8  PYTHONDONTWRITEBYTECODE=1
```

No `SKYLA_*` variable, no API token, no admin password, no DB path is inherited. The rootfs contains no Docker socket, no production DB file, no `.env`. Verified by
`test_host_environment_is_not_inherited`. The API process and the execution process are separate programs with independent resource limits, satisfying the requirement to build a *separate execution service*.

---

## 5. What is NOT claimed

* Aggregate per-cgroup limits (`memory.max`, `pids.max`, `cgroup.kill`) — **NOT VERIFIED** (see Deviation 1).
* gVisor / Firecracker / Kata — **not evaluated**: not installable in this environment. The requirement "if a secure runtime is unavailable, reject untrusted execution" is satisfied by the `disabled` provider.
* AppArmor as a second MAC layer — not used; Landlock is the enforced MAC mechanism.
* Resistance to a **kernel** LPE from inside the sandbox. The controls bound the *surface* (no caps, no raw sockets, no ptrace, no bpf, no mounts) but a kernel bug is out of scope for this layer. Recommended production posture: run this supervisor inside a VM or a gVisor-tier runtime.

## 6. Reproducing this document

```bash
python -m pytest tests/security/test_host_containment.py -q   # 20 tests, live kernel
python -m pytest tests/security/test_mutation_harness.py -q   # 13 mutations detected
```
