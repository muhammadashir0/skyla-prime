# SECOND HOST VALIDATION — v0.2.2 PRIME QUALIFICATION

**Mission 1.** Establish an independent Linux staging environment and reproduce the
execution-isolation suite there.

## Verdict

> ## **NOT VERIFIED**
>
> **No second host was available.** The programme ran on the same machine for every
> mission, so nothing in this release is evidence of portability. This document
> records the host profile in full, states exactly which validation was performed
> and which was not, and specifies what a second host must reproduce.

This is the single largest gap in the qualification. It is not downgraded to PASS
because the same suite was green twice: running the same tests on the same kernel
with the same LSM stack is repetition, not independence.

---

## 1. Host profile (measured, `2026-11-22`)

| Property | Value | How measured |
|---|---|---|
| Hostname | `e2b.local` | `hostname` |
| Machine ID | `7d67db294736411fab4adf8d1898c585` | `/etc/machine-id` |
| Distribution | Debian GNU/Linux 12 (bookworm) | `/etc/os-release` |
| Kernel | `6.1.158+ #1 SMP PREEMPT_DYNAMIC x86_64` | `uname -a` |
| CPU | 2 × Intel Xeon @ 2.60 GHz | `nproc`, `/proc/cpuinfo` |
| Memory | 3939 MB total, ~3648 MB available | `free -m` |
| Privilege | uid 1001 `user`; passwordless `sudo` to root | `id`, `sudo -n -l` |
| Seccomp (test process) | `Seccomp: 0` at rest; sandbox workloads get mode 2 | `/proc/self/status` |
| seccomp actions available | `kill_process kill_thread trap errno user_notif trace log allow` | `/proc/sys/kernel/seccomp/actions_avail` |

### Namespaces

All requested namespaces exist (`/proc/self/ns/`):
`user`, `pid`, `mnt`, `net`, `uts`, `ipc`, `cgroup`, `time`.

Behaviour differs by privilege and this matters for the v0.3.0 supervisor:

| Operation | As uid 1001 | As root |
|---|---|---|
| `unshare -m` | **EPERM** | OK |
| `unshare -Urmpf -n` (supervisor form) | OK (uses userns to gain mount rights) | OK |

### Landlock

| Property | Value |
|---|---|
| ABI | **2** |
| Enforcing LSM | `capability,landlock,selinux` (`/sys/kernel/security/lsm`) |
| Write-confinement | verified by `tests/security/test_host_containment.py` |

### cgroups v2

| Property | Value |
|---|---|
| Filesystem | `cgroup2fs` (magic `0x63677270`) |
| Root controllers | `cpuset cpu io memory hugetlb pids` |
| Root `subtree_control` | `cpuset cpu io memory pids` |
| Delegated subtree | `/sys/fs/cgroup/skyla` → owned by uid 1001 |
| Controllers delegated | `cpu memory pids` |
| Not delegated | `io cpuset` (not required by this release) |
| `cgroup.kill` | present (kernel ≥ 5.14) |

Delegation required one privileged step (`scripts/cgroup_bootstrap.sh`). Afterwards,
creating cgroups and writing `memory.max`, `pids.max`, `cpu.max`, `cgroup.kill` all
worked as uid 1001 with **no** runtime privilege.

### Container runtimes

| Runtime | Status |
|---|---|
| docker, podman, runc, crun, bwrap, runsc (gVisor), firecracker, systemd-nspawn, lxc | **all absent** |

Package installation is impossible: outbound HTTP (port 80) to `deb.debian.org`
fails, so `qemu-system-x86` and `cgroup-tools` cannot be fetched. HTTPS egress is
restricted by the sandbox to a small allowlist (pypi.org, github.com, npm),
confirmed by direct `curl` (see `EGRESS_PROXY_ASSESSMENT.md` §5).

**Consequence:** a true separate host could not be provisioned, and neither a VM
tier (Firecracker/QEMU) nor a user-space kernel (gVisor) could be installed. The
"prefer a host with rootless container support" instruction is unsatisfiable here.

### Filesystem permissions

```
drwxr-xr-x user:user  /sys/fs/cgroup/skyla
drwxr-xr-x user:user  /sys/fs/cgroup/skyla/service
```

Database files are created `0600` inside a `0700` directory by
`skyla/db.py::_secure_db_dir` (asserted by
`tests/security/test_db_integrity.py::test_database_file_is_created_0600`).

---

## 2. What was reproduced here

| Suite | Tests | Result |
|---|---|---|
| `tests/security/test_host_containment.py` | 20 | **PASS** (live kernel) |
| `tests/security/test_mutation_harness.py` | 13 | **PASS** (13/13 mutations detected) |
| `tests/security/test_cgroups.py` | 16 | **PASS** when run inside the delegated subtree |
| `tests/security/test_egress.py` | 22 | **PASS** |
| `tests/security/test_backup.py` | 13 | **PASS** |
| `tests/security/test_multiworker.py` | 9 | **PASS** |
| `tests/security/test_connector_reliability.py` | 16 | **PASS** |
| Full suite | 304 passed, 16 skipped | **PASS** |

The 16 skips are the cgroup tests when invoked outside the delegated subtree. A
skip is recorded as `NOT VERIFIED`, never as a pass — that distinction is load
bearing, because it is exactly the failure mode a second host would expose.

## 3. What a second host must reproduce

Run on a machine with a different kernel, LSM stack and container runtime:

1. `scripts/cgroup_bootstrap.sh` as root, then `scripts/skyla-run.sh`.
2. `pytest tests/security -q` — all modules, **no skips**.
3. Confirm `containment_status()` reports `landlock_abi > 0`, `seccomp: true`.
4. Confirm `cgroup_governor.status()` reports `cgroup_v2: true, placement: true`.
5. Confirm a memory bomb is OOM-killed by the kernel (`rc=-9`, `oom_kills>=1`) and
   a double-forked grandchild does not survive `cgroup.kill`.
6. Confirm the host's own egress policy, and that the proxy denies non-allowlisted
   hosts before any TCP connect.
7. Re-run `tests/security/test_mutation_harness.py` — the mutants are rebuilt from
   source, so this proves the controls are load-bearing on *that* kernel too.

**Nothing above has been done on a second host.** Status: **NOT VERIFIED**.

## 4. Why this blocks release

Release criterion 1 requires host isolation to be *independently verified*. A
single host cannot independently verify itself: kernel version, LSM ordering,
`/proc` layout and cgroup delegation semantics are all environment-specific, and
this release changed behaviour based on exactly those properties (e.g. the
supervisor relies on Landlock-ABI-2 semantics and on cgroup v2 ancestor-write
rules). Until a second host runs this suite with zero skips, the strongest
defensible statement is: *contained execution is verified on this host profile.*
