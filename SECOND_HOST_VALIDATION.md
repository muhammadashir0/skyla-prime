# Second-Host Validation — v0.2.3 Mission C

**Verdict: NOT VERIFIED. No second host could be obtained, and the reason is an environment boundary rather than an omission.**

A requirement that cannot be satisfied must be reported with its exact blocker and kept NOT VERIFIED. It must never be substituted with another process, container, or virtualenv on this host — that is explicitly not what this gate asks for.

---

## 1. What the gate requires

> Isolation verified on a genuinely separate Linux staging host: clean clone, native components built from source, full security suite executed, and the OS/kernel/CPU/memory/cgroup v2/delegated controllers/namespaces/Landlock ABI/seccomp/runtime/network/filesystem permissions/build dependencies documented.

## 2. Why it could not be done on this host

Every available mechanism for creating a separate host was checked. None exists.

| Mechanism | Result | Evidence |
|---|---|---|
| Dedicated hypervisor (`qemu-system-x86_64`, `qemu-kvm`) | **absent** | `command -v` → not found |
| MicroVM (`firecracker`, `cloud-hypervisor`) | **absent** | `command -v` → not found |
| Container runtime (`docker`, `podman`, `nerdctl`) | **absent** | `command -v` → not found |
| System container (`systemd-nspawn`, `lxc`) | **absent** | `command -v` → not found |
| Install any of the above | **blocked** | `apt-get update` → `Connection failed [IP: 151.101.130.132 80]` for `deb.debian.org`; `apt-get install qemu-system-x86` → `Unable to locate package` |

The sandbox permits egress to **github.com, codeload.github.com, api.github.com, registry.npmjs.org, pypi.org, files.pythonhosted.org** only. Debian package mirrors are unreachable, so no hypervisor or container runtime can be fetched and installed. There is no cloud API credential or provider CLI in the environment to provision a remote host.

**And even if one of those runtimes were installed, it would not satisfy the gate.** The requirement is explicit that another process, container, or virtualenv on the original host does not count. A container shares this kernel — kernel 6.1.158+, this cgroup hierarchy, this Landlock ABI, this seccomp behaviour. The gate exists precisely to find the failures that a shared kernel hides: a different kernel's Landlock ABI, a host without cgroup v2, a distro whose `unshare` lacks a flag.

## 3. What *was* verified on this host

The environment is recorded in full so a second host can be compared against it field by field. This is documentation, **not** a substitute for HOST-01.

| Property | Value |
|---|---|
| Hostname | `e2b.local` |
| OS | Debian GNU/Linux 12 (bookworm) |
| Kernel | **6.1.158+** |
| CPU | 2 vCPU |
| Memory | 3939 MB |
| cgroup | **v2** (`cgroup2fs` at `/sys/fs/cgroup`) |
| Available controllers | `cpuset cpu io memory hugetlb pids` |
| Delegated subtree control | `cpuset cpu io memory pids` |
| Namespaces | `unshare` util-linux 2.38.1; user/net/pid/mount/uts/ipc usable |
| Landlock | **ABI 2** (`landlock_create_ruleset(NULL,0,1) == 2`) |
| seccomp | `CONFIG_SECCOMP=y` |
| Landlock in kernel | `CONFIG_SECURITY_LANDLOCK=y` |
| Runtime | Python 3.11.2, uvicorn 0.54.0, FastAPI 0.165.0 |
| SQLite | 3.40.1 |
| git | 2.39.5 |
| Root filesystem type | `ext2/ext3` |
| Service uid | 1001 (unprivileged), NOPASSWD sudo for the operator |
| umask | 0022 |

### Host-specific blockers documented during this milestone

These are properties of *this* host that a second host would very likely not share, and they are the strongest argument for why HOST-01 still matters:

1. **Netfilter rulesets cannot be loaded.** `nft` and `iptables` binaries are absent, no binding is installable, and a direct `libnftables.so.1` netlink write returns `Could not process rule: No such file or directory` **as uid 0 with `CapEff 000001ffffffffff` and inside a freshly created network namespace**. On an ordinary Debian host this would succeed, and the perimeter could add a host-firewall layer that is not available here.
2. **The full test suite must run unprivileged.** As root, the supervisor refuses to execute untrusted jobs (`refusing to run: supervisor must not be setuid/root`) — 32 tests fail by design. A second host would confirm this is a property of the code, not of this uid.
3. **cgroup enforcement requires a one-time root bootstrap** (`scripts/cgroup_bootstrap.sh`). Without it 18 tests skip. `CGROUPS_VALIDATION.md` records results from a bootstrapped run; a clean second host would show whether the bootstrap is genuinely reproducible or depended on this host's pre-existing delegation.

## 4. What is needed to close this gate

1. A Linux host that is **not** this machine — a VM or physical box is acceptable; a container on this kernel is not.
2. A **clean clone** of commit `ad53336` (or later), with `pip install -e ".[dev]"` into a fresh virtualenv, so no artefact of this host's build leaks in.
3. Native components built **from source** on that host.
4. `scripts/cgroup_bootstrap.sh` as root, then the full suite **unprivileged**, plus the perimeter file **as root**.
5. The table in §3 filled in from that host, with every divergence explained.
6. Results attached here with the host's `uname -a`, `id`, and the suite's raw output.

## 5. Verdict

**HOST-01: NOT VERIFIED.** Not attempted-and-failed for lack of effort — attempted and blocked at the environment boundary, with the exact blocker recorded above. No substitute was used and none may be.

Release implication: this is one of the mandatory production controls. Production stays **NO-GO** on it until a genuinely separate host runs the suite.
