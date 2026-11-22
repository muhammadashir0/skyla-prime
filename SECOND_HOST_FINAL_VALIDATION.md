# Second-Host Final Validation — v0.2.4 Mission 3 (HOST-01)

**Verdict: NOT VERIFIED.**

A genuinely separate host could not be obtained in this environment. This document records that plainly, states exactly what is missing, and provides a runnable package so that the validation can be executed by anyone who has one.

---

## 1. What was attempted

The requirement is a **different machine**: not another process, not another venv, not another namespace on this one. Those are explicitly excluded because they share the kernel — and the properties under test (netfilter policy, cgroup delegation, namespace creation, kernel capability set) are all kernel properties, so a second container on the same kernel would validate nothing new.

Enumerated and found absent:

| Requirement | Result |
|---|---|
| `qemu-system-*` / KVM | absent; `/dev/kvm` does not exist |
| `docker` / `podman` / `lxc` / `incus` | absent |
| `systemd-nspawn` | absent |
| `firecracker` / `cloud-hypervisor` | absent |
| `multipass` | absent |
| `aws` / `gcloud` / `az` / `terraform` | absent |
| `apt-get` install path | binary not at `/usr/sbin/apt-get`; `apt-get update` produces no usable output |

No hypervisor, no container runtime, no cloud CLI, and no package installation path. A second host cannot be created from inside this sandbox.

**This was not retried.** The prior milestone recorded the same conclusion; repeating the probe would consume time without changing the answer.

## 2. What would satisfy HOST-01

One of:

- a second physical or virtual machine reachable over SSH;
- a cloud VM the operator can create (any provider);
- nested virtualisation with `/dev/kvm` exposed;
- a CI runner with a distinct kernel.

**Minimum specification:**

| Item | Requirement |
|---|---|
| OS | Linux, kernel ≥ 5.8 (≥ 6.1 recommended — landlock ABI ≥ 3) |
| Arch | x86_64 or aarch64 |
| CPU / RAM | 2 vCPU / 4 GB |
| Privileges | root or `CAP_SYS_ADMIN` + `CAP_NET_ADMIN` (namespace creation and iptables) |
| cgroup | v2 with `cpuset cpu io memory pids` delegated |
| Netfilter | `iptables` and `ip6tables` with `filter` table usable |
| Python | 3.11+ |
| Network | **different** topology from the current host, so the firewall exceptions are genuinely re-tested |

A second host on an identical network would still be worth running, but it would not test the parts most likely to be wrong.

## 3. The package

`scripts/skyla-host-qualify.sh` is the reproducible package. It does not require this repository's history, only a checkout.

```bash
# report capabilities; exits non-zero if a mandatory capability is MISSING
scripts/skyla-host-qualify.sh check

# run the full suite, account for every skip, write results
scripts/skyla-host-qualify.sh run
```

`check` reports: hostname, kernel, arch, distro, CPUs, memory, python version, presence of `ip`/`iptables`/`ip6tables`/`iptables-save`/`iptables-restore`/`unshare`/`setpriv`, **whether namespace creation actually works** (not merely whether the binary exists), cgroup version, available controllers, whether a delegated subtree exists, landlock ABI via syscall 444, and the count of global IPv6 addresses.

`run` executes the suite and writes to `qualification-results/`:
- the pytest output;
- a per-reason skip accounting, so "39 skipped" becomes "18 need cgroup delegation, 12 need CAP_SYS_ADMIN…";
- a machine-readable summary.

### Why the package exists rather than just instructions

The v0.2.3 gap was that second-host validation was a paragraph of prose. Prose cannot be run, so it cannot fail, so it cannot be trusted. A script that exits non-zero when a mandatory capability is missing will produce a different result on a host that lacks it — which is the property this release is missing.

## 4. What was proven *instead* — and what it does not prove

The package was executed **on this host** to confirm it works:

```
hostname            e2b.local
kernel              6.1.158+
distro              Debian GNU/Linux 12 (bookworm)
cpus                2
memory_mb           3939
python              3.11.2
ip / iptables / ip6tables / iptables-save / iptables-restore   PRESENT
unshare / setpriv                                             PRESENT
netns_usable                                                  PRESENT
netns_of_others                                               PRESENT
cgroup_version      cgroup2fs
cgroup_controllers  cpuset cpu io memory hugetlb pids
cgroup_subtree      cpuset cpu io memory pids
delegated_subtree_exists  no
landlock_abi        2
global_ipv6_addrs   0
```

This proves the **package runs and reports correctly**. It does **not** satisfy HOST-01: same host, same kernel, same network. Reading this output as second-host validation would be exactly the substitution the mission forbids.

Note `landlock_abi 2` — below the ABI 3 that full network-restriction semantics want. On this kernel the network boundary is enforced by namespace + netfilter + proxy, with landlock as a filesystem control only. A second host with ABI ≥ 3 would be a stronger platform, and that difference is only visible because `check` reports it.

## 5. Why this blocks release

The release rules require second-host validation. Individually defensible parts do not compose into a qualified system:

- the firewall exceptions (`10.201.0.2`, resolvers, metadata) are correct **for this network**. A different topology may have a different gateway, and the exception would be wrong — silently, because the policy would still deny everything else and still look healthy;
- cgroup delegation on this host is partial (`delegated_subtree_exists: no`), so 18 tests skip. Whether delegation works on a host where it *is* configured is untested;
- `landlock_abi 2` is a property of this kernel. The code's behaviour at ABI 3 is untested.

None of these can be settled by re-reading the code. That is what makes HOST-01 a genuine blocker rather than a formality.

## 6. Exact missing infrastructure requirement

> **One additional Linux host (VM or physical), kernel ≥ 5.8, root access, cgroup v2 with delegated controllers, working `iptables`/`ip6tables`, Python 3.11+, reachable over SSH, on a network topology distinct from `e2b.local`.**
>
> Absent: any hypervisor, container runtime, or cloud CLI in the build environment; `/dev/kvm` not exposed; `apt-get` not installable.

## 7. Instructions for the operator who has one

```bash
# on the second host
git clone <repo> && cd skyla-prime
python3.11 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

scripts/skyla-host-qualify.sh check        # must not print MISSING
scripts/skyla-host-qualify.sh run          # full suite
scripts/skyla-host-firewall.sh apply --safe-minutes 5
scripts/skyla-host-firewall.sh verify
sudo scripts/skyla-perimeter.sh start
# ... start the API inside the perimeter, run the security suite ...
sudo scripts/skyla-perimeter.sh stop
```

Record: hostname, kernel, the `check` output, suite totals, any newly skipped test with its reason, firewall `verify` output, and confirmation that the gateway exception matches **that** network.

## 8. Verdict

**NOT VERIFIED.** No second host was available. The package that performs the validation exists, runs, and reports honestly; the validation itself has not been performed, and no result in this document should be read as though it had been.
