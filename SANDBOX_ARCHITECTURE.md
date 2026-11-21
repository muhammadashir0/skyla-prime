# SANDBOX ARCHITECTURE — SKYLA PRIME v0.2.0

**Status:** implemented and adversarially tested on this host.
**Scope:** Workstream 1 (genuine execution isolation).
**Verified provider:** `namespace` (Linux user/mount/PID/net namespaces + chroot).
**Last validation:** 2026-11-21, this repository, kernel `uname -r` on the dev host, unprivileged user.

---

## 1. Why the v0.1.0 sandbox was rejected

The v0.1.0 "sandbox" was a `subprocess` runner with `RLIMIT_AS`, `RLIMIT_CPU`, a timeout and a
stripped environment. The independent audit demonstrated that code running under it could:

| Attack | v0.1.0 result |
|---|---|
| Read host `/etc/hostname`, `/etc/passwd` | **allowed** |
| Write host filesystem outside the workspace | **allowed** |
| Open TCP connections to host services | **allowed** (reached the API on :8000) |
| Spawn arbitrary subprocesses | **allowed** |
| Exhaust memory / CPU | blocked (rlimits) |

`RLIMIT_AS` + `RLIMIT_CPU` are *resource* controls, not *isolation*. v0.1.0 was corrected to report
`isolated: false` and to say so in the UI. v0.2.0 replaces it with a real provider architecture.

## 2. Provider model

Execution is now behind an interface (`skyla/execution/providers.py`):

```
ExecutionProvider (ABC)
├── NamespaceProvider   namespace   isolated=True   safe_for_untrusted=True   ← default here
├── ContainerProvider   container   isolated=True   safe_for_untrusted=True   ← Docker/OCI, auto-disabled if absent
├── RestrictedProvider  restricted  isolated=False  safe_for_untrusted=False  ← dev-only, labelled unsafe
└── DisabledProvider    disabled    isolated=True   safe_for_untrusted=True   ← fail-closed, runs nothing
```

Selection order (`get_execution_provider()`), overridable with `SKYLA_EXECUTION_PROVIDER`:

1. If `SKYLA_EXECUTION_PROVIDER=disabled` → **DisabledProvider** (no code execution at all).
2. If explicitly `container` and a Docker daemon is reachable → **ContainerProvider**, else fall back and report why.
3. **NamespaceProvider** if `unshare` + `chroot` are usable unprivileged.
4. Otherwise **RestrictedProvider**, flagged `isolated: false`, `safe_for_untrusted: false`.

The provider never *claims* isolation it cannot demonstrate: `status()` reports
`provider`, `isolated`, `safe_for_untrusted`, `available`, and the API surfaces this object verbatim
(`/api/health`, `POST /api/execute/python`).

## 3. What NamespaceProvider actually enforces

Each execution creates a fresh ephemeral workspace under a temp dir and runs:

```
unshare --user --map-root-user --mount --pid --net --fork --mount-proc  →  chroot <minimal-rootfs>  →  python3 /workspace/script.py
```

| Control | Mechanism | Adversarial evidence |
|---|---|---|
| No host filesystem access | `chroot` into a minimal rootfs containing only `bin lib lib64 usr dev proc tmp workspace` | `open('/etc/hostname')` → `FileNotFoundError`; `os.listdir('/')` returns only the 10 sandbox dirs |
| Read-only `/etc` | tmpfs mounted with `-o ro` | `open('/etc/x','w')` → traceback (read-only fs) |
| Ephemeral workspace | fresh temp dir per run, bind-mounted at `/workspace`, deleted in `finally` | every run starts empty |
| Network disabled by default | new net namespace with no interfaces | `connect_ex(('127.0.0.1', 8000))` → **101 Network is unreachable**; host listener never accepts |
| Process isolation | new PID namespace + `--fork` | subprocesses cannot see or signal host processes |
| Privilege restriction | user namespace maps caller to root *inside* the namespace only; no capabilities on the host | `id` inside reports the mapped uid; host privileges unchanged |
| Dropped capabilities | user-namespace root, no host caps; `chroot` before execution | cannot mount host devices, cannot alter host netns |
| Memory limit | `RLIMIT_AS` applied in the child | 3 GB allocation → `MemoryError` |
| CPU / wall-clock limit | `RLIMIT_CPU` + hard wall-clock timeout | `while True: pass` → `Timed out after 30s`, process group killed |
| Process limit | `RLIMIT_NPROC` | fork storms capped |
| Output cap | stdout/stderr truncated to 8 KB | 50 KB print → ≤ 8 KB returned |
| No inherited secrets | child env is a fixed minimal set (`PATH`, `HOME`, `LANG`, `PYTHON*`, `SKYLA_SANDBOX`) | `[k for k in os.environ if 'TOKEN' or 'KEY']` → `[]` |
| Forced cleanup | process-group kill on timeout, `shutil.rmtree` in `finally` | no orphaned processes or dirs observed |

Tests: `tests/unit/test_execution_isolation.py` (14 tests, each attempting a real escape).

## 4. What is *not* claimed

These are honest limitations, not open findings. Each is a deliberate, documented boundary:

1. **Kernel-surface risk.** User namespaces share the host kernel. This is the same trust model as
   rootless containers, not a hardware boundary. A kernel privilege-escalation exploit could escape.
   For untrusted third-party code at scale, use **gVisor** or **Firecracker** — see §6.
2. **`/proc` inside the sandbox** is the sandbox's own procfs (`--mount-proc`), not the host's.
3. **No seccomp filter is applied by NamespaceProvider.** The provider relies on the namespace
   boundary. ContainerProvider inherits the daemon's seccomp profile (`docker` default). A bespoke
   seccomp allowlist is listed as planned work in §6 — it is **not** implemented, and no document or
   UI here claims otherwise.
4. **Sibling processes.** `RLIMIT_NPROC` limits the *user*, so contention with other processes of the
   same uid is possible.
5. **No GPU, no device passthrough, no persistent volumes.** By design.
6. **Data exfiltration to an approved network**, if `SKYLA_ALLOW_NETWORK` is enabled, removes the
   strongest channel. The flag exists for explicit, per-deployment opt-in only and is off by default.

## 5. Fail-closed behaviour

- If neither namespaces nor a container runtime are available, `RestrictedProvider` is selected and
  **every surface that reports isolation says `false`**, and the API response carries
  `warning: "Restricted provider is NOT a security boundary — development use only"`.
- With `SKYLA_EXECUTION_PROVIDER=disabled`, `run()` returns an error and executes nothing.
- The API never upgrades an `isolated: false` result to a success-shaped "sandboxed" claim.

## 6. Optional runtimes: evaluation

| Runtime | Evaluated | Verdict for this host |
|---|---|---|
| **Rootless containers** (Podman/Docker rootless) | `ContainerProvider` implemented, auto-detects the daemon | **NOT VERIFIED** — no Docker/Podman binary in the build environment. Code path is exercised only for its "unavailable → disable" branch. |
| **gVisor** (`runsc`) | Documented as the recommended upgrade for multi-tenant untrusted code | **NOT VERIFIED** — not installed; requires kernel/runtime setup and root. No claim made. |
| **Firecracker** | Documented as the strongest boundary (hardware virt) | **NOT VERIFIED** — requires `/dev/kvm`; unavailable here. No claim made. |
| **Namespace provider** | Implemented, adversarially tested | **VERIFIED on this host** (see §3). |

Blocker for the three unverified rows: the build environment has no container runtime, no
`/dev/kvm`, and no root — installing any of them is infrastructure provisioning that was not
authorised in this workstream.

## 7. Approved-network execution (configurable, off by default)

- Default: pod's own network namespace, no interfaces → all egress fails (`ENETUNREACH`).
- `SKYLA_ALLOW_NETWORK=1` opts a deployment into the host netns for a given provider instance.
  This is an **explicit** operator decision, logged at startup, and never a default.
- Even when enabled, no credentials are injected into the sandbox; connectors perform their own
  authenticated calls outside the sandbox (see `AUTHORIZATION_ARCHITECTURE.md` §7).

## 8. Reproducing the validation

```bash
python -m pytest tests/unit/test_execution_isolation.py -v
# manual probes
python -c "from skyla.execution.providers import get_execution_provider; print(get_execution_provider().status())"
```

Expected on this host: `{'provider': 'namespace', 'isolated': True, 'safe_for_untrusted': True, 'available': True}`.

## 9. Decision record

- **ADR-1.1** Pluggable providers over a single hardened subprocess — enables honest degradation and
  lets a deployment with Docker/gVisor upgrade without code changes.
- **ADR-1.2** Namespace provider as the default on this host, because it is the only runtime that
  could be *validated*, and an unvalidated isolation claim is worse than a documented limitation.
- **ADR-1.3** `RestrictedProvider` retained for developer convenience but hard-labelled unsafe and
  never selectable silently as "isolated".
- **ADR-1.4** Execution disabled by configuration rather than by patching, so a locked-down
  deployment needs no code change.
