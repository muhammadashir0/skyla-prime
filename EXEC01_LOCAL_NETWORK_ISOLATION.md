# EXEC-01 — Local Execution Network Isolation

**Status: CLOSED for network inheritance. Not closed as a full security boundary (correctly reported as weaker).**

- Defect: `skyla/execution/sandbox.py` ran untrusted code in the **host network namespace**
- Commit: `87511f6` → this release
- Host: `e2b.local`, kernel 6.1.158+, Debian 12

---

## 1. The defect, precisely

```python
# before (v0.2.4 and earlier)
proc = subprocess.run([sys.executable, str(script)], ..., env={...})
```

The docstring above that line read: *"Sandboxed Python execution — timeout + memory limits, no network."*

Three of those four claims were true. `RLIMIT_AS` and `RLIMIT_CPU` were applied; "no network" was
**enforced by nothing**. The child had the host's interfaces, the host's default route, and the host's
resolver.

This is worse than an unisolated sandbox, because it was a *documented* control. A reader auditing
`providers.py` would see `RestrictedProvider` honestly labelled `isolated = False`, but a reader auditing
`sandbox.py` would believe the network was handled. The two documents disagreed and the reassuring one was
fiction.

## 2. Every way local execution is initiated

Searched the whole tree for entry points before changing anything:

| Path | Reachable how | Network before |
|---|---|---|
| `RestrictedProvider.run` → `sandbox.run_python` | `SKYLA_EXECUTION_PROVIDER=restricted` + `SKYLA_ALLOW_UNSAFE_EXECUTION=1` | **host netns** ← the defect |
| `NamespaceProvider.run` → `workload.run_isolated` | default `auto`/`namespace` | `unshare -Urmpf -n`, correct |
| `ContainerProvider.run` → `docker run --network none` | `SKYLA_EXECUTION_PROVIDER=container` | `none`, correct (docker absent here) |
| `DisabledProvider.run` | fallback when nothing is available | refuses, correct |

Only the first row was defective. `get_execution_provider()` never falls back to it: on failure it returns
`DisabledProvider`, so the unsafe path requires two deliberate environment variables.

## 3. The fix

The workload now runs inside a private network namespace, and — more importantly — **the isolation is proven
before any workload code executes**.

```python
proc = subprocess.run([unshare, "-Urmpf", "-n", sys.executable, str(script)], ...)
```

Three design decisions carry the weight:

**a. The proof runs inside the namespace.** Checking connectivity from the parent would describe the parent.
The probe executes *in the sandbox*, so it reports what the workload will actually see.

**b. The positive control runs OUTSIDE, in the host namespace.** This was a real design error in my first
attempt: I put the control inside the sandbox, where every destination is blocked by design, so it could
never pass and every run reported "cannot verify". The control's job is to establish that this host has
ordinary reachability *at all* — only then does "blocked inside" mean isolation rather than a broken
environment.

**c. A verified failure is a refusal.** `IsolationUnavailable` → `refused: True`, `stdout` empty. There is no
fallback path. This is asserted directly: `test_an_unverifiable_boundary_refuses_execution` patches the probe
to fail and requires the workload *not* to run.

## 4. Measured results — all vectors

Each row is a test that runs the attack inside the sandbox.

| Vector | Attempt | Result |
|---|---|---|
| Public internet | `connect('1.1.1.1', 53)` | **blocked** (`OSError`) |
| Host loopback service | `connect('127.0.0.1', 8155)` — the egress proxy | **blocked** |
| Cloud metadata | `connect('169.254.169.254', 80)` | **blocked** |
| Perimeter gateway | `connect('10.201.0.2', 8155)` | **blocked** |
| Private network | `connect('10.0.0.1', 80)` | **blocked** |
| DNS resolution | `getaddrinfo('pypi.org', 443)` | **blocked** |
| Subprocess bypass | child process dials out | **blocked** |
| Raw socket | `socket.socket()` + `connect` | **blocked** |

```
isolation_status: {'verified': True, 'interfaces': 'eth0 lo sk999dg',
                   'has_default_route': False, 'reachable': []}
```

Note `interfaces` still lists `eth0` and `lo` — those names exist in the new namespace but carry no
addresses and no routes. Listing names is not evidence of connectivity; the route table and the deny-target
sweep are.

Route table inside the sandbox: **no default route**.

## 5. What the fix does NOT do

`RestrictedProvider.safe_for_untrusted` remains **`False`**, deliberately:

| Control | `namespace` provider | `restricted` provider |
|---|---|---|
| Network isolation | yes (`unshare -n`) | **yes (new)** |
| seccomp allowlist | yes | **no** |
| Landlock write confinement | yes | **no** |
| Capability drop | yes | **no** |
| PID-namespace termination | yes | **no** |
| cgroup enforcement | yes | **no** |

Reporting network confinement as full containment would repeat the original mistake in the opposite
direction. `status()` names the gap explicitly:

```json
{"provider": "restricted", "isolated": true, "safe_for_untrusted": false,
 "weaker_than": "namespace provider (no seccomp/Landlock/pid-kill)"}
```

## 6. Network-enabled execution

`network=True` is **refused** by both providers. No authorised egress path is wired to local execution, and
inventing one would require a destination policy that does not exist for this path. Deny by default.

## 7. Mutation evidence

Each mutation must be detected, and the detection must name the control:

| Mutation | Detected? | What caught it |
|---|---|---|
| Remove `-n` from the sandbox command | **yes** | `test_removing_the_local_namespace_is_detected` — the escape then succeeds |
| Report the host's connectivity | **yes** | `test_restoring_host_network_inheritance_is_detected` |
| Add a default route | **yes** | `test_adding_a_default_route_is_detected` — "default route" in stderr |
| Make `_assert_isolated` a no-op | **yes** | `test_disabling_the_isolation_assertion_is_detected` — the workload then RUNS |
| Claim `verified: True` on failure | **yes** | `test_reporting_isolation_after_failure_is_detected` |

The fourth is the important one: removing the assertion makes `print('RAN')` actually execute, which proves
the assertion is load-bearing rather than decorative.

## 8. A related defect found in the launcher

While preparing the cgroup work I found that `scripts/skyla-run.sh` decided whether it could place the
service into its cgroup with `[ -w "$SERVICE/cgroup.procs" ]`. **On cgroupfs the POSIX mode bits do not
reflect the kernel's write checks**: the test returned success, the write failed with `EPERM`, and the error
was discarded by `|| true`. The launcher silently launched unplaced, which is why 18 cgroup tests skipped
with "placement unavailable" even after a successful bootstrap.

Fixed to attempt the write and then **confirm it from `/proc/self/cgroup`**, with a loud warning when it
cannot. Same lesson as §3: verify the outcome, not the intention.

## 9. Reproduction

```bash
# isolation state
python -c "from skyla.execution import sandbox; print(sandbox.isolation_status())"

# the full vector sweep
python -m pytest tests/security/test_local_execution_isolation.py -q

# mutations
python -m pytest tests/security/test_execution_mutation_v025.py -q
```

## 10. Verdict

| Claim | Status |
|---|---|
| Local execution cannot inherit host networking | **PASS** — verified from inside the sandbox |
| Direct and indirect bypasses rejected | **PASS** — 8 vectors, including subprocess and DNS |
| No fallback to unrestricted execution | **PASS** — refusal asserted, no fallback path exists |
| Isolation proven before execution | **PASS** |
| Full containment equivalent to `namespace` provider | **FAIL, by design** — reported as `safe_for_untrusted: False` |

**EXEC-01 is closed for the network-inheritance defect.** The restricted provider remains a weaker boundary
than the namespace provider and says so.
