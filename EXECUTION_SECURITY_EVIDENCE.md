# Execution Security Evidence — v0.2.5

Consolidated evidence for the execution controls. Every claim names its implementation, its test, and the
command that reproduces it. Sections 1–9 were measured in this release; §10 lists what was not.

- Commit: v0.2.5 · Base: `87511f6`
- Host: `e2b.local`, Debian 12, kernel 6.1.158+, 2 vCPU, 3939 MB, cgroup v2, Landlock ABI 2, Python 3.11.2

---

## 1. Environment

| Property | Value |
|---|---|
| cgroup v2 | mounted, controllers `cpuset cpu io memory hugetlb pids` |
| `/sys/fs/cgroup/skyla` | delegated to `user` (uid 1001) |
| `cgroup.kill` | present |
| `memory.swap.max` | present |
| `unshare -Urmpf -n` | works unprivileged (user namespaces enabled) |
| netfilter extensions available | none beyond core (`LOG`, `limit`, `owner` all absent) |

## 2. Claim-by-claim evidence

| ID | Claim | Implementation | Test ID | Command | Expected | Actual | Mutation | Status |
|---|---|---|---|---|---|---|---|---|
| EXE-01 | Local execution cannot inherit host networking | `sandbox.py` `unshare -n` | `test_a_local_workload_cannot_reach_the_network[8 vectors]` | `pytest tests/security/test_local_execution_isolation.py` | all blocked | **all blocked** | remove `-n` → detected | **PASS** |
| EXE-02 | Sandbox has no default route | `sandbox.py` `_assert_isolated` | `test_the_sandbox_namespace_has_no_default_route` | same | no `00000000` route | none | add route → detected | **PASS** |
| EXE-03 | Isolation proven before execution | `sandbox.run_python` | `test_an_unverifiable_boundary_refuses_execution` | same | refuse, no stdout | refused | no-op guard → detected | **PASS** |
| EXE-04 | Positive control required | `_host_control_ok` | `test_a_failed_host_control_refuses_execution` | same | refuse | refused | — | **PASS** |
| EXE-05 | Reachable target ⇒ refusal | `_assert_isolated` | `test_a_reachable_target_refuses_execution` | same | refuse | refused | — | **PASS** |
| EXE-06 | No network-enabled local execution | `providers.py` | `test_the_local_provider_refuses_network_enabled_execution` | same | refuse | refused | — | **PASS** |
| EXE-07 | Restricted provider does not claim full containment | `providers.py` | `test_the_local_provider_does_not_claim_to_be_safe_for_untrusted_code` | same | `safe_for_untrusted False` | False | — | **PASS** |
| CG-01 | Per-job memory limit enforced | `cgroups.py` | `test_cgroups.py` (18) | see `CGROUP_ENFORCEMENT_REPORT.md` §6 | OOM at limit | peak **128.0 MB** of 128 MB | no-op write → detected | **PASS** |
| CG-02 | Per-job pids limit enforced | `cgroups.py` | same | same | stop at limit | stopped at **11** of 50 | — | **PASS** |
| CG-03 | Aggregate ceiling enforced | `cgroups.py` | same | same | under 1024 MB | **601 MB** | remove aggregate → detected | **PASS** |
| CG-04 | Failed write never yields `enabled: true` | `cgroups.py` | `test_failed_cgroup_write_refuses_execution` | `pytest tests/security/test_execution_mutation_v025.py` | raise | raised | yes | **PASS** |
| CG-05 | `cgroup.kill` empties the tree | `cgroups.py` | `test_cgroups.py` | see §6 there | `populated 0` | `populated 0` | no-op kill → detected | **PASS** |
| PT-01 | No descendant survives | `workload.py`, `cgroups.py` | survivor diff | `PROCESS_TREE_CONTAINMENT_REPORT.md` §2 | 0 remaining | **0 remaining** (25 killed) | no-op cleanup → detected | **PASS** |
| PT-02 | Double-fork contained | both | same | same | terminated | terminated | — | **PASS** |
| FW-01 | Firewall denies direct egress | `skyla-host-firewall.sh` | `verify` | `sudo scripts/skyla-host-firewall.sh verify` | blocked | blocked | — | **PASS** |
| FW-02 | Firewall rollback works | same | manual | `rollback` | restored | restored | — | **PASS** |
| FW-03 | Authorised egress reaches upstream | proxy + firewall | CONNECT probe | `HOST_FIREWALL_REGRESSION.md` §3 | 200 | **403 upstream unreachable** | — | **FAIL** |
| API-01 | API responsive under saturation | isolation of app from jobs | latency probe | §4 of `AGGREGATE_RESOURCE_TESTS.md` | p99 < 1 s | **p99 15 ms** | — | **PASS** |

## 3. Mutation summary

8 mutations, 8 detected. Each names the assertion that caught it — "some test failed" was not accepted as
evidence.

| # | Mutation | Caught by |
|---|---|---|
| 1 | Remove the network namespace | `test_removing_the_local_namespace_is_detected` |
| 2 | Restore host network inheritance | `test_restoring_host_network_inheritance_is_detected` |
| 3 | Add a default route | `test_adding_a_default_route_is_detected` |
| 4 | Disable the isolation assertion | `test_disabling_the_isolation_assertion_is_detected` |
| 5 | Report isolation after failed verification | `test_reporting_isolation_after_failure_is_detected` |
| 6 | Remove a per-job memory limit | `test_removing_a_per_job_memory_limit_is_detected` |
| 7 | Ignore failed cgroup writes | `test_failed_cgroup_write_refuses_execution` |
| 8 | Disable process-tree cleanup | `test_disabling_process_tree_cleanup_is_detected` |

## 4. Suite totals

| Run | Result |
|---|---|
| Unprivileged, no delegation | **385 passed / 42 skipped** |
| Delegated cgroup subtree, as the service user | **406 passed / 21 skipped** |
| Baseline (v0.2.4) | 360 passed / 39 skipped |

The 21 remaining skips:

| Count | Reason | Production significance |
|---|---|---|
| 9 | namespace entry needs `CAP_SYS_ADMIN` | **compensated** — the same properties were measured manually as root (perimeter `verify`: `isolated: True`) |
| 6 | API egress tests need `CAP_SYS_ADMIN` | **compensated** — capability sweep measured manually |
| 2 | real internet reachability now denied by the firewall | **expected** — a correct default-deny makes these impossible |
| 1 | absent-namespace path cannot be exercised while the namespace exists | not significant |
| 3 | cgroup mutations need placement (in the unprivileged run) | **not applicable** — they pass in the delegated run |

**No skip is counted as a pass.**

## 5. Defects found while producing this evidence

Recording these because a report that only lists successes is not evidence:

| # | Defect | Severity | Status |
|---|---|---|---|
| 1 | `skyla-run.sh` trusted POSIX `-w` on cgroupfs, which lies; the placement write failed and was discarded, so 18 cgroup tests skipped on a host where delegation worked | **high** (false NOT VERIFIED) | fixed |
| 2 | My own sandbox probe placed the positive control *inside* the sandbox, where it can never pass, so every run reported "unverifiable" | **medium** (would have hidden EXEC-01's fix) | fixed |
| 3 | The API latency probe measured `/health` (404) and reported excellent latency for a nonexistent endpoint | **medium** (meaningless measurement) | fixed |
| 4 | `FW-01`: the firewall blocks the proxy's own upstream | **high** (availability) | open, documented |
| 5 | `EXEC-01` residual: the restricted provider has no seccomp/Landlock/PID-kill | medium | open by design, reported |

Items 2 and 3 have the same root cause as the v0.2.4 perimeter defect: **a measurement that could not fail,
or measured the wrong thing, and reported success.** It is the recurring failure mode of this codebase and
the reason every claim here names a concrete command and an expected-when-wrong result.

## 6. Reproducing everything

```bash
# environment
sudo scripts/cgroup_bootstrap.sh
scripts/skyla-host-qualify.sh check

# unprivileged suite
python -m pytest -q                                     # 385 passed / 42 skipped

# delegated suite (as the service user, inside the subtree)
sudo sh -c 'printf %s $$ > /sys/fs/cgroup/skyla/service/cgroup.procs
            exec setpriv --reuid=user --regid=user --clear-groups \
              python -m pytest -q'                      # 406 passed / 21 skipped

# execution isolation + mutations
python -m pytest tests/security/test_local_execution_isolation.py -q
python -m pytest tests/security/test_execution_mutation_v025.py -q

# firewall
sudo scripts/skyla-host-firewall.sh verify
```

## 7. Verdict

| Acceptance criterion | Status |
|---|---|
| 1. Local execution cannot inherit host networking | **PASS** |
| 2. Direct and indirect network bypasses rejected | **PASS** |
| 3. Cgroup setup fails closed | **PASS** |
| 4. Aggregate resource limits enforced | **PASS** |
| 5. Per-job limits enforced | **PASS** |
| 6. No descendant processes survive termination | **PASS** |
| 7. API responsiveness maintained | **PASS** |
| 8. Firewall and gateway behaviour intact | **PARTIAL** — FW-01 |
| 9. Mutations demonstrate sensitivity | **PASS** — 8/8 |
| 10. Clean-environment reproduction | **NOT VERIFIED** — no second host |
