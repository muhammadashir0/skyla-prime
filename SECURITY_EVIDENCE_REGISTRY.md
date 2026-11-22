# Security Evidence Registry — v0.2.3

Every significant security claim in the v0.2.3 documents maps to one record here. A claim without a record is not evidence.

**Status values:** `PASS` (measured, test exists, mutation-sensitive) · `FAIL` (measured and failing) · `NOT VERIFIED` (could not be measured — includes skips)

**Last verified commit:** `ad53336` · **Environment:** `e2b.local`, Debian 12, kernel 6.1.158+, 2 vCPU, 3939 MB, cgroup v2, Landlock ABI 2, Python 3.11.2, SQLite 3.40.1, uvicorn 0.54.0

**Repro command shorthand**
- `SUITE` = `/tmp/env3/bin/python -m pytest tests/ -q` (unprivileged, 341 passed / 31 skipped)
- `SUITE_ROOT` = `sudo -n /tmp/env3/bin/python -m pytest tests/security/test_network_perimeter.py -q` (root — **only the perimeter file**)

> **The full suite MUST run unprivileged.** As root, 32 unit/security tests fail by
> design: the supervisor refuses to execute untrusted jobs as root
> (`refusing to run: supervisor must not be setuid/root`). That refusal is a
> control, not a bug. Root is used solely to enter the network namespace, which
> requires `CAP_SYS_ADMIN`. Measured both ways:
> unprivileged **341 passed / 31 skipped**, root **320 passed / 32 failed / 20 skipped**
> (the 32 are all the supervisor refusal; the perimeter file alone is 17 passed / 2 skipped as root).
- `PERIM` = `sudo -n env PYTHON=/tmp/env3/bin/python scripts/skyla-perimeter.sh setup`
- `PERIM_V` = `sudo -n env PYTHON=/tmp/env3/bin/python scripts/skyla-perimeter.sh verify`

---

## A. Network perimeter (mission B — B-01)

| ID | Claim | Impl | Threat | Test | Repro | Expected | Actual | Mutation | Detected | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| NET-01 | Workload namespace has no default route | `perimeter.py:create` | undirected egress | `test_workload_namespace_has_no_default_route` | `SUITE_ROOT` | no `default` line | no `default` line | add default route | **yes** (1 fail) | **PASS** |
| NET-02 | No IPv6 path exists | `perimeter.py` sysctl | IPv6 bypass | `test_workload_namespace_has_no_ipv6_path` | `SUITE_ROOT` | `ip -6 route` empty | empty | — | n/a | **PASS** |
| NET-03 | Exactly one non-loopback interface | `perimeter.py:create` | extra peer | `test_..._exactly_one_non_loopback_interface` | `SUITE_ROOT` | `['lo','sk999dwp']` | same | — | n/a | **PASS** |
| NET-04 | Public + metadata destinations unreachable from inside | `perimeter.py` | SSRF/IMDS | `test_public_and_metadata_destinations_are_unreachable` ×4 | `SUITE_ROOT` | all fail | all `OSError` | add route | **yes** (Timeout instead of OSError) | **PASS** |
| NET-05 | Host control proves reachability unconfined | test design | false "blocked" | same test | `SUITE_ROOT` | `REACHED` on host | `REACHED` | — | n/a | **PASS** |
| NET-06 | DNS does not resolve inside | no resolver path | name-based egress | `test_dns_does_not_resolve_inside_the_perimeter` | `SUITE_ROOT` | `gaierror` | `gaierror` | — | n/a | **PASS** |
| NET-07 | Internal `0.0.0.0` and loopback services unreachable | gateway topology | lateral movement to API | `test_internal_services_are_unreachable_from_the_workload` | `SUITE_ROOT` | unreachable | `OSError` ×3 | single-veth topology | **yes** (was REACHED) | **PASS** |
| NET-08 | Workload loopback ≠ host loopback | netns | loopback confusion | `test_workload_loopback_is_its_own_not_the_hosts` | `SUITE_ROOT` | refused inside | `ConnectionRefusedError` | — | n/a | **PASS** |
| NET-09 | Proxy reachable from inside (allow path) | `egress.proxy_from_env` bind | outage | `test_the_proxy_is_reachable_from_inside` | `PERIM` + proxy | `REACHED` | `200 Established` | bind loopback | **yes** (was refused) | **PASS** |
| NET-10 | Only the proxy port is open on the gateway | gateway FORWARD | port confusion | `test_only_the_proxy_port_is_reachable_on_the_gateway` | `SUITE_ROOT` | other ports closed | closed | — | n/a | **PASS** |
| NET-11 | Allowlisted host permitted end to end | `egress.POLICIES['research']` | over-blocking | live probe | proxy + probe | 200 | **200** | — | n/a | **PASS** |
| NET-12 | Non-allowlisted host denied | same | open proxy | live probe | proxy + probe | 403 | **403** (github.com) | — | n/a | **PASS** |
| NET-13 | Metadata denied through the proxy too | `netguard` | IMDS via proxy | live probe | proxy + probe | 403 | **403** | — | n/a | **PASS** |
| NET-14 | Internal API denied through the proxy | policy | SSRF | live probe | proxy + probe | 403 | **403** (`10.201.0.1:8000`) | — | n/a | **PASS** |
| NET-15 | Proxy refuses `0.0.0.0` bind | `egress.proxy_from_env` | open relay | `test_proxy_refuses_to_bind_all_interfaces` | `SUITE` | `EgressDenied` | raised | — | n/a | **PASS** |
| NET-16 | Proxy binds the gateway address | same | unreachable proxy | `test_proxy_binds_the_configured_gateway_address` | `SUITE` | `10.201.0.1` | same | — | n/a | **PASS** |
| NET-17 | Fail-closed without CAP_NET_ADMIN | `perimeter.py` | silent unconfined run | `test_perimeter_refuses_when_it_cannot_be_built` | `SUITE` | `PerimeterUnavailable` | raised | — | n/a | **PASS** |
| NET-18 | Partial build ≠ available | `perimeter.py:create` | false assurance | `test_create_failure_is_reported_as_unavailable` | `SUITE` | `available False` | False | — | n/a | **PASS** |
| NET-19 | Unrun probe ≠ isolated | `perimeter.prove_no_egress` | **false assurance** | `test_an_unmeasured_probe_never_reports_isolated` | `SUITE` | `isolated False` | False | revert fix | **yes** | **PASS** |
| NET-20 | Healthy perimeter reports available | `perimeter.verify` | false negative | `test_verify_reports_available_true_...` | `SUITE` | `available True` | True | revert fix | **yes** | **PASS** |
| NET-21 | Broken perimeter names its problem | same | unactionable signal | `test_verify_reports_available_false_with_a_reason` | `SUITE` | reason mentions route | same | — | n/a | **PASS** |
| NET-22 | Perimeter refuses the leaky single-veth topology | `run_confined` | internal leak | `test_run_confined_requires_both_namespaces` | `SUITE` | raises | raised | — | n/a | **PASS** |
| **NET-23** | **Host-wide nftables/iptables default-deny** | **none** | **unconstrained host egress** | — | attempted | ruleset loads | `Could not process rule: No such file or directory` as uid 0, CapEff `1ffffffffff`, fresh netns | — | — | **NOT VERIFIED (blocked)** |
| **NET-24** | **API process OS-confined end to end** | **`perimeter.run_confined` (unused by API)** | **trusted-process egress** | — | `grep -c "egress\|proxy" skyla/api/app.py` = **0** | wired | **not wired** | — | — | **PARTIAL → FAIL as a mandatory control** |

## B. Cross-process execution lease (mission A — B-02)

| ID | Claim | Impl | Threat | Test | Repro | Expected | Actual | Mutation | Detected | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| LEASE-01 | Concurrent claims yield one execution | `db.lease_task` CAS | duplicate execution | `test_concurrent_claims_yield_one_execution` | `SUITE` | 1 acquired | 1 | — | n/a | **PASS** |
| LEASE-02 | Side effects occur once | `orchestrator._run_claimed` | duplicated writes | `test_execution_side_effects_occur_once` | `SUITE` | 2 step rows | 2 | original orchestrator | **yes** (4 fail) | **PASS** |
| LEASE-03 | `executing` not reclaimable | CAS `status='queued'` | re-entry | `test_an_executing_task_cannot_be_reacquired` | `SUITE` | held | held | CAS accepts `planning` | **yes** | **PASS** |
| LEASE-04 | `completed` not reclaimable | CAS | re-run | `test_a_completed_task_cannot_be_reacquired` | `SUITE` | terminal | terminal | release resets status | **yes** | **PASS** |
| LEASE-05 | `failed` not reclaimable | CAS | re-run | `test_a_failed_task_cannot_be_reacquired` | `SUITE` | terminal | terminal | — | n/a | **PASS** |
| LEASE-06 | Release does not reopen a task | `db.release_task` | sequential duplicate | `test_release_does_not_reopen_a_task` | `SUITE` | status intact | intact | reset to `queued` | **yes** | **PASS** |
| LEASE-07 | Lease records owner/pid/host/expiry | `task_leases` schema | unattributable holder | `test_lease_records_the_owner` | `SUITE` | populated | populated | — | n/a | **PASS** |
| LEASE-08 | Expired lease reaped to `interrupted` | `reap_expired_tasks` | stuck task | `test_expired_lease_is_reaped_to_interrupted` | `SUITE` | `interrupted` | same | — | n/a | **PASS** |
| LEASE-09 | Reaping does not auto-rerun | same | duplicate after crash | `test_reaping_does_not_rerun_the_task` | `SUITE` | no execution | none | — | n/a | **PASS** |
| LEASE-10 | `held` verdict performs no work | `orchestrator.run_task` | phantom success | `test_a_held_verdict_skips_execution` | `SUITE` | 0 steps | 0 | — | n/a | **PASS** |
| LEASE-11 | 30-run determinism | CAS | flake | reproducer | `/tmp/b02work/repro.py` | 2 rows × 30 | 2 rows × 30 | — | n/a | **PASS** |
| LEASE-12 | Live API 4-worker idempotency | `app.py:347` | multi-worker dup | 16 concurrent POSTs | port 8041 | executed 1, replayed 15 | same | — | n/a | **PASS** |

## C. Isolation and resource controls (pre-existing, re-verified)

| ID | Claim | Impl | Test / evidence | Actual | Status |
|---|---|---|---|---|---|
| ISO-01 | Untrusted jobs have no network | `workload.py:222` `unshare -n` | probe in real workload | no interfaces; `socket()` → `PermissionError` | **PASS** |
| ISO-02 | Untrusted jobs cannot read host secrets | seccomp + Landlock | `test_no_inherited_secrets` | pass | **PASS** |
| ISO-03 | Timeout enforced | supervisor | `test_timeout_enforced` | pass | **PASS** |
| ISO-04 | cgroup memory limit kills the job | cgroup v2 | 4×60 MB → `rc=-9`, `oom_kills=6`, peak 128 MB | as stated | **PASS** |
| ISO-05 | cgroup tree kill | `cgroup.kill` | harness | whole tree dies | **PASS** |
| ISO-06 | `pids.max` enforced | cgroup v2 | fork 7 at `pids.max=8` | as stated | **PASS** |
| ISO-07 | CPU throttled | `cpu.max=20000` | harness | throttled | **PASS** |
| ISO-08 | Aggregate capacity capped | supervisor | 4th job → `AggregateCapacityExceeded` | as stated | **PASS** |
| ISO-09 | Fail-closed on missing cgroup | `test_cgroup_failclosed` | 18/18 | pass | **PASS** |

## D. Data integrity (pre-existing, re-verified)

| ID | Claim | Test / evidence | Actual | Status |
|---|---|---|---|---|
| DB-01 | WAL checkpoint + integrity check | `wal_checkpoint(TRUNCATE)` | `integrity_check ok` | **PASS** |
| DB-02 | Backup/restore round trip | `WAL_BACKUP_RECOVERY_REPORT.md` | verified | **PASS** |
| DB-03 | Idempotency ledger dedupes identical requests | `app.py` | executed 1 / replayed 15 | **PASS** |

## E. Connectors (mission D)

| ID | Claim | Status | Reason |
|---|---|---|---|
| CONN-01 | Gmail actions live-verified | **NOT VERIFIED** | no authorized test account; **0** provider credential env vars present |
| CONN-02 | Calendar actions live-verified | **NOT VERIFIED** | same |
| CONN-03 | Telegram send live-verified | **NOT VERIFIED** | same |
| CONN-04 | Connector mock never reported as external action | **PASS** | `EXTERNAL_ACTION_INTEGRITY.md`; mock marked as such in code paths |
| CONN-05 | Provider TLS reachable (network prerequisite) | **PASS** | `www.googleapis.com:443`, `api.telegram.org:443` → TCP OK; DNS resolves |

`CONN-05` is a prerequisite check only. It proves the network would permit a live test; it proves **nothing** about provider behaviour, and no capability may be upgraded on its strength.

## F. Second-host reproducibility (mission C)

| ID | Claim | Status | Reason |
|---|---|---|---|
| HOST-01 | Full suite on a separate physical/virtual host | **NOT VERIFIED** | no hypervisor (`qemu`, `firecracker`, `cloud-hypervisor` absent), no container runtime (`docker`, `podman`, `lxc`, `systemd-nspawn`, `nerdctl` absent), and apt egress blocked (`deb.debian.org` unreachable). Only github/npm/pypi are reachable, so a second host cannot be provisioned. |
| HOST-02 | Environment recorded for the current host | **PASS** | see header + `SECOND_HOST_VALIDATION.md` |

## G. Test suite accounting (mission G)

| Metric | Value |
|---|---|
| Total | **372 collected** = 341 passed + 31 skipped |
| Security suite | 271 collected = 240 passed + 31 skipped |
| Unprivileged pass | 341 |
| Root, perimeter file only | 17 passed / 2 skipped |
| Root, full suite | 320 passed / 32 failed / 20 skipped — 32 are the supervisor refusing to run as root (correct behaviour) |
| Skips | 31 — enumerated below |

| Skip group | Count | Reason | Release implication |
|---|---|---|---|
| cgroup enforcement (`tests/security/test_cgroups.py`) | **18** | `/sys/fs/cgroup/skyla` absent: the delegated subtree must be created by `scripts/cgroup_bootstrap.sh` as root once | **The strongest concern on this list.** Memory/pids/CPU limits are asserted in `CGROUPS_VALIDATION.md` from a bootstrapped run, but in a clean checkout these 18 do not execute. A host that never runs the bootstrap has **no cgroup enforcement** while the suite still reports green. Recorded as a bootstrap dependency, and the deployment path must fail closed (see ISO-09) rather than run unlimited. |
| Perimeter boundary tests, unprivileged run | **12** | `cannot enter namespace 'skyla-egress' without CAP_SYS_ADMIN` | Enforcement is unaffected — the boundary is the route table, not the test. These execute as root (`SUITE_ROOT`: 17 passed / 2 skipped). **NOT VERIFIED in the unprivileged run — not a pass.** |
| `run_confined` absent-namespace path | **1** | perimeter is installed, so the refusal path cannot be reached | Exercised on a host without the perimeter. Low risk; the fail-closed behaviour is also pinned by `test_perimeter_refuses_when_it_cannot_be_built`. |

Total: 31. Enumerated from a live `-rs` run, not estimated.

No skip is treated as a pass anywhere in this registry.

## H. Honesty controls (self-checks that failed and were fixed)

| ID | Claim | Status |
|---|---|---|
| HON-01 | `verify` reports a healthy perimeter as available | **PASS** (was `available: False` always — fixed `ad53336`) |
| HON-02 | An unrun probe is never reported as `isolated` | **PASS** (was `isolated: True` — fixed `ad53336`) |
| HON-03 | Job outcome is judged by its side effect, not the API verdict | **PASS** (`task_steps` rows counted in every lease test) |
| HON-04 | Historical audit reports unaltered | **PASS** (`git diff --stat 9f4db1f -- <frozen files>` empty) |

## I. Registry summary

Counted by parsing every `NET-*`/`LEASE-*`/`ISO-*`/`DB-*`/`CONN-*`/`HOST-*`/`HON-*` row in this document — not estimated.

| Group | Records | PASS | PARTIAL | NOT MET / NOT VERIFIED |
|---|---|---|---|---|
| NET (perimeter) | 24 | 21 | 2 | 1 |
| LEASE (B-02) | 12 | 12 | 0 | 0 |
| ISO (isolation/resources) | 9 | 9 | 0 | 0 |
| DB (integrity) | 3 | 3 | 0 | 0 |
| CONN (connectors) | 5 | 2 | 0 | 3 |
| HOST (second host) | 2 | 1 | 0 | 1 |
| HON (honesty controls) | 4 | 4 | 0 | 0 |
| **Total** | **59** | **52** | **2** | **5** |

Production remains **NO-GO**. Three mandatory controls are not PASS:

- **NET-23** — no host-wide firewall (environment blocker, §A)
- **NET-24** — the trusted API process is not yet OS-confined (wiring pending, §A)
- **HOST-01** — no second host (blocked, §F)

Live connectors are NOT VERIFIED (§E: CONN-01/02/03), and independent external review has not taken place. **No skip anywhere in §G is counted as a pass.**

Note on NET: 21 PASS includes 12 boundary tests that execute only as root. In the unprivileged run they are skips, and they are reported as such in §G — the PASS verdict for those records rests on the root run, not on the CI default.
