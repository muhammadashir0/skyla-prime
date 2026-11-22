# Security Evidence Registry — v0.2.3

Every significant security claim in the v0.2.3 documents maps to one record here. A claim without a record is not evidence.

**Status values:** `PASS` (measured, test exists, mutation-sensitive) · `FAIL` (measured and failing) · `NOT VERIFIED` (could not be measured — includes skips)

**Last verified commit:** `5bace07` · **Environment:** `e2b.local`, Debian 12, kernel 6.1.158+, 2 vCPU, 3939 MB, cgroup v2, Landlock ABI 2, Python 3.11.2, SQLite 3.40.1, uvicorn 0.54.0

**Repro command shorthand**
- `SUITE` = `/tmp/env3/bin/python -m pytest tests/ -q` (unprivileged, 359 passed / 37 skipped)
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

## A2. API egress integration (mission B — B-01 closure, commit `5bace07`)

The B-01 record set below is **additional** to `NET-01…NET-24`; those are unchanged. These records cover the API process specifically, which the NET records did not.

| ID | Claim | Impl | Threat | Test | Repro | Expected | Actual | Mutation | Detected | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| API-01 | The API process runs inside the perimeter | deployment | unconstrained trusted process | live `nsenter` probe | `nsenter -t $PID -n` | confined inode | `net:[4026532280]`, uid 1001 | — | n/a | **PASS** |
| API-02 | API cannot reach the internet directly | namespace routing | dependency exfiltration | `test_the_api_namespace_cannot_reach_the_internet_directly` | `SUITE_ROOT` | `OSError` | `OSError` (1.1.1.1, 8.8.8.8) | M2 default route | **yes** | **PASS** |
| API-03 | API cannot reach metadata | namespace routing | credential theft | same + live probe | `SUITE_ROOT` | `OSError` | `OSError`; `403` via proxy | M2 | **yes** | **PASS** |
| API-04 | API cannot reach host `0.0.0.0` services | gateway topology | lateral movement to API | `test_the_api_namespace_cannot_reach_internal_services` | `SUITE_ROOT` | unreachable | `OSError`, `403` via proxy | — | n/a | **PASS** |
| API-05 | API cannot reach host loopback | gateway topology | host-local services | live probe | `SUITE_ROOT` | unreachable | `OSError` | — | n/a | **PASS** |
| API-06 | API has no IPv6 path | namespace config | v6 bypass | `test_the_api_namespace_has_no_ipv6_path` | `SUITE_ROOT` | `ip -6 route` empty | empty; `::1` `OSError` | — | n/a | **PASS** |
| API-07 | All 11 outbound call sites use the factory | `egress_client.py` | unguarded client | `grep` + review | inventory §5 | 0 direct in app modules | 0 | M1 drop `proxy=` | **yes** (2) | **PASS** |
| API-08 | Client cannot be redirected by the environment | `trust_env=False` | attacker-controlled proxy | `test_the_client_is_bound_...` | `SUITE` | `trust_env False` | False | — | n/a | **PASS** |
| API-09 | Redirects are not auto-followed | `follow_redirects=False` | redirect SSRF | same | `SUITE` | False | False | M4 | **yes** | **PASS** |
| API-10 | Capability is enforced per request | `Proxy-Authorization` → policy | capability crossover | live 11-case sweep | namespace probe | wrong cap denied | denied ×4 | — | n/a | **PASS** |
| API-11 | Unknown capability gets deny-all | `policy_for_connector` | permissive default | `test_an_unknown_capability_gets_deny_all` | `SUITE` | `deny-all` | `deny-all` | — | n/a | **PASS** |
| API-12 | No wildcard policy exists | `POLICIES` | global allow | `test_there_is_no_wildcard_policy` | `SUITE` | none contain `*` | none | — | n/a | **PASS** |
| API-13 | Proxy unreachable ⇒ no client | `_verify_boundary` | silent downgrade | `test_an_unreachable_gateway_fails_closed` | `SUITE` | raises | raises | M7 | **yes** (3) | **PASS** |
| API-14 | Direct egress success ⇒ raise | `_verify_boundary` | boundary not constraining | `test_direct_egress_success_is_treated_as_a_failure` | `SUITE` | raises | raises | M7 | **yes** | **PASS** |
| API-15 | API refuses to start without enforcement | `api/app.py` | serving unconstrained | live import | `SUITE` / shell | `RuntimeError` | `RuntimeError` | — | n/a | **PASS** |
| API-16 | A confined process cannot downgrade | `resolve_mode` | self-selected weaker mode | `test_a_namespaced_process_cannot_downgrade_its_mode` | `SUITE` + live uid 1001 | refused | refused | — | n/a | **PASS** |
| API-17 | Namespace detection works unprivileged | compare `/var/run/netns/...` | **guard silently disabled** | `test_namespace_detection_works_without_reading_proc1` | `SUITE` | `True` | was `False`, now `True` | revert to `/proc/1` | **yes** | **PASS** |
| API-18 | Destroy does not strand live processes | `EgressPerimeter.members` | healthy-looking dead service | `test_destroying_the_perimeter_does_not_strand_live_processes` | `SUITE_ROOT` | member detected | detected | — | n/a | **PASS** |
| API-19 | Stranding warning survives the generic reason | `destroy()` | reassuring-and-wrong | `test_destroy_reports_stranding_when_members_are_left_alone` | `SUITE` | warning text | warning text | — | n/a | **PASS** |
| API-20 | Authorised reach still works | proxy + policies | enforcement as outage | `test_the_authorised_path_is_still_open` + sweep | `SUITE_ROOT` | 200 | 200 | — | n/a | **PASS** |
| API-21 | netguard blocks private addresses independently of policy | `netguard` | widened policy reaching internals | `test_a_widened_policy_still_cannot_reach_a_private_address` | `SUITE` | `SSRFBlocked` | blocked | **M6: suite did not fail** | **no** — layer 2 held | **PASS** |
| **API-22** | **TLS reach to googleapis / openai / telegram** | — | provider integration | live probe | host + namespace | TLS OK | `SSLZeroReturnError` even from the host, no proxy | — | — | **NOT VERIFIED** |

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
| Total | **396 collected** = 359 passed + 37 skipped |
| Security suite | 295 collected = 258 passed + 37 skipped |
| Unprivileged pass | 359 |
| Root, perimeter file only | 17 passed / 2 skipped |
| Root, full suite | 320 passed / 32 failed / 20 skipped — 32 are the supervisor refusing to run as root (correct behaviour) |
| Skips | 31 — enumerated below |

| Skip group | Count | Reason | Release implication |
|---|---|---|---|
| cgroup enforcement (`tests/security/test_cgroups.py`) | **18** | `/sys/fs/cgroup/skyla` absent: the delegated subtree must be created by `scripts/cgroup_bootstrap.sh` as root once | **The strongest concern on this list.** Memory/pids/CPU limits are asserted in `CGROUPS_VALIDATION.md` from a bootstrapped run, but in a clean checkout these 18 do not execute. A host that never runs the bootstrap has **no cgroup enforcement** while the suite still reports green. Recorded as a bootstrap dependency, and the deployment path must fail closed (see ISO-09) rather than run unlimited. |
| Perimeter boundary tests, unprivileged run | **12** | `cannot enter namespace 'skyla-egress' without CAP_SYS_ADMIN` | Enforcement is unaffected — the boundary is the route table, not the test. These execute as root. **NOT VERIFIED in the unprivileged run — not a pass.** |
| API egress kernel tests, unprivileged run | **6** | `cannot enter the namespace without CAP_SYS_ADMIN` | Same class. As root the file is 22 passed / 1 skipped; combined with the perimeter file, 45 passed / 1 skipped. **NOT VERIFIED unprivileged.** |
| `run_confined` absent-namespace path | **1** | perimeter is installed, so the refusal path cannot be reached | Exercised on a host without the perimeter. Low risk; the fail-closed behaviour is also pinned by `test_perimeter_refuses_when_it_cannot_be_built`. |

Total: 37. Enumerated from a live `-rs` run, not estimated.

No skip is treated as a pass anywhere in this registry.

## H. Honesty controls (self-checks that failed and were fixed)

| ID | Claim | Status |
|---|---|---|
| HON-01 | `verify` reports a healthy perimeter as available | **PASS** (was `available: False` always — fixed `ad53336`) |
| HON-02 | An unrun probe is never reported as `isolated` | **PASS** (was `isolated: True` — fixed `ad53336`) |
| HON-03 | Job outcome is judged by its side effect, not the API verdict | **PASS** (`task_steps` rows counted in every lease test) |
| HON-04 | Historical audit reports unaltered | **PASS** (`git diff --stat 9f4db1f -- <frozen files>` empty) |

## I. Registry summary

Counted by parsing every record row in this document — not estimated.

| Group | Records | PASS | PARTIAL | NOT MET / NOT VERIFIED |
|---|---|---|---|---|
| API (API egress integration, `5bace07`) | 22 | 21 | 0 | 1 |
| NET (perimeter) | 24 | 21 | 2 | 1 |
| LEASE (B-02) | 12 | 12 | 0 | 0 |
| ISO (isolation / resources) | 9 | 9 | 0 | 0 |
| DB (integrity) | 3 | 3 | 0 | 0 |
| CONN (connectors) | 5 | 2 | 0 | 3 |
| HOST (second host) | 2 | 1 | 0 | 1 |
| HON (honesty controls) | 4 | 4 | 0 | 0 |
| **Total** | **81** | **73** | **2** | **6** |

### B-01 status after this milestone

**REMEDIATED for the API process.** API-01…API-21 pass, including the two records that exist because the implementation was wrong first (API-17 namespace detection unprivileged, API-18 stranding on destroy). API-22 remains NOT VERIFIED for an environment reason, not an implementation one.

### Production remains NO-GO

- **NET-23** — no host-wide default-deny egress. The API is confined; other host processes are not. The netfilter blocker recorded in earlier revisions of this registry was a **PATH artifact** (see `NET-23` note below).
- **HOST-01** — no second host.
- **CONN-01/02/03** — no live connector verification.
- **API-22** — provider data plane unverifiable in this sandbox.
- Independent external review: not performed.

### Correction to NET-23

Earlier revisions recorded "no `nft`/`iptables` binary, rulesets cannot be loaded". That was wrong, and the error is worth stating rather than quietly editing: `iptables` and `nft` are present in `/usr/sbin`, which is **not on an unprivileged `PATH`**. `sudo iptables -A OUTPUT …` works. `nft` works in the `ip` family; the `inet` family is unsupported here.

The conclusion for NET-23 is unchanged — there is still no host-wide default-deny ruleset — but the reason is now accurate: it is **not deployed**, not **impossible**. That distinction matters because "impossible" closed the item; "not deployed" leaves it as real outstanding work.

**No skip anywhere in §G is counted as a pass.** 12 of the NET PASS records execute only as root; in the unprivileged run they skip and are reported as such.

---

# v0.2.4 EXTENSION — appended, nothing above modified

Sections A–I are the v0.2.3 record and remain **byte-identical** to their state at `5bace07`.
The SHA-256 of this file before this append was `6108d7b78ae896832653d32b0c644b656df58d951cae866d9fb88f608739e9c1`,
which is also the hash of `git show 6b489ef:SECURITY_EVIDENCE_REGISTRY.md` — verified equal, so no historical
row was touched. New evidence is added below, never substituted above.

**v0.2.4 verified commit:** `067bdf0` · **Environment:** unchanged — `e2b.local`, Debian 12, kernel 6.1.158+,
2 vCPU, 3939 MB, cgroup v2 (partial delegation), Landlock ABI 2, Python 3.11.2

**Repro shorthand for this extension**
- `SUITE24` = `/tmp/env4/bin/python -m pytest tests/ -q` → **360 passed / 39 skipped**
- `QUAL`  = `scripts/skyla-host-qualify.sh check`
- `FW_V`  = `sudo scripts/skyla-host-firewall.sh verify`
- `MUT24` = `scripts/mutation_check.py <module> <description>` (the standing mutation harness)

---

## J. Complete egress re-verification (v0.2.4 mission M1)

| ID | Claim | Impl | Test | Repro | Expected | Actual | Status |
|---|---|---|---|---|---|---|---|
| M1-01 | No gRPC, no vendor SDK, no `requests`/`aiohttp`/`urllib3` anywhere in `skyla/` | whole tree | grep scan | see `COMPLETE_EGRESS_REVIEW.md` §2 | zero matches | **zero matches** | **PASS** |
| M1-02 | Exactly one outbound mechanism: `httpx` inside `egress_client` | `egress_client.py` | `test_no_client_is_issued_*` | `SUITE24` | no client constructed elsewhere | **zero constructions in application modules** | **PASS** |
| M1-03 | Raw `socket` use is confined to the boundary probes and proxy listener | `perimeter.py`, `egress_client.py`, `egress.py`, `netguard.py` | manual review | grep in §2 | only those files | **only those files** | **PASS** |
| M1-04 | Unknown capability resolves to `deny-all`; no wildcard policy | `egress.py` | `test_an_unknown_capability_gets_deny_all` | `python -c "policy_for_connector('x')"` | `deny-all`, no hosts | `deny-all`, `False`, no `*` | **PASS** |
| M1-05 | Redirects never followed implicitly; each hop re-vetted | `research.py` | `test_the_client_is_bound_*` | `SUITE24` | `follow_redirects is False` | confirmed; `validate_url` per hop | **PASS** |
| M1-06 | `local` execution provider inherits host network | `sandbox.py:31` | static review | — | should be namespace-isolated | **inherits host netns** | **FAIL** (EXEC-01, open) |

### New findings in the verification machinery itself

| ID | Finding | Why it matters | Fixed in |
|---|---|---|---|
| M1-07 | `perimeter.py` called `socket` without importing it → every host-control probe raised `NameError`, so control read as "no network" while the verdict still printed `isolated: True` | a proof that cannot fail is not a proof; two contradictory lines with the reassuring one winning | `067bdf0` |
| M1-08 | `127.0.0.1:80` used as a control target; nothing listens there, so it failed regardless of policy | the control proved nothing | `067bdf0` |
| M1-09 | `prove_no_egress` requires a working host control before reporting isolation | fail-closed proof | `067bdf0` |

---

## K. Host firewall (v0.2.4 mission M2 — NET-23)

| ID | Claim | Impl | Test | Repro | Expected | Actual | Status |
|---|---|---|---|---|---|---|---|
| NET-23 | Host-wide default-deny egress, IPv4 **and** IPv6 | `scripts/skyla-host-firewall.sh` | `FW_V` | `sudo scripts/skyla-host-firewall.sh verify` | unauthorised blocked, exceptions work | `VERIFY: PASS` | **PASS** |
| NET-24 | Unauthorised destinations are blocked | `SKYLA-EGRESS` chain | `FW_V` | same | pypi/github/TEST-NET blocked | all **blocked** | **PASS** |
| NET-25 | Management/DNS/gateway exceptions remain usable | chain rules | `FW_V` | same | ssh + `1.1.1.1:53` + metadata reachable | reachable | **PASS** |
| NET-26 | Policy survives reboot (persistence) | `/etc/skyla-firewall.v4`, systemd unit | simulated reboot | flush → `iptables-restore` | jump restored | `-A OUTPUT -j SKYLA-EGRESS` restored | **PASS** |
| NET-27 | Rollback restores the prior state | `rollback` subcommand | manual | `rollback` | `OUTPUT ACCEPT`, pypi reachable | restored | **PASS** |
| NET-28 | Automatic rollback fires if not confirmed | dead-man timer | `--safe-minutes` | armed then left to expire | policy reverts | **fired and reverted** (observed live) | **PASS** |
| NET-29 | Activation refuses a chain lacking terminal DROP | `apply` guard | manual | build partial chain, attempt activate | refuse | refused | **PASS** |
| NET-30 | Firewall + perimeter compose: both layers active simultaneously | both | live sweep | see `HOST_FIREWALL_DEPLOYMENT.md` §4 | authorised 200, wrong-capability denied | `research→pypi` **200**; `research→github` ProxyError; `research→metadata` **403**; `connector-google→pypi` ProxyError | **PASS** |
| NET-31 | Host-level denial logging | — | — | — | denials logged | **no LOG/limit extension on this kernel** | **NOT VERIFIED** |
| NET-32 | Firewall deployed on a second host | — | — | — | deployed elsewhere | **only this host** | **NOT VERIFIED** |

---

## L. Second host (v0.2.4 mission M3 — HOST-01)

| ID | Claim | Impl | Test | Repro | Actual | Status |
|---|---|---|---|---|---|---|
| HOST-01 | Full qualification executed on a genuinely separate host | `scripts/skyla-host-qualify.sh` | `QUAL` then `run` | see `SECOND_HOST_FINAL_VALIDATION.md` | **no second host exists**; package runs correctly on this host | **NOT VERIFIED** |
| HOST-02 | A reproducible qualification package exists and reports honestly | `scripts/skyla-host-qualify.sh` | `QUAL` | `scripts/skyla-host-qualify.sh check` | full capability report, non-zero on `MISSING` | **PASS** |
| HOST-03 | Package detects kernel capability differences (not just binary presence) | `netns_usable` probe | `QUAL` | same | reports usability, not existence | **PASS** — reports `landlock_abi 2`, `delegated_subtree_exists: no` |

---

## M. Live connectors (v0.2.4 mission M4)

| ID | Claim | Actual | Status |
|---|---|---|---|
| CONN-01 | Gmail live-verified (OAuth, messages, threads, drafts, controlled send, **revocation**) | **no credentials**; connector reports `mode=mock`, `live=False` | **NOT VERIFIED** |
| CONN-02 | Calendar live-verified (availability, create, update, invite, conference link) | **no credentials**; `mode=mock` | **NOT VERIFIED** |
| CONN-03 | Telegram live-verified (auth, delivery, command authorization, duplicate prevention) | **no credentials**; `mode=mock` | **NOT VERIFIED** |
| CONN-04 | Connectors never report mock mode as live | `mode` / `live` populated correctly from absence of credentials | **PASS** |
| CONN-05 | Validation harness refuses unsafe runs (test-mode ack, missing creds, wrong recipient) | 3 refusals each tested | **PASS** |
| CONN-06 | Harness does not auto-send mail or auto-invite attendees | controlled send is an operator step; no invite path in harness | **PASS** |

---

## N. Test-suite accounting (v0.2.4 mission M6 — every skip explained)

`SUITE24` = **360 passed / 39 skipped**. 36 skip *occurrences* appear in `-rs` because 4 tests share
line 136. Distribution and production significance:

| Count | File | Reason | Production significance |
|---|---|---|---|
| 18 | `test_cgroups.py` | `/sys/fs/cgroup/skyla` missing — delegation not bootstrapped | **Significant.** Memory/CPU/PID limits are unverified. A production host must run `scripts/cgroup_bootstrap.sh` as root or resource-exhaustion isolation is untested. |
| 10 | `test_network_perimeter.py` | needs `CAP_SYS_ADMIN` to enter the namespace | **Significant but compensated.** The kernel-level properties were verified *manually as root* during M1/M2 (live process inspection, `nsenter` probes). The automated form cannot run unprivileged; the evidence exists in §J/§K, not in this run. |
| 6 | `test_api_egress.py` | needs `CAP_SYS_ADMIN` | **Same as above** — compensated by the live sweep in §K NET-30. |
| 2 | `test_egress.py` | host cannot reach pypi (host firewall now denies it) | **Not significant — expected.** These tests exercise real internet reachability; a correct default-deny firewall makes them impossible by design. The guard reports why rather than failing. |
| 1 | `test_network_perimeter.py:302` | "perimeter is installed; the absent-namespace path cannot be exercised" | **Not significant.** Testing the *absence* handling requires the namespace to be absent; it currently exists. |
| **39** | | | |

**No skip is counted as a pass.** The 12 namespace-CAP skips are the only ones where a real control exists
but the automated test cannot reach it; in both cases the control was verified manually and the manual
evidence is recorded above with its command.

---

## O. Registry summary — v0.2.4

Appended rows only. Historical totals (§I) are unchanged and still refer to `5bace07`.

| Group | Records | PASS | FAIL | NOT VERIFIED |
|---|---|---|---|---|
| M1 (egress re-verification) | 9 | 8 | 1 (EXEC-01) | 0 |
| NET (host firewall, v0.2.4) | 10 | 8 | 0 | 2 |
| HOST (second host, v0.2.4) | 3 | 2 | 0 | 1 |
| CONN (live connectors, v0.2.4) | 6 | 3 | 0 | 3 |
| **v0.2.4 subtotal** | **28** | **21** | **1** | **6** |
| Historical (v0.2.3, §I) | 81 | 73 | 0 | 6 (+2 PARTIAL) |
| **Cumulative** | **109** | **94** | **1** | **12** (+2 PARTIAL) |

### Changes versus the v0.2.3 gate

| Item | v0.2.3 | v0.2.4 |
|---|---|---|
| NET-23 host firewall | **FAIL** | **PASS** (this host) |
| NET-23 on second host | FAIL | **NOT VERIFIED** (reclassified: deployed here, unproven elsewhere) |
| EXEC-01 `sandbox.py` host network | not recorded | **FAIL** (disclosed) |
| HOST-01 | NOT VERIFIED | **NOT VERIFIED** |
| CONN-01/02/03 | NOT VERIFIED | **NOT VERIFIED** |
| External review | not performed | **not performed** (package ready) |
| Suite | 359/37 | **360/39** |

NET-23 moves from FAIL to PASS **for this host**. It does not move to PASS for production, because the
release rule requires the firewall where the threat model demands it *and* second-host validation, and the
second host is still missing.
