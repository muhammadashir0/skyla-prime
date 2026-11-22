# B-01 Remediation Report

**Finding:** B-01 — no enforcement forces egress through the proxy (High)
**Status:** REMEDIATED for the execution workload; PARTIAL for the trusted API process
**Commits:** `5201853`, `ad53336`, and the proxy-bind commit
**Date:** 2026-11-22 · host `e2b.local` · kernel 6.1.158+

---

## 1. The finding, as written

From `EGRESS_PROXY_ASSESSMENT.md` (v0.2.2, frozen and unaltered):

> nothing forces traffic through the proxy at the host firewall level, because no firewall tooling is available on this host (`iptables`, `nft` absent; apt blocked)… recorded as finding **B-01 (High)**, not as 'not verified' — the control is *absent*

> A process that ignores `HTTPS_PROXY` and dials directly is not stopped by this layer… this is **FAIL**, not an untested control.

The identifier says "missing host firewall". That description was **not** taken as the specification. Per the standing instruction, the finding was reproduced and the affected paths mapped before any fix was designed.

## 2. Reproduction — which processes were actually exposed

**Step 1: probe the untrusted-execution path.** A probe was run inside a real workload through the platform's own `NamespaceProvider`.

| probe from inside a real workload | result | meaning |
|---|---|---|
| `tcp 1.1.1.1:53` | `PermissionError` | seccomp denies `socket()` |
| DNS `pypi.org` | `gaierror` | no resolver, no socket |
| `169.254.169.254:80` | `PermissionError` | denied at syscall |
| `127.0.0.1:<any>` | `PermissionError` | denied at syscall |
| `socket(AF_INET)` | `PermissionError` | the syscall itself is filtered |
| `/proc/net/dev` | **no interfaces** | `unshare -n` gave it no network |

**Conclusion: B-01 does not apply to the untrusted-execution path.** `workload.py:222` already runs `unshare -Urmpf -n`, and the seccomp filter denies the socket syscall outright. The v0.2.2 documentation was accurate about this and the finding never concerned it.

**Step 2: check the trusted API process.** `grep -c "egress\|proxy" skyla/api/app.py` → **`0`**. The default-deny proxy in `skyla/egress.py` is not referenced by the API at all. It starts only when `SKYLA_EGRESS_ENABLED=1` is set by an operator. So the process holding credentials, database access and every outbound connector call runs **entirely unconstrained**.

**Step 3: prove the exposure.** A listener on the host bound `0.0.0.0:8200` (substituting for the API) was reachable from a naive namespace that had a route to the host. This is what the fix had to prevent.

**Root cause:** enforcement was placed in a *library call* (`netguard`/`egress`) that a caller may skip, rather than in a *kernel boundary* a caller cannot skip.

## 3. Affected paths

| Path | Exposure | Action |
|---|---|---|
| `skyla/execution/workload.py` untrusted jobs | none (`unshare -n` + seccomp) | unchanged; verified only |
| API process outbound (`research.fetch_url`, connectors, dependencies) | **fully exposed** | perimeter built; wiring pending (§7b of the assessment) |
| `skyla/egress.py` proxy | a chokepoint, not a boundary | made bind-address-correct for the perimeter |
| Any library opening a socket inside the API | **fully exposed** | the same; this is the reason a library-level fix is insufficient |

**Adjacent endpoints found while mapping.** Every one of these is reachable from an unconfined API process and was previously guarded only by convention: the cloud metadata service (`169.254.169.254`, both AWS and GCP shapes), every `0.0.0.0`-bound port on the host including the API itself and the dashboard, and the host's own loopback services.

## 4. The fix

A two-namespace OS boundary, in `skyla/perimeter.py` + `scripts/skyla-perimeter.sh`.

```
workload netns (skyla-egress, 10.200.0.2)
   └── /30 veth to the gateway; host route to 10.200.0.1; NO default route; no IPv6
gateway netns (skyla-egress-gw, 10.200.0.1 / 10.201.0.2)
   ├── DNAT tcp:8155 -> host proxy, MASQUERADE return path
   ├── FORWARD: tcp:8155 + ESTABLISHED,RELATED, then DROP
   └── default route (so the proxy can reach upstream)
host (10.201.0.1)
   └── egress proxy bound to 10.201.0.1:8155 only
```

Design decisions worth recording:

- **The boundary is the route table, not a filter.** With no default route there is no next hop; the packet dies at `ENETUNREACH` regardless of what any application does. A firewall rule can be misconfigured; a missing route cannot.
- **The gateway namespace exists because of a measurement** (§3 of the assessment): a single veth to the host leaked every `0.0.0.0`-bound host service, including the API. The gateway's peer contains one port and nothing else.
- **The proxy may not bind `0.0.0.0`.** `proxy_from_env()` now raises `EgressDenied` for that, because an all-interfaces proxy is an open relay for every process on the host — the finding itself, reintroduced. It binds the gateway's host-side address instead.
- **Interface names are capped at 15 characters**; `skyla-egress-wlp` was rejected by the kernel. Names are derived as `sk{tag}w/wp/g/gp`.

### Two defects found in my own fix, by using it

Recorded because both failed in the reassuring direction:

1. `verify` rejected a **healthy** perimeter with "namespace was not created" — it keyed off an in-memory flag a fresh object never has.
2. `prove_no_egress` reported **`isolated: True`** for a caller that could not enter the namespace at all: it computed `leaked` from an error dict. A probe that never ran was reported as isolation.
3. `status.available` was never assigned on the success path, so a working perimeter was indistinguishable from a broken one.

All three are fixed (`ad53336`) and pinned by tests. **A control that reports success when it cannot measure is worse than one that reports nothing** — this is the same failure pattern v0.2.2 found in the sandbox's `isolated: false` bug.

## 5. Regression tests — 20, in `tests/security/test_network_perimeter.py`

| Test | Asserts |
|---|---|
| `test_workload_namespace_has_no_default_route` | no default route exists |
| `test_workload_namespace_has_no_ipv6_path` | `ip -6 route` empty |
| `test_workload_namespace_has_exactly_one_non_loopback_interface` | one peer, not many |
| `test_public_and_metadata_destinations_are_unreachable` (×4 params) | real connects fail inside; host control succeeds |
| `test_dns_does_not_resolve_inside_the_perimeter` | `gaierror` inside |
| `test_internal_services_are_unreachable_from_the_workload` | host `0.0.0.0` and loopback listeners unreachable |
| `test_workload_loopback_is_its_own_not_the_hosts` | `127.0.0.1` is not shared |
| `test_the_proxy_is_reachable_from_inside` | the authorised path survives |
| `test_only_the_proxy_port_is_reachable_on_the_gateway` | allowlisting is a port |
| `test_perimeter_refuses_when_it_cannot_be_built` | fail-closed without CAP_NET_ADMIN |
| `test_create_failure_is_reported_as_unavailable` | partial build ≠ available |
| `test_verify_marks_missing_namespace_unavailable` | absent ns ≠ success |
| `test_run_confined_requires_both_namespaces` | refuses the leaky topology |
| `test_an_unmeasured_probe_never_reports_isolated` | reporting bug regression |
| `test_verify_reports_available_true_for_a_healthy_namespace` | reporting bug regression |
| `test_verify_reports_available_false_with_a_reason_when_broken` | reasons are named |
| `test_proxy_refuses_to_bind_all_interfaces` | no open relay |
| `test_proxy_binds_the_configured_gateway_address` | binds where the workload dials |
| `test_proxy_defaults_to_loopback_when_no_perimeter_is_installed` | unchanged behaviour |

Every boundary test uses a **host control**: the same connection attempt is made unconfined and must succeed. Without that control, "blocked" could simply mean the sandbox has no network.

## 6. Mutation testing

| # | Mutation applied to the live system | Result | Caught? |
|---|---|---|---|
| 1 | `ip route add default via 10.200.0.1` in the workload ns | `test_workload_namespace_has_no_default_route` **FAILED** | **yes** |
| 2 | add a route to the host link | connect → `TimeoutError` (gateway DROP held) instead of `OSError` | layer 2 independently effective |
| 3 | `iptables -I FORWARD 1 -j ACCEPT` in the gateway | still `OSError` — routing layer held first | layer 1 independently effective |
| 4 | revert the three status-reporting fixes | the 2 reporting tests **FAILED** | **yes** |

Mutations 2 and 3 are the important pair: each layer stops the traffic **on its own**, so neither is decorative. Mutation 1 proves the primary claim is tested rather than assumed.

All mutations removed; clean state re-verified: `14 passed, 2 skipped` (as root), `335 passed, 31 skipped` (full suite, unprivileged).

## 7. What is not closed

| Requirement | Status | Blocker |
|---|---|---|
| Host-wide nftables/iptables default-deny | **NOT MET** | No `nft`/`iptables` binary; no installable binding; direct `libnftables.so.1` netlink write returns `Could not process rule: No such file or directory` as uid 0 with `CapEff 1ffffffffff` and inside a fresh netns. This is the environment's own boundary. Isolation does not depend on it. |
| API process confined end to end | **PARTIAL** | `run_confined()` is proven but `skyla/api/app.py` has no egress reference; the proxy starts only when explicitly enabled. The boundary exists; it is not yet the mandatory path for the trusted process. |

Neither is claimed as a pass. B-01's substance — *"nothing forces traffic through the proxy"* — is answered by a structural boundary for the process that was actually exposed by measurement, and the remaining work is wiring with no unknown.

## 8. Verdict

**B-01: REMEDIATED for the untrusted-execution path (which was already safe, now proven) and for workloads entering the perimeter. PARTIAL for the trusted API process.**

Not closed outright, because the process the finding is really about is not yet inside the boundary. The next commit wires it there; until then this report stays PARTIAL and production stays NO-GO on it.
