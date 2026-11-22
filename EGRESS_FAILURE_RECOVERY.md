# Egress Failure and Recovery — v0.2.3 Mission 6

Every failure mode was induced on the live system. The governing rule: **the application must never silently revert to unrestricted networking.** In every case below it refused instead.

- Commit: `5bace07` · API running unprivileged (uid 1001) inside `skyla-egress`

---

## 1. Results

| # | Failure induced | How | Observed behaviour | Verdict |
|---|---|---|---|---|
| 1 | Egress proxy unavailable | `pkill -f "skyla-perimeter.sh proxy"` | `EgressUnavailable: egress gateway 10.200.0.1:8155 unreachable (ConnectionRefusedError)` — no client issued | **fail-closed** |
| 2 | Gateway namespace missing | `ip netns del skyla-egress-gw` | `EgressUnavailable: egress enforcement required but the perimeter is not installed` | **fail-closed** |
| 3 | Perimeter absent entirely | `ip netns del skyla-egress` | same refusal | **fail-closed** |
| 4 | API startup with no boundary | `SKYLA_EGRESS_MODE=enforce python -c "import skyla.api.app"` on the host | `RuntimeError: SKYLA PRIME refused to start: egress gateway ... unreachable` — **before serving** | **fail-closed** |
| 5 | Attempt to downgrade from inside the boundary | `resolve_mode("policy")` / `("legacy")` as uid 1001 inside | both **REFUSED** | **fail-closed** |
| 6 | Direct egress succeeds (boundary not constraining) | mutation: make `create_connection` always succeed | `EgressUnavailable: direct egress succeeded ... can bypass the egress gateway` | **fail-closed** |
| 7 | Proxy restart | restart the proxy after failure | authorised path resumes (`HTTP 200`) | **recovers** |
| 8 | Configuration error: unknown mode | `resolve_mode("permissive")` | `EgressUnavailable: unknown egress mode` | **fail-closed** |
| 9 | Cleanup after interrupted initialisation | `destroy()` while a process is inside | members detected and terminated before removal | **fail-closed (see §3)** |
| 10 | Namespace deleted under a live process | rebuilt the perimeter while the API was running | process stranded with only `lo`, every connect `ENETUNREACH` | **DEFECT — fixed in §3** |

## 2. Why "no client" rather than "a weaker client"

The entire control reduces to the return type of one function. `client()` either returns a proxied client or raises. There is no branch that returns a direct client when the proxy is down — a search for `EgressUnavailable` shows one raise site per failure and no handler that converts it into a client.

This matters because the natural "resilient" design — fall back to direct egress if the proxy is unavailable — is precisely the vulnerability. An attacker who can kill the proxy would gain unrestricted egress. Unavailability must therefore be an outage, not a downgrade.

**Cost, stated honestly:** an outage of the egress proxy takes down every outbound capability of the API (research, model calls, connectors) until it is restarted. That is the intended trade. It is an availability control failure, not a security control failure, and it is visible rather than silent.

## 3. The lifecycle defect found during this milestone

**Symptom.** After rebuilding the perimeter while an API instance was running, that instance kept running and kept passing health checks. Inside its namespace:

```
lo               UNKNOWN        127.0.0.1/8
(routes: none)
gateway  → OSError [Errno 101] Network is unreachable
```

**Cause.** `ip netns del` detaches the namespace mount but does not kill or migrate the processes inside it. They remain pinned to the now-orphaned namespace, whose veth peers were destroyed. They see `lo` and nothing else.

**Why it is the worst failure shape.** The process looks healthy from outside — the health endpoint answers inside the namespace, the supervisor sees a live PID — while every network operation fails with `ENETUNREACH`. No startup error, no crash, no alert. It fails only when a protected operation is attempted, at which point the failure looks like a network problem rather than a lifecycle mistake.

**Fix.** `EgressPerimeter.members()` enumerates PIDs whose network namespace inode matches the perimeter. `destroy()` terminates them (SIGTERM, 5 s grace, then SIGKILL) before removing the namespace. Passing `kill_members=False` leaves them alone but records a warning that **survives** the generic "destroyed" reason:

> `2 process(es) remain inside 'skyla-egress' and will lose all network reachability when it is removed`

Overwriting that warning with "destroyed" would have been the reassuring-and-wrong signal this milestone exists to remove, so the warning takes precedence.

**Tests.** `test_destroying_the_perimeter_does_not_strand_live_processes` (a real process inside the namespace is detected as a member) and `test_destroy_reports_stranding_when_members_are_left_alone`.

## 4. Recovery semantics

| Component | Failure | Recovery | Verified |
|---|---|---|---|
| Egress proxy | process dies | restart; no API restart needed — `client()` re-probes on every call | yes (§1 row 7) |
| Gateway namespace | deleted | `scripts/skyla-perimeter.sh setup`; **running API must be restarted** (it is stranded) | yes |
| Workload namespace | deleted | same | yes |
| API | any egress refusal | restart; startup re-verifies and refuses if still broken | yes (§1 row 4) |
| Route configuration | tampered | `verify` reports the problem by name and refuses | yes |

`_verify_boundary()` runs **per client creation**, not once at startup. A boundary that is removed at runtime is therefore detected on the next protected operation rather than after the next restart. The cost is one `connect()` to the gateway plus one to `1.1.1.1` per client; both are cheap relative to the outbound call that follows, and it is the difference between "confined at boot" and "confined now".

## 5. Startup failure is a refusal, not a warning

```
$ SKYLA_EGRESS_MODE=enforce python -c "import skyla.api.app"
RuntimeError: SKYLA PRIME refused to start: egress gateway 10.200.0.1:8155
unreachable (TimeoutError: timed out) — protected operations refuse to run
```

Raised at module import, before uvicorn binds a port. An operator cannot start the service in a state where outbound calls would be unconfined — unless they explicitly select a weaker mode, which a namespaced process is not permitted to do (§1 row 5).

## 6. Residual risks, not hidden

| Risk | Mitigation | Residual |
|---|---|---|
| Proxy is a single point of failure for all egress | restart; verified recovery | An outage stops model calls and connectors. Accepted; it is an availability cost, not a silent downgrade. |
| Proxy runs as root on the host | needed to bind the gateway's host-side address | A compromised proxy is outside the namespace's protection. Not addressed here. |
| An operator could place the API outside the namespace | startup contract documents `enforce`; `verify` reports `namespaced` | Not prevented — deployment discipline. Recorded as an operational control. |
| Custom LAN model endpoints cannot work | documented policy edit required | A deliberate constraint, not a bug. |

## 7. Reproducing

```bash
# 1. proxy down
sudo pkill -f "skyla-perimeter.sh proxy"
sudo nsenter -t $API_PID -n env SKYLA_EGRESS_MODE=enforce \
     python -c "from skyla.egress_client import client; client('research')"
# -> EgressUnavailable: egress gateway ... unreachable

# 2. startup refusal (host, no perimeter)
SKYLA_EGRESS_MODE=enforce python -c "import skyla.api.app"
# -> RuntimeError: SKYLA PRIME refused to start: ...

# 3. stranding detection
sudo python -c "
from skyla.perimeter import EgressPerimeter
print('members:', EgressPerimeter('skyla-egress').members())"
```
