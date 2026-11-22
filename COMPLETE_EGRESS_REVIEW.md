# Complete Egress Review — v0.2.4 Mission 1

Independent re-verification of the B-01 implementation, searching for **all** networking mechanisms rather than only the ones previously known.

- Base commit: `6b489ef` · Review commit: `067bdf0`
- Method: exhaustive import scan, then each claim tested rather than read

---

## 1. The ten required confirmations

| # | Claim | Method | Result |
|---|---|---|---|
| 1 | The API actually starts inside the required namespace | live process inspection | **CONFIRMED** — PID in `net:[4026532183]` ≠ host `4026531840`, uid 1001 |
| 2 | Every outbound HTTP client uses the approved factory | exhaustive grep | **CONFIRMED** — 0 `httpx` constructions in application modules |
| 3 | No direct-network fallback exists | grep for fallback patterns | **CONFIRMED** — one raise site per failure, no converting handler |
| 4 | Proxy credentials never enter model-visible context | payload inspection | **CONFIRMED** — credentials in the proxy URL only; payload has `model`/`messages`/`temperature`/`max_tokens` |
| 5 | Proxy capabilities are independently validated | unit + live sweep | **CONFIRMED** — unknown → `deny-all`; wrong capability → 403 |
| 6 | Redirects are revalidated | code + test | **CONFIRMED** — `follow_redirects=False`, each hop re-vetted |
| 7 | IPv4 and IPv6 restrictions enforced | live probe | **CONFIRMED** — v4 `OSError`, no v6 routes, `::1` `OSError` |
| 8 | Subprocesses inherit intended restrictions | env + namespace inspection | **CONFIRMED** — `unshare -Urmpf -n`, env allowlist `PATH`/`HOME` only |
| 9 | API restarts do not silently downgrade | restart test | **CONFIRMED** — `enforce` re-verified per client, not just at boot |
| 10 | Namespace destruction safely handles running processes | lifecycle test | **CONFIRMED** — members terminated before removal |

## 2. Complete outbound-path inventory — all mechanisms searched

Searched for: `requests`, `urllib`, `urllib3`, `aiohttp`, `socket`, `ssl`, `http.client`, `httpx`, `grpc`, `httplib2`, `pycurl`, `boto3`, `googleapiclient`, `slack_sdk`, `twilio`, `anthropic`, `openai`, and subprocess-capable code.

| Mechanism | Used? | Where | Verdict |
|---|---|---|---|
| `httpx` | **yes** | only inside `skyla/egress_client.py` | the single approved path |
| `socket` | yes | `egress.py` (proxy listener), `netguard.py` (resolve/classify), `perimeter.py` + `egress_client.py` (boundary probes) | all legitimate |
| `urllib.parse` | yes | `research.py`, `netguard.py`, `egress.py` | **URL parsing only — never opens a connection** |
| `requests`, `urllib3`, `aiohttp` | **no** | — | not dependencies |
| `grpc` / `http.client` / `httplib2` / `pycurl` | **no** | — | absent |
| Vendor SDKs (`boto3`, `googleapiclient`, `openai`, `anthropic`, `slack_sdk`, `twilio`) | **no** | — | providers reached over plain HTTPX, no SDK |
| `subprocess` | yes | `workload.py`, `sandbox.py`, `providers.py`, `perimeter.py` | see §3 |

**The absence of vendor SDKs matters.** Each SDK would bring its own connection pool and its own proxy handling; the platform deliberately speaks raw HTTPX so that exactly one factory controls every call.

## 3. Subprocess inheritance

| Path | Mechanism | Network | Env |
|---|---|---|---|
| Untrusted execution (`workload.py:222`) | `unshare -Urmpf -n` | **own netns, no interfaces**; seccomp denies `socket()` | allowlist: `PATH`, `HOME` |
| Legacy sandbox (`sandbox.py:31`) | `subprocess.run` | **inherits host network** — see §5 | allowlist: `PATH`, `PYTHONDONTWRITEBYTECODE` |
| Provider wrapper (`providers.py:89`) | `subprocess.run` | `unshare -n` | inherited |
| Perimeter commands (`perimeter.py:141`) | `subprocess.run` | host (admin only) | inherited |

Neither env allowlist contains `HTTPS_PROXY`, `SKYLA_EGRESS_SECRET`, or any provider credential, so a subprocess cannot obtain the proxy capability even if it kept a route.

## 4. Restart behaviour — verified, not assumed

`_verify_boundary()` runs **per client creation**, not once at startup. A boundary removed at runtime is therefore detected on the next protected operation rather than after the next restart. The cost is two `connect()` calls per client; the benefit is that "confined at boot" and "confined now" are the same statement.

Measured sequence: start API inside perimeter → kill proxy → protected operation raises → restart proxy → operation succeeds **without restarting the API**.

## 5. One gap, stated rather than enclosed

`skyla/execution/sandbox.py` (the `local` provider) runs a child that **inherits the host network namespace**. It is not the default (`SKYLA_EXECUTION_PROVIDER=namespace`), and it was listed in the v0.2.3 inventory as an open item.

This review confirms it is still open. It is **not** a B-01 regression — B-01 concerns the trusted API process, which is confined — but it is a real hole in the execution boundary for an operator who switches providers. With the host firewall from `HOST_FIREWALL_DEPLOYMENT.md` now deployed, that sandbox's egress is subject to host default-deny instead of being unrestricted, which reduces the exposure without closing the design gap. Recorded as **EXEC-01, open**.

## 6. What changed in this review versus the v0.2.3 claims

Two defects were found in the prior work **by re-running it**, not by reading it:

| Defect | Consequence | Fixed |
|---|---|---|
| `perimeter.py` used `socket` without importing it | every host-control probe raised `NameError`, so the control read as "host has no network" while `isolated: True` was still printed — two contradictory lines, the reassuring one winning | `067bdf0` |
| `127.0.0.1:80` used as a "host control" target | nothing listens there on a normal host, so it failed either way and proved nothing | `067bdf0` |

The first is the most consequential finding of this review: **a proof that cannot fail is not a proof.** `prove_no_egress` now requires a working control before it will report isolation, and `setup` fails closed with the reason when the control is unavailable.

## 7. Verification matrix

| Property | Test | Runs unprivileged? | Status |
|---|---|---|---|
| API in namespace | live inspection + `test_the_api_namespace_*` | no (needs CAP_SYS_ADMIN) | **PASS** |
| Client factory only | `test_the_client_is_bound_*`, `test_an_unknown_capability_gets_deny_all` | **yes** | **PASS** |
| No fallback | `test_no_client_is_issued_*`, `test_an_unreachable_gateway_fails_closed` | **yes** | **PASS** |
| Capability scoping | `test_a_research_client_cannot_reach_a_model_provider` + live sweep | **yes** / no | **PASS** |
| Redirect revalidation | `test_the_client_is_bound_*` asserts `follow_redirects is False` | **yes** | **PASS** |
| IPv6 | `test_the_api_namespace_has_no_ipv6_path` | no | **PASS** |
| Subprocess env | inventory + `workload.py` inspection | **yes** (static) | **PASS** |
| Restart, no downgrade | live sequence + `test_a_namespaced_process_cannot_downgrade_its_mode` | **yes** | **PASS** |
| Namespace destroy | `test_destroying_the_perimeter_does_not_strand_live_processes` | no | **PASS** |
| Control gating | `test_a_failed_host_control_means_isolation_is_not_proven` | **yes** | **PASS** |

## 8. Reproducing this review

```bash
# inventory (should print nothing for the application modules)
grep -rn "httpx.AsyncClient(\|httpx.Client(" --include=*.py skyla/integrations skyla/knowledge skyla/models
for m in requests urllib3 aiohttp grpc boto3 googleapiclient httplib2 pycurl; do
  grep -rn "import $m\|from $m" --include=*.py skyla/ ; done

# the API is really confined
PID=$(pgrep -f "uvicorn skyla.api.app:app --host 10.200.0.2" | tail -1)   # the python process, not the shell
stat -L -c %i /proc/$PID/ns/net /var/run/netns/skyla-egress     # must be equal
sudo nsenter -t $PID -n python -c "import socket; socket.create_connection(('1.1.1.1',53),3)"
```

**A caution learned the hard way:** `pgrep -f "uvicorn skyla.api.app"` matches the *wrapper shell first*, which is in the host namespace. During this review that produced a false "all authorised paths blocked" result until the correct PID was found. Always verify the process's own namespace inode, not its command line.

## 9. Verdict

**B-01 implementation: CONFIRMED.** All ten required properties hold, verified from the running process. Two defects were found in the verification machinery itself and fixed; both had failed in the reassuring direction.

**One execution-boundary gap remains open (EXEC-01, `sandbox.py` local provider)** — disclosed, not enclosed.
