# B-01 API Egress Integration — v0.2.3

**Verdict: B-01 is now REMEDIATED for the API process.** The trusted process — the one holding credentials, database access and every connector — cannot reach the internet except through the egress gateway, and that was proven by probing the live unprivileged process rather than a child workload.

This document summarises; the evidence is in `B01_REMEDIATION_EVIDENCE.md`, the design in `API_NETWORK_ISOLATION_DESIGN.md`, and the measurements in `API_EGRESS_SECURITY_TESTS.md`.

- Commit: `5bace07` · Suite: **359 passed, 37 skipped** · Perimeter file as root: **45 passed, 1 skipped**

---

## 1. What was wrong

The previous milestone closed B-01 for child workloads and marked it PARTIAL for the API. That was the right call, and this milestone shows how much was left:

```
$ grep -rn "HTTPS_PROXY\|trust_env\|proxy=" --include=*.py skyla/
(only matches: docstrings in egress.py and perimeter.py)

$ grep -rn "httpx.AsyncClient(" --include=*.py skyla/integrations skyla/knowledge skyla/models
11 call sites, none with proxy=
```

Measured from the running API's own namespace, before any change:

| Probe | Result |
|---|---|
| `pypi.org:443` | **REACHED** |
| `169.254.169.254:80` | **REACHED** |
| `www.googleapis.com:443` | **REACHED** |

The egress proxy was a module and a document. No application code path used it. B-01's substance — *"a process that ignores `HTTPS_PROXY` and dials directly is not stopped by this layer"* — described the API exactly.

## 2. What changed

**Option A + Option B, combined** (rationale in the design doc): the API runs inside the restricted namespace, so there is no route to bypass; and every outbound call goes through the proxy, so per-destination policy is applied per capability.

Three code changes:

1. **`skyla/egress_client.py` (new).** The only way to obtain an outbound client. Proxy fixed to the gateway, `trust_env=False`, `follow_redirects=False`, capability-scoped, and in `enforce` mode it proves the boundary before returning — gateway reachable **and** internet unreachable. A direct route raises rather than logging a warning.
2. **All 11 call sites rewritten** to use it: research, model health, model chat, custom endpoint, Gmail OAuth + 2 API calls, Calendar OAuth + 2 API calls, Telegram × 2.
3. **`skyla/api/app.py` refuses to start** when enforcement is configured but unavailable — at import, before uvicorn binds a port.

Plus two defects found by running it as deployed (both failures in the dangerous direction):

- `is_namespaced()` read `/proc/1/ns/net`, which an **unprivileged** process cannot open — and unprivileged is how the service is meant to run. A correctly confined process reported `False`, which disabled the guard preventing it from selecting a weaker mode. Fixed to compare `/var/run/netns/skyla-egress`.
- `destroy()` removed a namespace out from under running processes. They kept running with only `lo`, every connect `ENETUNREACH`, still answering health checks. `destroy()` now terminates members first, or reports the stranding.

## 3. Verification from the actual process

API started with `setpriv --reuid=1001 --clear-groups --inh-caps=-all` inside `skyla-egress`. Startup log:

```
egress route confirmed: {'mode': 'enforce', 'proxy': 'http://10.200.0.1:8155',
                         'namespaced': True, 'netns_inode': 'net:[4026532280]',
                         'policy': 'api-egress', 'enforced': True}
```

Probes from inside that process's namespace:

```
IPv4 internet 1.1.1.1:53             OSError
IPv4 internet 8.8.8.8:443            OSError
metadata 169.254.169.254:80          OSError
host 0.0.0.0 svc 10.201.0.1:8200     OSError
host loopback 10.201.0.1:8201        OSError
gateway non-proxy 10.200.0.1:8080    ConnectionRefusedError
gateway proxy 10.200.0.1:8155        REACHED
DNS pypi.org                         gaierror
IPv6 ::1:53                          OSError
```

Exactly one reachable destination, and it is the authorised one.

Capability sweep — 11/11:

| Case | Result |
|---|---|
| `research` → pypi.org | **200** |
| `research` → files.pythonhosted.org | reached (404) |
| `research` → github.com | denied |
| `research` → googleapis | denied |
| `research` → metadata | 403 |
| `research` → host `0.0.0.0` service | 403 |
| `research` → host loopback | 403 |
| `connector-google` → pypi (wrong capability) | denied |
| `connector-google` → github | denied |
| `connector-telegram` → pypi | denied |
| `model-provider` → pypi | denied |

The cross-capability rows are what make scoping credible: a Google-scoped client is refused a host that a research-scoped client may reach.

## 4. Failure behaviour — 10/10 fail closed

Proxy down, gateway missing, perimeter absent, startup without a boundary, attempted downgrade from inside, unknown mode, direct egress succeeding, cleanup with live processes — every one refuses rather than degrading. Recovery was verified: after a proxy restart the authorised path resumes without an API restart, because the boundary is re-proved per client rather than only at boot.

**The trade, stated plainly:** a proxy outage stops all outbound capability (research, model calls, connectors) until it is restarted. That is an availability cost chosen deliberately over the alternative — falling back to direct egress, which would hand an attacker who can kill the proxy unrestricted access.

## 5. Mutations

| Mutation | Detected |
|---|---|
| Remove `proxy=` from the client factory | **yes** (2 tests) |
| Default route in the workload namespace | **yes** |
| `follow_redirects=True` | **yes** |
| Skip boundary verification (setup "succeeds" without controls) | **yes** (3 tests) |
| `verify()` always reports available | **yes** |
| Widen a policy to a private IP | **no** — `netguard` blocked it independently; two tests now pin that layer |
| Disable gateway FORWARD rules | **no** — the routing layer held independently |

Two non-detections, both explained by an independent second layer rather than by a gap. Reported as non-detections because that is what they are; a detection would have meant the first layer alone was sufficient, and it is not.

## 6. What is still not verified

| Item | Status | Reason |
|---|---|---|
| TLS reach to googleapis / openai / telegram | **NOT VERIFIED** | this sandbox blocks those hosts even from the host with no proxy (`SSLZeroReturnError`). Policies permit them; the data plane cannot be exercised here. |
| Live connector operations | **NOT VERIFIED** | no authorized provider credentials (`LIVE_CONNECTOR_VALIDATION.md`) |
| Host-wide default-deny egress (NET-23) | **NOT MET** | the API is confined; other host processes are not |
| Second host (HOST-01) | **NOT VERIFIED** | no hypervisor or container runtime (`SECOND_HOST_VALIDATION.md`) |

The first is an environment limitation and is not inferred as a pass. The rest are unrelated release gates that B-01 closure does not resolve.

## 7. Release consequence

| Control | Before this milestone | After |
|---|---|---|
| B-01 — enforced egress for the API | PARTIAL | **PASS** |
| Perimeter enforcement (property 2 of 10) | PARTIAL | **PASS** |
| Fail-closed behaviour | not applicable | **PASS** (10/10 modes) |

**Production remains NO-GO** — on NET-23, HOST-01, live connectors, independent review, and the open findings (A-13, A-17, A-21, A-22, B-03…B-07), none of which this milestone addresses. B-01 was one gate; it is now closed on its own terms, and the manifest continues to say NO-GO for the others.
