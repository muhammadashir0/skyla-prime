# B-01 Remediation Evidence — v0.2.3 API Egress Integration

Per-record evidence for the API-integration closure of B-01. The original finding text and the preceding partial closure are **retained unchanged** (`EGRESS_PROXY_ASSESSMENT.md` and `B01_REMEDIATION_REPORT.md`); this document is a new record that references them rather than rewriting them.

- Original finding: `EGRESS_PROXY_ASSESSMENT.md` — **B-01 (High)**, frozen, unaltered
- Prior partial record: `B01_REMEDIATION_REPORT.md` — verdict PARTIAL, unaltered
- This record: API integration, commit `5bace07`
- Environment: `e2b.local`, Debian 12, kernel 6.1.158+, 2 vCPU, 3939 MB

---

## 1. Why the previous closure was insufficient

`B01_REMEDIATION_REPORT.md` closed B-01 "for the untrusted-execution path" and marked it PARTIAL for the trusted API process, stating:

> `run_confined()` exists and is proven, but the API's own outbound calls do not yet go through it: `skyla/api/app.py` has **no egress reference at all**

That was correct, and it left the substance of B-01 open. The finding was never about child processes — it was:

> A process that ignores `HTTPS_PROXY` and dials directly is not stopped by this layer… this is **FAIL**, not an untested control.

The API process is the process that dials. Measured before any change here:

| Probe from the running API's own namespace | Result |
|---|---|
| `pypi.org:443` | **REACHED** |
| `169.254.169.254:80` (metadata) | **REACHED** |
| `www.googleapis.com:443` | **REACHED** |

`grep -rn "HTTPS_PROXY\|trust_env\|proxy=" skyla/` returned **zero real uses**. Eleven independent `httpx.AsyncClient(...)` constructions, none with a proxy. The proxy module was never on any path the application took.

## 2. Evidence records

Each row is a claim with its test, its reproduction, and the mutation that shows the test is sensitive.

### E-01 · API process is confined to the perimeter namespace

| Field | Value |
|---|---|
| Control | API-originated egress is constrained by a kernel boundary |
| Requirement | Mission 4: verify the actual running API process |
| Implementation | deployment (`EGRESS_GATEWAY_DEPLOYMENT.md` §3), `egress_client.is_namespaced()` |
| Threat | compromised dependency or connector reaches the internet / metadata |
| Test | `test_the_api_namespace_cannot_reach_the_internet_directly` |
| Environment | root (CAP_SYS_ADMIN to enter the namespace) |
| Repro | `sudo nsenter -t $API_PID -n python -c "import socket; socket.create_connection(('1.1.1.1',53),3)"` |
| Expected | `OSError` |
| Actual | `OSError`, from a live uid-1001 API in `net:[4026532280]` |
| Mutation | M2 add a default route → test fails |
| Detected | **yes** |
| Status | **PASS** |

### E-02 · Internal and metadata services unreachable through the perimeter

| Field | Value |
|---|---|
| Control | no lateral movement from the API to host services |
| Implementation | gateway topology + `netguard` address classification |
| Threat | SSRF to the API itself, to metadata, or to host loopback |
| Test | `test_the_api_namespace_cannot_reach_internal_services`, `test_netguard_blocks_private_addresses_independently_of_policy` |
| Repro | probe `10.201.0.1:8200` (host `0.0.0.0`), `10.201.0.1:8201` (host loopback), `169.254.169.254` |
| Expected | all fail |
| Actual | `OSError` raw; `403` via proxy |
| Mutation | M6 widen policy to `10.201.0.1` → **suite did not fail**; `netguard` still refused |
| Detected | partially — see §3 |
| Status | **PASS** (two independent layers) |

### E-03 · The authorised path still works

| Field | Value |
|---|---|
| Control | enforcement is not an outage |
| Implementation | proxy `api-egress` default + capability policies; gateway DNAT to the proxy |
| Test | `test_the_authorised_path_is_still_open`, plus the live 11-case sweep |
| Repro | `client("research").get("https://pypi.org/simple/")` from inside the namespace |
| Expected | HTTP 200 |
| Actual | **HTTP 200**; `files.pythonhosted.org` reached (404 = reached) |
| Status | **PASS** |

### E-04 · Capability scoping is enforced, not merely declared

| Field | Value |
|---|---|
| Control | one compromised capability cannot borrow another's reach |
| Implementation | `Proxy-Authorization: Basic base64("cap:secret")` → per-request policy |
| Threat | a compromised research fetcher calling a paid model provider, or a connector reaching an arbitrary host |
| Test | live sweep §2 of `API_EGRESS_SECURITY_TESTS.md` |
| Repro | `client("connector-google")` GET `https://pypi.org/simple/` |
| Expected | denied |
| Actual | `ProxyError 403`; the same URL via `research` returns 200 |
| Status | **PASS** |

### E-05 · Proxy failure fails closed

| Field | Value |
|---|---|
| Control | no silent downgrade to direct networking |
| Implementation | `client()` raises `EgressUnavailable`; no fallback branch exists |
| Test | `test_an_unreachable_gateway_fails_closed` |
| Repro | stop the proxy, call `client("research")` |
| Expected | raise |
| Actual | `EgressUnavailable: egress gateway ... unreachable (ConnectionRefusedError)` |
| Mutation | M7 skip `_verify_boundary` → **3 tests fail** |
| Detected | **yes** |
| Status | **PASS** |

### E-06 · Startup fails closed

| Field | Value |
|---|---|
| Control | the API will not serve with unconstrained egress |
| Implementation | `api/app.py` startup check at import time |
| Test | `test_no_client_is_issued_when_the_perimeter_is_missing` + live import |
| Repro | `SKYLA_EGRESS_MODE=enforce python -c "import skyla.api.app"` on the host |
| Expected | `RuntimeError` before binding a port |
| Actual | `RuntimeError: SKYLA PRIME refused to start: egress gateway ... unreachable` |
| Status | **PASS** |

### E-07 · A confined process cannot downgrade its mode

| Field | Value |
|---|---|
| Control | enforcement is mandatory inside the boundary, not selectable |
| Implementation | `resolve_mode()` refuses `policy` and `legacy` when namespaced |
| Test | `test_a_namespaced_process_cannot_downgrade_its_mode` |
| Repro | uid 1001 inside `skyla-egress`: `resolve_mode("policy")`, `resolve_mode("legacy")` |
| Expected | both refuse |
| Actual | both `REFUSED`; `enforce` returns `enforce` |
| Status | **PASS** |

### E-08 · Namespace detection works unprivileged

| Field | Value |
|---|---|
| Control | the guard above is actually active for the service as deployed |
| Implementation | compare against `/var/run/netns/skyla-egress` (world-readable) |
| Threat | **a confined process reporting itself unconfined, disabling its own guard** |
| Test | `test_namespace_detection_works_without_reading_proc1`, `test_detection_compares_against_the_perimeter_namespace` |
| Repro | live uid-1001 API inside the perimeter |
| Expected | `is_namespaced() == True` |
| Actual | **before fix `False`** (read `/proc/1/ns/net`, unreadable unprivileged); **after fix `True`** |
| Status | **PASS** — after fixing a real defect |

### E-09 · Destroying the perimeter does not strand live processes

| Field | Value |
|---|---|
| Control | correct namespace lifecycle |
| Threat | a service that looks healthy while every network call fails |
| Implementation | `EgressPerimeter.members()` + terminate-before-destroy |
| Test | `test_destroying_the_perimeter_does_not_strand_live_processes`, `test_destroy_reports_stranding_when_members_are_left_alone` |
| Repro | start a process inside the namespace, call `destroy()` |
| Expected | the process is detected as a member and terminated |
| Actual | detected and terminated; with `kill_members=False` the warning survives |
| Status | **PASS** — after fixing a real defect |

### E-10 · Redirect re-validation preserved

| Field | Value |
|---|---|
| Test | `test_the_client_is_bound_to_the_gateway_and_ignores_the_environment` |
| Expected | `follow_redirects is False`, `trust_env is False` |
| Actual | both |
| Mutation | M4 `follow_redirects=True` → test fails |
| Detected | **yes** |
| Status | **PASS** |

## 3. Mutation summary — precise, including the failure

| # | Mutation | Detected by suite | Notes |
|---|---|---|---|
| M1 | Remove `proxy=` from the factory | **yes** (2 tests) | client could bypass the approved route |
| M2 | Default route in the workload namespace | **yes** (kernel test) | |
| M3 | Disable gateway FORWARD enforcement | **no** — layer 1 still held | recorded as an independent-layer result, not a pass |
| M4 | `follow_redirects=True` | **yes** | |
| M5/M8 | `verify()` always reports available | **yes** | |
| M6 | Widen policy to a private IP | **NO** | `netguard` blocked it anyway; two tests now pin that layer |
| M7 | Skip boundary verification | **yes** (3 tests) | |

M3 and M6 are reported as non-detections because that is what they are. Both were explained by a second, independent layer — which is a better outcome than a detection, but only if someone records that the first layer alone was insufficient and that the second is what actually held.

## 4. What remains NOT VERIFIED

| Item | Reason |
|---|---|
| TLS reach to `googleapis` / `openai` / `telegram` | this sandbox's egress filter blocks them even from the host with no proxy (`SSLZeroReturnError`). Policy permitting is verified; data-plane reach is not. Needs a host without that filter. |
| Live connector operations | no authorized provider credentials exist (`LIVE_CONNECTOR_VALIDATION.md`) |
| Host-wide default-deny egress | the API is confined; other host processes are not (NET-23) |
| Second-host validation | no hypervisor or container runtime available (HOST-01) |

None is claimed as a pass, and none of these is required for B-01 specifically — but all remain release gates.

## 5. Verdict

**B-01: REMEDIATED for the API process.**

Every condition the milestone set:

| Condition | Met |
|---|---|
| The actual API process is constrained | **yes** — `namespaced: True`, uid 1001, live |
| Every relevant external operation uses the approved route | **yes** — 11 call sites, zero direct `httpx` in application modules |
| Unauthorized direct connections fail | **yes** — `OSError` / `403` |
| Internal services cannot be accessed through the perimeter | **yes** — two layers |
| Gateway failures cause protected operations to fail closed | **yes** — 10/10 failure modes |
| Required authorized integrations continue working | **partially** — allowlisted hosts yes; google/openai/telegram data plane NOT VERIFIED (environment) |
| Relevant mutations are detected | **5 of 7**, 2 explained by an independent layer |
| Evidence is reproducible | **yes** — commands in every record |

The one partial condition is an environment limitation, not a gap in the enforcement path, and it is recorded as NOT VERIFIED rather than inferred.

**Production remains NO-GO** on the other outstanding gates (NET-23 host firewall, HOST-01 second host, live connectors, independent review), none of which B-01 closure resolves.
