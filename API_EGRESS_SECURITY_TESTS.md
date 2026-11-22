# API Egress Security Tests — v0.2.3 Mission 4 & 7

All results below are from the **actual running API process**, unprivileged (uid 1001) inside the perimeter, probed through its own namespace with `nsenter -t <pid> -n`. None is a child-workload test and none calls a URL validator.

- Commit: `5bace07`
- API: `uvicorn skyla.api.app:app --host 10.200.0.2 --port 8080`, started with `setpriv --reuid=1001 --clear-groups --inh-caps=-all --bounding-set=-all`
- Startup proof: `{'mode': 'enforce', 'proxy': 'http://10.200.0.1:8155', 'namespaced': True, 'netns_inode': 'net:[4026532280]', 'policy': 'api-egress', 'enforced': True}`

---

## 1. Mission 4 — required verifications

| # | Requirement | Method | Result | Verdict |
|---|---|---|---|---|
| 1 | Allowlisted public HTTPS destination succeeds | `GET https://pypi.org/simple/` via `client("research")` | **HTTP 200** | **PASS** |
| 1b | Second allowlisted host | `GET https://files.pythonhosted.org/` | HTTP 404 (reached, host has no `/` document) | **PASS** |
| 2 | Non-allowlisted destination fails | `GET https://github.com/` via `client("research")` | `ProxyError 403` | **PASS** |
| 2b | Non-allowlisted, different capability | `GET https://www.googleapis.com/` via `client("research")` | `ProxyError 403` | **PASS** |
| 3 | Metadata endpoints fail | `169.254.169.254:80` raw socket; and via proxy | `OSError` (raw), `403` (proxy) | **PASS** |
| 4 | Private internal services fail | `10.201.0.1:8200` (host, bound `0.0.0.0`) | `OSError` raw, `403` via proxy | **PASS** |
| 5 | Host loopback unreachable | `10.201.0.1:8201` (host, bound `127.0.0.1`) | `OSError` raw, `403` via proxy | **PASS** |
| 6 | Host-bound `0.0.0.0` services unreachable from unauthorised namespaces | same as #4, plus a live listener created during the test | unreachable | **PASS** |
| 7 | Direct DNS bypass denied | `socket.gethostbyname("pypi.org")` inside | `gaierror` | **PASS** |
| 8 | Redirect-based SSRF blocked | `client()` forces `follow_redirects=False`; `netguard` rejects redirect targets | asserted + `SSRFBlocked` for `169.254.169.254`, `127.0.0.1`, `10.0.0.1` | **PASS** |
| 9 | Direct socket operations cannot bypass the approved route | `socket.create_connection` to `1.1.1.1:53`, metadata, host API | `OSError` ×3 | **PASS** |
| 10 | IPv4 restricted | #1–#4, #9 | as above | **PASS** |
| 11 | IPv6 restricted | `ip -6 route` inside → **empty**; `::1:53` → `OSError` | no v6 path exists | **PASS** |
| 12 | API still performs authorised operations | 11-case capability sweep (§2), API serves `GET /api/health` → 200 | **11/11** | **PASS** |

### Raw probe output (from the unprivileged API's namespace)

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

Exactly one destination reachable, and it is the authorised one.

## 2. Capability sweep — authorised reach and cross-capability denial

| Case | Expected | Result | Verdict |
|---|---|---|---|
| `research` → pypi.org | reach | 200 | **PASS** |
| `research` → files.pythonhosted.org | reach | 404 (reached) | **PASS** |
| `research` → github.com | deny | ProxyError | **PASS** |
| `research` → googleapis | deny | ProxyError | **PASS** |
| `research` → metadata | deny | 403 | **PASS** |
| `research` → host `0.0.0.0` service | deny | 403 | **PASS** |
| `research` → host loopback | deny | 403 | **PASS** |
| `connector-google` → pypi.org | deny (wrong capability) | ProxyError | **PASS** |
| `connector-google` → github.com | deny | ProxyError | **PASS** |
| `connector-telegram` → pypi.org | deny | ProxyError | **PASS** |
| `model-provider` → pypi.org | deny | ProxyError | **PASS** |

**11/11.** The cross-capability rows are the ones that prove scoping is real rather than incidental: a Google-scoped client is refused a host that a research-scoped client is allowed.

## 3. Provider reach — NOT VERIFIED, with the reason

Reach to `www.googleapis.com`, `api.openai.com` and `api.telegram.org` **could not be demonstrated**, and this is not a defect in the enforcement path:

```
Measured from the HOST, no proxy, no namespace:
  pypi.org             TLS OK   TLSv1.3
  github.com           TLS OK   TLSv1.3
  www.googleapis.com   TLS FAIL SSLZeroReturnError
  api.openai.com       TLS FAIL SSLZeroReturnError
  api.telegram.org     TLS FAIL SSLZeroReturnError
```

The sandbox's own egress filter blocks TLS to those three hosts **even unconfined**. Through the proxy the `CONNECT` succeeds (`HTTP/1.1 200 Connection Established` for all three — policies allow them), and then the TLS handshake receives EOF from the upstream filter.

So: **policy permitting is verified; data-plane reach to those providers is NOT VERIFIED.** It would pass or fail identically with or without the perimeter. Claiming either way from this environment would be fabrication. A host without that filter is required — the same action item as `LIVE_CONNECTOR_VALIDATION.md`.

## 4. Mission 7 — mutation results

Each mutation was applied to a live system, the suite run, and the original restored from a byte-copy (not `git checkout`, which discarded uncommitted work once during this milestone — see §5).

| # | Mutation | Expected | Observed | Detected by |
|---|---|---|---|---|
| M1 | Drop `proxy=` from the client factory (bypass the approved proxy) | binding test fails | **2 failed** | `test_the_client_is_bound_to_the_gateway_and_ignores_the_environment`, `test_an_unknown_capability_gets_deny_all` |
| M2 | Add a default route to the workload namespace | route test fails | **1 failed** | `test_workload_namespace_has_no_default_route` |
| M3 | `iptables -I FORWARD 1 -j ACCEPT` in the gateway, plus a route to the host | internal service reachable | **still blocked** — `ConnectionRefusedError`; routing layer held | kernel probe (not the suite) |
| M4 | `follow_redirects=True` (skip redirect re-validation) | binding test fails | **1 failed** | `test_the_client_is_bound_...` |
| M5/M8 | `verify()` reports `available` regardless of problems | reporting test fails | **1 failed** | `test_verify_reports_available_false_with_a_reason_when_broken` |
| M6 | Widen `research` policy to include `10.201.0.1` (allow direct internal API access) | policy test fails | **15 passed** — **NOT DETECTED** | *nothing; see below* |
| M7 | Skip `_verify_boundary()` (setup "succeeds" without controls) | fail-closed tests fail | **3 failed** | `test_no_client_is_issued_...`, `test_an_unreachable_gateway_fails_closed`, `test_direct_egress_success_is_treated_as_a_failure` |

### M6 — an honest non-detection, and what it revealed

M6 is reported as **not detected by the suite**, because it was not. The reason is not a gap but a second layer doing its job:

```
policy allows 10.201.0.1: True
netguard: '10.201.0.1' resolves to blocked destination: private address
```

`netguard` classifies the **resolved address** independently of policy. Widening a policy to a private address therefore achieves nothing — the address check refuses it. Two tests were added to pin that layer (`test_netguard_blocks_private_addresses_independently_of_policy`, `test_a_widened_policy_still_cannot_reach_a_private_address`), because without them a future refactor could remove the address check and rely on policy, at which point M6 *would* become exploitable and nothing would say so.

### Kernel-level versus suite-level detection

Stated precisely, because the distinction matters for what a green suite means:

| Mutation type | Detected by | Runs without privileges? |
|---|---|---|
| Client construction, policy, fail-closed logic | pytest suite | **yes** |
| Routing table, namespace presence, actual reachability | kernel probes / `@requires_perimeter` tests | **no** — needs CAP_SYS_ADMIN |

M2, M3 and the reachability assertions are kernel-level: they skip in an unprivileged run and are **NOT VERIFIED** there, never passed.

## 5. A process error worth recording

During mutation testing, `git checkout skyla/egress.py` was used to restore a mutant. Because the policy work was **uncommitted**, that discarded the entire policy implementation — 14 additions — and silently reverted the file to `HEAD`. The suite's next run failed with `ImportError: cannot import name 'policy_for_connector'`.

Two lessons, both now applied:
1. Restore mutations from a **byte-copy** (`cp`), never `git checkout`, when the file has uncommitted work.
2. `git checkout <file>` is not a safe revert during active development; it is a time machine to the last commit.

No work was permanently lost (the backup existed), but the failure was invisible until the next test run. This is the same class of problem the milestone is about: a change that looks safe and silently removes a control.

## 6. Reproducing these tests

```bash
# Suite-level (no privileges): construction, policy, fail-closed logic
venv/bin/python -m pytest tests/security/test_api_egress.py -q     # 18 passed, 6 skipped

# Kernel-level: the boundary itself
sudo venv/bin/python -m pytest tests/security/test_api_egress.py \
    tests/security/test_network_perimeter.py -q                    # 45 passed, 1 skipped

# Live API probe (the method used above)
PID=$(pgrep -f "uvicorn skyla.api.app:app --host 10.200.0.2")
sudo nsenter -t $PID -n python -c "
import socket
try: socket.create_connection(('169.254.169.254',80),timeout=3); print('REACHED - BAD')
except Exception as e: print('blocked:', type(e).__name__)"
```

**Skips are not passes.** Unprivileged, 6 tests skip (5 need CAP_SYS_ADMIN, 1 needs the running proxy). As root, 1 skips (proxy not running). Every skip is enumerated with its release implication in `SECURITY_EVIDENCE_REGISTRY.md`.
