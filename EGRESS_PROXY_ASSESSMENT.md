# EGRESS PROXY ASSESSMENT — v0.2.2 PRIME QUALIFICATION

**Mission 3.** Default-deny egress proxy: destination allowlisting, DNS checks,
private-address restrictions, redirect validation, rebinding protection, metadata
blocking, connection-level validation, audit logging, per-task policy.

## Verdict

> **PASS** for the proxy itself as measured below.
> **NOT VERIFIED** for network-perimeter enforcement: nothing forces traffic through
> the proxy at the host firewall level, because no firewall tooling is available on
> this host (`iptables`, `nft` absent; apt blocked). The proxy is a *policy*
> boundary that traffic must be routed to, not a hermetic network perimeter.

---

## 1. Why a proxy rather than URL validation

v0.3.0 shipped `netguard.validate_url()`. It has three structural gaps:

1. **Only guarded callers.** Any library that opens a socket directly bypasses it.
2. **Check/connect race.** Validation resolves the name, then the HTTP client
   resolves it again — a rebinding resolver wins.
3. **No chokepoint to audit.** Refusals are scattered across call sites.

`skyla/egress.py` is a real HTTP/HTTPS forward proxy. Callers point at it via
`HTTP_PROXY`/`HTTPS_PROXY`; it refuses before opening any socket and logs every
decision.

## 2. Decision order (this order is the security property)

```
1. policy:  host in allowlist?   -> no  => 403, no DNS performed
2. policy:  port permitted?      -> no  => 403
3. policy:  method permitted?    -> no  => 403   (CONNECT governed separately)
4. resolve the hostname
5. classify EVERY resolved address (private / loopback / link-local / metadata)
                                 -> blocked => 403
6. dial the VETTED IP            (never re-resolve the name)
7. log the decision with the vetted IP
```

Step 6 is what closes DNS rebinding: the connection is made to the address that was
classified, not to the name. Tested by substituting a resolver that returns a public
IP and asserting the dial target is that IP
(`test_connection_dials_the_vetted_ip_not_the_name`).

Step 1 ordering matters too: a denied host costs **no DNS lookup**, so a policy
denial cannot itself be used to probe internal name resolution. Verified by
`test_denial_happens_before_any_connection` (denied records carry no resolved IP).

## 3. Required controls

| Requirement | Implementation | Evidence |
|---|---|---|
| Destination allowlisting | exact host or `*.suffix` wildcard; empty policy denies all | `test_empty_policy_denies_everything` |
| DNS resolution checks | every A/AAAA record classified; one blocked record refuses the URL | `test_resolver_returning_metadata_ip_is_refused` |
| Private-address restrictions | RFC1918, loopback, link-local, CGNAT, ULA, IPv4-mapped v6 unwrapped first | `test_private_destinations_denied_even_when_allowlisted` |
| Redirect validation | `follow_redirects=False`; every hop re-vetted; >3 hops refused | `test_redirect_hop_is_revalidated` |
| DNS rebinding protection | dial the vetted IP, not the name | `test_connection_dials_the_vetted_ip_not_the_name` |
| Cloud metadata blocking | `169.254.169.254`, `metadata.google.internal`, `.internal` | `test_private_destinations_denied_*`, `test_internal_service_name_denied` |
| Internal service protection | private ranges + port allowlist `{80,443,8080,8443}` | `test_port_not_in_policy_is_refused` |
| Connection-level validation | classification happens immediately before `connect()` | `test_connection_dials_the_vetted_ip...` |
| Audit logging | JSONL of every allow/deny with vetted IP and task id | `test_every_decision_is_audited`, `test_audit_log_persists_to_disk` |
| Per-task policy | `X-Skyla-Task` selects the policy; one task's allowlist cannot leak | `test_per_task_policy_is_applied` |

## 4. Live results

The environment has its own egress allowlist (see §5), which makes the "authorised
vs unauthorised host" comparison real rather than simulated:

```
policy: research (wikipedia.org, example.com, pypi.org, files.pythonhosted.org)

https://pypi.org/simple/                 -> HTTP 200  48 920 079 bytes
https://github.com/                      -> ProxyError 403
https://www.google.com/                  -> ProxyError 403
http://169.254.169.254/latest/meta-data/ -> HTTP 403   (metadata endpoint)
https://metadata.google.internal/        -> ProxyError 403

--- decisions (JSONL audit, reversed) ---
True   CONNECT pypi.org:443            ip=151.101.128.223  reason=tunnel established
False  CONNECT github.com:443          ip=-                reason=host 'github.com' not in policy 'research'
False  CONNECT www.google.com:443      ip=-                reason=host 'www.google.com' not in policy 'research'
False  GET     169.254.169.254:80      ip=-                reason=host '169.254.169.254' not in policy 'research'
False  CONNECT metadata.google.internal:443 ip=-           reason=host 'metadata.google.internal' not in policy 'research'
```

Three things to read from that table:

* The pypi request transferred **48.9 MB through the tunnel** — a genuine end-to-end
  proxy, not a header check.
* Every denial has `ip=-`: **no DNS was performed for a refused destination**, so the
  decision order (allowlist → DNS) is observable in the audit log, not merely asserted.
* `169.254.169.254` is refused at the **allowlist** stage. The metadata endpoint would
  also be refused by the private-address classifier, so the block does not depend on
  the address appearing in a policy.

`curl` reports `000` rather than `403` for CONNECT denials because the tunnel never
establishes; the HTTP response is on the `CONNECT` line
(`HTTP/1.1 403 Forbidden`, `X-Skyla-Egress: denied`). Verified with `curl -v`.

A workload cannot reach an internal service: the sandbox has no network at all
(`socket()` denied by seccomp), and anything going through the proxy hits the
private-range classifier.

## 5. A bug found by testing

CONNECT was being filtered through `allow_methods`. Any policy that listed specific
HTTP verbs (e.g. `GET, HEAD` for research) therefore made **every HTTPS request
impossible** — the proxy returned `403 method CONNECT not permitted` for
allowlisted hosts. `CONNECT` is tunnel establishment, not an application method, so
it is now governed by the separate `allow_connect` flag. Caught by the live test
asserting `pypi.org -> 200`, which failed while the unit tests were green.

## 6. What is NOT verified

* **No host firewall enforcement.** `iptables`/`nft` are absent and apt is blocked,
  so egress cannot be *forced* through the proxy. A process that ignores
  `HTTPS_PROXY` and dials directly is not stopped by this layer. In production the
  proxy must be the only permitted egress route (network namespace + firewall rule
  `DROP` for all other destinations), and that rule is **NOT VERIFIED** here.
* **No DNS pinning at the socket layer beyond the vetted IP the proxy dials.** The
  proxy dials the vetted IP, but `netguard.validate_url()` (used by the API-side
  fetchers) still hands a hostname to `httpx`, so the API-side path retains a small
  rebinding window unless it is routed through this proxy. Recommended: route
  `research.fetch_url` through the proxy.
* **No TLS interception.** The proxy tunnels CONNECT; it does not inspect content.
  That is intentional (no MITM keys), but it means egress *content* is not filtered,
  only destinations.
* **The sandbox's own HTTP allowlist** (pypi/github/npm only) is a property of this
  execution environment, not of SKYLA. It was useful as an independent control
  during testing and must not be counted as SKYLA's egress policy.

## 7. Residual risk

| Risk | Severity | Note |
|---|---|---|
| Traffic can bypass the proxy (no firewall) | High | closes only with host-level egress rules |
| API-side fetchers keep a rebinding window | Medium | route them through the proxy |
| Content is not inspected | Medium | destination policy only; no DLP |
| Single proxy instance, no HA | Low | acceptable for staging |

## 8. Reproduction

```bash
python -m pytest tests/security/test_egress.py -q     # 22 passed
```

Two tests hit real pypi.org and skip when the sandbox allowlist blocks it; a skip is
`NOT VERIFIED`, never a pass.
