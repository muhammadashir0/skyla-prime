# PRIME CONTAINMENT — SSRF Defence Design

**Scope:** Mission 4, audit finding **A-08** (SSRF in the research fetcher).
**Status:** **PASS** for URL validation, resolution and redirect handling. Egress proxying **NOT VERIFIED** (not deployable here).

---

## 1. The finding

`knowledge/research.py` fetched whatever URL it was given with `httpx` default settings, including `follow_redirects=True`. The audit used it to reach the loopback interface and internal addresses. There was no host, scheme, port or address validation anywhere in the path.

---

## 2. Where validation happens

**At the connection boundary, after resolution — not at parse time.**

```
input URL
   |
   +-- scheme allowlist        http, https only
   +-- credential check        user:pass@ rejected
   +-- host extraction         reject absent / ambiguous numeric hosts
   +-- metadata host list      metadata.google.internal, .internal, etc.
   +-- port allowlist          80, 443, 8080, 8443
   |
   +-- DNS RESOLUTION  <-- the important step
   |      all A/AAAA records vetted individually; if ANY resolves into a
   |      blocked range the whole URL is refused
   |
   +-- return VettedURL(ip=...)   <-- caller connects to this IP, not to the name
```

Vetting the *resolved address* and returning it is what closes the classic TOCTOU window: a name that resolves to a public address during validation and to `127.0.0.1` a millisecond later (DNS rebinding) cannot succeed, because the connection is made to the **vetted IP**, not re-resolved from the name.

`validate_url()` accepts a `resolver` parameter so this property is testable without network access:

```python
def fake_resolver(host, port, **kw):
    return [(AF_INET, SOCK_STREAM, 6, "", ("127.0.0.1", port))]

validate_url("http://innocent-looking.example/", resolver=fake_resolver)
# -> SSRFBlocked: resolves to blocked destination 127.0.0.1
```

(`test_dns_rebinding_is_caught_by_resolving_before_connect`)

---

## 3. Blocked ranges

| Category | Ranges |
|---|---|
| IPv4 loopback | `127.0.0.0/8` |
| IPv4 private | `10/8`, `172.16/12`, `192.168/16` |
| Link-local | `169.254/16` (includes cloud metadata `169.254.169.254`) |
| CGNAT | `100.64/10` |
| Unspecified / this-host | `0.0.0.0/8`, `0.0.0.0` |
| IPv6 loopback | `::1` |
| IPv6 ULA | `fc00::/7` |
| IPv6 link-local | `fe80::/10` |
| **IPv4-mapped IPv6** | `::ffff:a.b.c.d` — unwrapped first, then the v4 rules apply |

The IPv4-mapped case is called out because `::ffff:127.0.0.1` passes a naive version check and then behaves like loopback. `is_blocked_ip()` unwraps `ipv4_mapped` before classification.

Metadata hosts are matched by name as well as by address, because some providers answer on a hostname whose address can change: `metadata.google.internal`, and the `.internal` suffix.

---

## 4. Redirect handling

`follow_redirects` is disabled on the client and the chain is walked manually:

```python
while True:
    vetted = validate_url(current)          # EVERY hop is vetted
    r = client.get(vetted.url, follow_redirects=False)
    if r.status_code not in (301, 302, 303, 307, 308):
        return r
    current = safe_redirect_chain(vetted.url, r.headers["Location"], hops=hops)
    hops += 1                                # > 3 hops -> refused
```

Every hop is a fresh `validate_url`, so a public URL that 302s to `http://127.0.0.1/admin` is refused at the second hop — not fetched and inspected afterwards.

`safe_redirect_chain()` only joins and enforces the hop cap; it deliberately does **not** claim to make the target safe. The safety comes from re-validating each result, which is why the tests assert that the joined URL is still rejected by `validate_url`. This separation is what makes the mutation test meaningful: neutralising `is_blocked_ip` makes the second hop pass, proving the check is load-bearing.

Relative redirects stay on the same public host and are re-validated like any other hop.

---

## 5. Alternate representations and schemes

| Input | Result |
|---|---|
| `http://2130706433/` (decimal 127.0.0.1) | rejected (ambiguous numeric host, and would resolve into loopback) |
| `http://0x7f000001/` | rejected |
| `http://0.0.0.0/` | rejected |
| `http://[::ffff:127.0.0.1]/` | rejected (unwrapped, then loopback) |
| `file:///etc/passwd` | rejected (scheme) |
| `gopher://`, `ftp://`, `dict://` | rejected (scheme) |
| `http://user:pass@example.com/` | rejected (credentials in URL) |
| `http://example.com:22/` | rejected (port) |
| `http://example.com:6379/` | rejected (port) |

Default deny: anything not explicitly permitted is refused.

---

## 6. Measured results

`tests/security/test_ssrf.py` — **45 tests, all passing**. 22 hostile URLs rejected (see `BLOCKED_URLS`), 14 blocked IP ranges confirmed, public addresses allowed, rebinding simulated with a resolver double, redirect chain revalidated, hop cap enforced, malformed inputs refused.

Original scratch matrix (`/tmp/ssrftest.py`): 18 of 20 blocked; the two allowed were `https://example.com` and `http://1.1.1.1`, as intended.

---

## 7. Not verified / not implemented

* **No egress proxy.** The mission asks for "outbound proxy/network policy where practical". No proxy is available in this environment, so egress is not restricted at the network layer. The application-layer checks above are the only control. In production, a forward proxy with a deny-by-default ACL is the recommended compensating control, and DNS egress should be restricted to that proxy.
* **No verification that the connected peer equals the vetted IP.** `httpx` connects to a hostname; this implementation validates and returns the IP, and the fetch loop uses the validated URL. Pinning the TCP peer to `VettedURL.ip` (a custom transport that dials the resolved IP) is the stronger form and is **NOT VERIFIED** here. Without it, a rebinding window remains between `validate_url` and the actual connect if the resolver is queried twice.
* **IPv6-only networks** are covered by the classifier but not exercised end-to-end here.
* **The sandbox has no network at all**, so workloads cannot perform SSRF; this design governs the API-side fetchers only.
