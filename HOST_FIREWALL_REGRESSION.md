# Host Firewall Regression — v0.2.5 Mission F

**Result: the v0.2.4 firewall is intact and still enforces. One genuine conflict with the egress proxy
was found, and it fails CLOSED.**

- Implementation: `scripts/skyla-host-firewall.sh` (unchanged in v0.2.5)
- Commit: v0.2.5 · Host: `e2b.local`, kernel 6.1.158+

---

## 1. Regression matrix

| Test | Expected | Result |
|---|---|---|
| Persistent rules present | `OUTPUT → SKYLA-EGRESS` jump | **PASS** |
| Chain terminates in `DROP` | terminal deny | **PASS** |
| Default deny (non-excepted destination) | blocked | **PASS** — `203.0.113.99`, `198.51.100.99` |
| IPv6 policy | denied | **PASS** |
| Rollback | prior state restored | **PASS** — `-P OUTPUT ACCEPT` |
| Re-apply after rollback | policy reinstated | **PASS** |
| Persistence file | `/etc/skyla-firewall.v4` valid | **PASS** |
| Gateway exception present | `10.201.0.2:8155` accepted | **PASS** |
| **Authorised egress end-to-end** | provider reachable | **FAIL** — see §3 |
| Direct egress denial | blocked | **PASS** |
| Proxy capability enforcement | wrong capability denied | **PASS** |
| API egress routing | API confined | **PASS** — perimeter `isolated: True` |

```
$ sudo scripts/skyla-host-firewall.sh verify
  PASS  203.0.113.99:443 blocked
  PASS  198.51.100.99:443 blocked
  PASS  ipv6 egress blocked
  PASS  OUTPUT jumps to SKYLA-EGRESS
  PASS  SKYLA-EGRESS ends in DROP
VERIFY: PASS
```

No firewall code was modified in this milestone. The ruleset was left in its v0.2.4 state and the backup
mechanism was not needed.

## 2. Capability enforcement unchanged

```
api-egress -> pypi.org        denied (not in the policy)        PASS
connector-google -> pypi.org  denied (ProxyError)               PASS
```

The proxy answers `403` with `X-Skyla-Egress: denied` for a disallowed destination — the capability layer is
functioning independently of the host policy.

## 3. The conflict: the firewall also blocks the proxy's own upstream

**This is the significant finding of Mission F.**

The egress proxy runs in the **host** namespace (`net:[4026531840]`, verified via `/proc/<pid>/ns/net`), not
in the gateway namespace. The `SKYLA-EGRESS` chain therefore applies to its own outbound connections, and the
chain has no rule permitting them.

Measured, with the firewall **active**:

```
CONNECT api.openai.com:443 (allowed host, valid api-egress capability)
  -> HTTP/1.1 403 Forbidden
  -> SKYLA egress denied: upstream unreachable
```

With the firewall **rolled back**:

```
CONNECT api.openai.com:443
  -> HTTP/1.1 200 Connection Established
```

Same client, same proxy, same capability, same host. The only variable is the host firewall.

### What this means

| Firewall | Direct egress | Proxy upstream | Provider access |
|---|---|---|---|
| active | **blocked** | **blocked** | none |
| lifted | allowed | allowed | works |

The two controls are **mutually exclusive for upstream reachability** on this host as configured. That is a
real defect in the composition, not a test artifact.

### Why it fails closed

The denial is on the *authorised* path. Nothing leaks: a workload still cannot reach the internet directly,
the perimeter still confines the API, and the capability layer still refuses wrong destinations. The failure
is availability, not confidentiality — the system refuses to do useful remote work rather than permitting
unaccounted egress. That is the correct direction, and it is why this is not a security regression.

### Attempted fixes and their outcomes

| Approach | Result |
|---|---|
| `-m owner --uid-owner <proxy uid> -j ACCEPT` | **unsupported** — `Extension owner revision 0 not supported` |
| `-m LOG` for diagnosis | unsupported (known since v0.2.4) |
| Run the proxy inside the gateway netns | the gateway namespace has **no internet route** (`gateway -> internet: BLOCKED`) |
| Allow the proxy's upstream by destination | would require enumerating provider IPs; brittle, and defeats the point |

The `owner` match is the natural fix and the kernel does not provide it. On a host with `xt_owner` the
firewall script would need one rule:

```sh
iptables -A SKYLA-EGRESS -m owner --uid-owner "$PROXY_UID" -j ACCEPT   # before the terminal DROP
```

That rule belongs **before** the `DROP`, and it grants the proxy — and only the proxy — upstream reachability
while every other host process stays denied.

## 4. Why this was not "fixed" by loosening the firewall

The tempting change is to widen the exception until the proxy works, e.g. allowing outbound 443 generally.
That would restore provider access and destroy the control: any process could then reach any host on 443.

The rule this project operates under — do not weaken a requirement to obtain a passing state — applies
directly. The conflict is recorded, the fail-closed direction is preserved, and the fix is specified for a
host whose kernel supports it.

## 5. Consequences for the release

| Item | Effect |
|---|---|
| Provider access with the firewall active | **unavailable** |
| Live connector validation (M4 of v0.2.4) | **still NOT VERIFIED**, and would fail closed on this host |
| Direct egress denial | unaffected |
| Perimeter enforcement | unaffected |
| Fail-closed direction | preserved |

This is recorded as **FW-01** in the evidence registry: the firewall and the proxy cannot both be satisfied on
this kernel, so a deployment must choose, and the choice must be explicit rather than emergent.

## 6. What was preserved

Per the mission's instruction not to modify host-wide rules without a preserved ruleset and verified
recovery:

- the ruleset was never edited in place;
- `backup` ran as part of every `apply`;
- `rollback` was exercised and verified before and after;
- `/etc/skyla-firewall.v4` and the systemd unit remain enabled;
- the final state was verified `PASS` after all testing.

## 7. Verdict

| Criterion | Status |
|---|---|
| Firewall behaviour intact | **PASS** |
| Default deny | **PASS** |
| IPv4 and IPv6 policies | **PASS** |
| Rollback and recovery | **PASS** |
| Proxy capability enforcement | **PASS** |
| API egress routing | **PASS** |
| Authorised gateway communication end-to-end | **FAIL (FW-01)** — firewall blocks the proxy's upstream |
| Recovery mechanism preserved and verified | **PASS** |
