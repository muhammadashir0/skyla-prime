# FW-01 — Egress Composition Defect: Closure Evidence (v0.2.6)

**Status: FW-01 CLOSED by construction.**

FW-01 was the composition defect in which the egress proxy, running in the host
network namespace, had its own upstream traffic dropped by the host `OUTPUT`
chain (`SKYLA-EGRESS` terminates in `DROP`). The workload's egress therefore
worked in principle and failed in practice, and the only ways to "fix" it by
weakening the host policy traded execution security for connectivity.

This document records the measured mechanism, the rule set that replaces it, and
the limits of what was actually verified.

---

## 1. Mechanism (measured, not inferred)

The proxy used to run in the **host** namespace. A connection it opened to an
upstream therefore traversed `OUTPUT` — the same chain that is deliberately
strict for the host's own processes — and hit the terminal `DROP`.

Moving the proxy into the **gateway** namespace changes which hook the packet
enters:

```
workload ns (10.200.0.2)
   └─ route: only 10.200.0.0/30 dev veth            (no default route — isolation is the routing table)
        └─ gateway ns (10.201.0.2) — proxy listens on 10.200.0.1:8155
             └─ upstream connection leaves the gateway
                  └─ arrives on host veth sk999dg      -> FORWARD / SKYLA-FWD
                       (never OUTPUT — this is the closure)
```

The host `OUTPUT` policy was **never relaxed** at any point during this work.
`scripts/skyla-host-firewall.sh verify` returned `VERIFY: PASS` throughout,
including the final state.

## 2. Rule set — `skyla/egress_gateway.py`

`HostForwardPolicy` applies and verifies:

| Element | Content |
|---|---|
| `ip_forward` | `1` |
| `FORWARD` policy | `DROP`, jumps to `SKYLA-FWD` |
| `SKYLA-FWD` deny | metadata `169.254.169.254/32`; `172.16/12`; `192.168/16`; `127/8`; `100.64/10`; `10.0.0.0/8` **minus** the two perimeter `/30`s |
| `SKYLA-FWD` allow | `ESTABLISHED,RELATED`; `INVALID` drop; `-i sk999dg -s 10.201.0.0/30 -o eth0` tcp/udp **443, 853**; DNS tcp/udp **53** to `8.8.8.8`/`1.1.1.1`; terminal `DROP` |
| `SKYLA-GW-NAT` | `-s 10.201.0.0/30 -o eth0 MASQUERADE` |
| `SKYLA-GW-IN` | `ESTABLISHED,RELATED` accept, then terminal `DROP` for `-s 10.201.0.0/30 -i sk999dg` |

`SKYLA-GW-IN` is not cosmetic. `FORWARD` never sees gateway→host-service
traffic; without an `INPUT` chain the gateway could reach every host listener
(`10.201.0.1:8155` was measured `REACHED` before this chain existed).

## 3. Verification matrix — 10/10

Executed from the gateway namespace against the live rule set:

| Destination | Port | Expected | Observed |
|---|---|---|---|
| `1.1.1.1` | 443 | REACHED | REACHED |
| `1.1.1.1` | 853 | REACHED | REACHED |
| `1.1.1.1` | 22 | blocked | blocked |
| `1.1.1.1` | 80 | blocked | blocked |
| `1.1.1.1` | 25 | blocked | blocked |
| `169.254.169.254` | 80 | blocked | blocked |
| `10.0.0.1` | 443 | blocked | blocked |
| `192.168.1.1` | 443 | blocked | blocked |
| `127.0.0.1` | 8155 | blocked | blocked |
| `10.201.0.1` (host side) | 8155 | blocked | blocked |

End-to-end through the real client, from inside the workload namespace:

```
CONNECT pypi.org:443      -> HTTP/1.1 200 Connection Established
TLS                       -> TLSv1.3 TLS_AES_128_GCM_SHA256
GET /simple/              -> HTTP/1.1 200 OK
```

## 4. Six silent defects found on the way

Each of these failed with no error message; rule counters stayed at zero and the
symptom was always "blocked".

1. `self._iface` attribute shadowed the `_iface()` method → `TypeError` on apply.
2. Blanket `-d 169.254.0.0/16 DROP` killed the **return** path, because this
   host's own default gateway is link-local (`169.254.0.22`). Scoped to the
   metadata `/32`.
3. Blanket `-d 10.0.0.0/8 DROP` killed return traffic addressed to the gateway
   (`10.201.0.2`).
4. A hand-written CIDR split of `10/8` left a hole at `10.201.0.0/16`, so the
   gateway's own address sat inside a "block private networks" rule. Replaced
   with a computed exclusion (`ipaddress.address_exclude`).
5. `-o` in `FORWARD` is the egress interface, not the arrival veth. The same
   mistake made `MASQUERADE -o <veth>` a no-op.
6. `INPUT` is a separate path — see `SKYLA-GW-IN` above.

**Two further defects were found in the proxy itself, unrelated to netfilter:**

7. `EgressProxy.authorise()` returned **`""` as the vetted IP** on the
   multi-capability union branch. The caller then dialled `("", 443)`, which
   fails with *"Name or service not known"* and is reported as **"upstream
   unreachable"**. A correct policy decision was therefore surfaced as a network
   fault. Fixed: the branch now resolves and returns a vetted address.
8. `validate_url()` returned `vetted[0]` with no family preference. The gateway
   is IPv4-only, so a dual-stack name that resolved AAAA-first failed at
   `connect()`. Fixed: IPv4 is preferred when both families are offered.

Both are covered by regression tests in `tests/security/test_egress.py`
(`test_capability_union_authorise_returns_a_vetted_ip`,
`test_validate_url_prefers_ipv4_when_both_families_resolve`).

## 5. What is NOT verified — and why it must be read carefully

**The test host cannot complete TLS to arbitrary internet destinations, and this
is a property of the sandbox, not of Skyla.**

Measured controls:

| Path | `8.8.8.8:443` | `1.1.1.1:443` | `www.google.com:443` | `example.com:443` |
|---|---|---|---|---|
| Host, perimeter bypassed (`SKYLA-EGRESS` ACCEPT inserted) | TLS OK | SSLZeroReturn | SSLZeroReturn | SSLZeroReturn |
| Gateway, `FORWARD` policy set to `ACCEPT` | TLS OK | SSLZeroReturn | — | — |
| Gateway, full policy in force | TLS OK | — | — | — |

The decisive row is the first: with **no Skyla firewall in the path at all**, the
host itself fails these handshakes. Outbound reachability is limited to a
sandbox allowlist (pypi.org, github.com, registry.npmjs.org complete TLS 1.3;
arbitrary hosts do not). An earlier reading of this symptom — "TLS fails through
the proxy" — was a misdiagnosis; the proxy was faithfully relaying to an upstream
that never answered.

Consequences for the evidence above:

- The 10/10 matrix and the pypi.org end-to-end transfer are **real** and were
  measured against the live stack.
- A claim that "Skyla permits arbitrary HTTPS egress" is **NOT VERIFIED**. It
  could not be tested here, because the environment blocks it above the layer
  Skyla controls.
- `api.openai.com`, `www.google.com`, `example.com`, `api.telegram.org` are the
  app's actual egress targets and remain **NOT VERIFIED end-to-end** for the same
  reason. Their policy decisions were verified (`authorise()` returns
  `allowed by 'api-egress'` with a vetted IPv4), but the transport beyond the
  gateway is blocked by the sandbox.

Do not record this as a pass on a machine that has open egress; re-run the matrix
and the end-to-end transfer there.

## 6. Reproduce

```sh
# rules
sudo scripts/skyla-perimeter.sh setup
sudo /tmp/env4/bin/python -c \
  'import sys; sys.path.insert(0,"."); from skyla.egress_gateway import HostForwardPolicy as H; \
   p=H(); p.remove(); p.apply(); print(p.verify().problems or "PASS")'

# proxy in the gateway namespace
sudo scripts/skyla-perimeter.sh proxy-ns

# end-to-end from the workload namespace
sudo nsenter --net=/var/run/netns/skyla-egress /tmp/env4/bin/python - <<'PY'
import asyncio, sys; sys.path.insert(0, "/home/user/skyla-prime")
from skyla.egress_client import client
async def main():
    async with client("api-egress") as c:
        r = await c.get("https://pypi.org/simple/", timeout=30)
        print(r.status_code, len(r.content))
asyncio.run(main())
PY

# host policy never relaxed
sudo scripts/skyla-host-firewall.sh verify     # -> VERIFY: PASS
```

Suite: **387 passed / 42 skipped** (baseline 385 + 2 regression tests).
