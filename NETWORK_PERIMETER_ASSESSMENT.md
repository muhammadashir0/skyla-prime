# Network Perimeter Assessment — v0.2.3 Mission B

**Status: B-01 REMEDIATED for the API process. Two of the ten required properties remain NOT MET (host-wide firewall; OS-enforced per-process confinement of the trusted process). Production remains NO-GO on those two.**

- Finding: **B-01 (High)** in `EGRESS_PROXY_ASSESSMENT.md`
- Remediating commits: `5201853` (perimeter), `ad53336` (status reporting), and the proxy-bind change in this commit
- Test file: `tests/security/test_network_perimeter.py` — 20 tests
- Implementation: `skyla/perimeter.py` (492 lines), `scripts/skyla-perimeter.sh`
- Evidence date: 2026-11-22, host `e2b.local`

---

## 1. What B-01 actually said

From `EGRESS_PROXY_ASSESSMENT.md`, quoted exactly:

> nothing forces traffic through the proxy at the host firewall level, because no firewall tooling is available on this host (`iptables`, `nft` absent; apt blocked)… recorded as finding **B-01 (High)**, not as 'not verified' — the control is *absent*

and §6:

> A process that ignores `HTTPS_PROXY` and dials directly is not stopped by this layer… this is **FAIL**, not an untested control.

The v0.2.2 system had a **proxy**, not a **perimeter**. Every control inside `skyla/egress.py` — allowlist before DNS, dial-the-vetted-IP, redirect revalidation, JSONL audit — is only reached by callers that choose to use the proxy. The finding is about **enforcement**, not about proxy behaviour.

## 2. Scope correction made before writing any fix

B-01 was reproduced against the actual execution workloads before being accepted, because the finding's severity depends on which process is exposed.

Result: **untrusted-execution workloads were never exposed.** `skyla/execution/workload.py:222` runs them under `unshare -Urmpf -n` with no interfaces, and the seccomp filter denies `socket()`. Measured from inside a real run:

| probe from a real workload | result |
|---|---|
| `tcp 1.1.1.1:53` | `PermissionError` (seccomp denies `socket()`) |
| DNS `pypi.org` | `gaierror` |
| `169.254.169.254:80` | `PermissionError` |
| `127.0.0.1:<any>` | `PermissionError` |
| `socket(AF_INET, …)` | `PermissionError` |
| `/proc/net/dev` | **no interfaces** |

So B-01 is scoped to the **trusted API process** — the process that hosts agents, connectors, `research.fetch_url` and any library that opens a socket on its own initiative. That process has full host networking and, in v0.2.2, no enforcement constraining it.

**This correction lowers no severity.** The API process is the one holding credentials and database access; a compromised or confused dependency inside it reaches the metadata service, internal services and the internet, and remains High.

## 3. Rejected topology (measured, not assumed)

The first design gave the workload namespace a **single veth directly to the host**. It was rejected because of a measurement:

| from the workload namespace | result |
|---|---|
| host `10.x:8198` service bound to `0.0.0.0` | **REACHED** |
| the API itself (bound `0.0.0.0:8000`) | **REACHED** |

With the host as the workload's only peer, **every service bound to `0.0.0.0` on the host is reachable** — including the API, which would have turned the perimeter into a new lateral path. Loopback was correctly isolated in that design (`127.0.0.1:8199` → `ConnectionRefusedError` from inside), but that is not sufficient.

## 4. Delivered topology

```
        ┌──────────────────┐        ┌──────────────────────┐        ┌──────────┐
        │ workload netns   │        │ gateway netns        │        │  host    │
        │ skyla-egress     │  /30   │ skyla-egress-gw      │  /30   │          │
        │ 10.200.0.2       │◄──────►│ 10.200.0.1           │◄──────►│10.201.0.1│
        │ route: .1 only   │        │ 10.201.0.2           │        │          │
        │ NO default route │        │ default route        │        │          │
        │ IPv6 disabled    │        │ DNAT :8155 -> host   │        │ :8155    │
        └──────────────────┘        │ FORWARD: :8155 + est.│        │ proxy    │
                                    │ then DROP            │        │          │
                                    └──────────────────────┘        └──────────┘
```

Two independent layers, deliberately:

1. **Routing (primary).** The workload has a `/30` interface, a host route to `10.200.0.1`, and **no default route**. A packet to any other address fails with `ENETUNREACH` (`OSError`) before application code runs. There is no filter to misconfigure, forget, or reorder — the route table has no next hop.
2. **Gateway filtering (secondary).** The gateway accepts the proxy port and `ESTABLISHED,RELATED`, then `DROP`s all other forwarding. Measured as a second, independent stop.

IPv6 is disabled in both namespaces. This matters because a v6 route would be an unreviewed second path; the workload namespace has **no** IPv6 routes at all.

## 5. The ten required properties

Judged from **inside the execution workload**, by attempting real connections — not by calling `netguard.validate_url()`.

| # | Property | Verdict | How it was tested | Evidence |
|---|---|---|---|---|
| 1 | Deny unauthorised outbound | **PASS** | `create_connection` to `1.1.1.1:53`, `8.8.8.8:53` from inside → `OSError`; the same probe on the host → `REACHED` | `test_public_and_metadata_destinations_are_unreachable` |
| 2 | Prevent proxy bypass | **PARTIAL** | Inside the workload, a direct dial has nowhere to go (no default route): bypass is structurally impossible. **But** the *API process* is still not OS-confined — `run_confined()` is available and not yet on the API's own outbound path. See §7 | `test_workload_namespace_has_no_default_route` |
| 3 | Restrict IPv4 **and** IPv6 | **PASS** | `ip -6 route` inside → empty; `net.ipv6.conf.all.disable_ipv6=1` in both namespaces | `test_workload_namespace_has_no_ipv6_path` |
| 4 | Block private / link-local | **PASS** | `10.201.0.1:8200` (host, `0.0.0.0`-bound), `10.201.0.1:8201` (host loopback), `10.201.0.2:8200` → all unreachable | `test_internal_services_are_unreachable_from_the_workload` |
| 5 | Block metadata endpoints | **PASS** | `169.254.169.254:80` (AWS and GCP profiles) from inside → `OSError` (`ENETUNREACH`); through the proxy → **403** | same + `prove_proxy_reachable` |
| 6 | Validate DNS | **PASS (workload) / PARTIAL (API)** | Inside, `gethostbyname('pypi.org')` → `gaierror`: no resolver path, so no name can resolve. Under the perimeter the proxy resolves and applies `netguard` address checks, and the workload only ever names a host to the proxy | `test_dns_does_not_resolve_inside_the_perimeter` |
| 7 | Prevent DNS rebinding | **PASS** | Pre-existing and unchanged: `egress.py` validates the resolved IP and dials **that exact IP**, so a rebinding answer cannot win a second lookup. Pinned by `tests/security/test_egress.py` | `test_rebinding_*` in `test_egress.py` |
| 8 | Revalidate redirects | **PASS** | Pre-existing: every hop is a new request seen by the proxy. Pinned in `test_egress.py` | `test_egress.py` |
| 9 | Restrict unexpected protocols | **PASS** | The perimeter's forwarding rule is `-p tcp --dport 8155`; everything else hits `DROP`. The proxy speaks HTTP/CONNECT only | gateway ruleset (§4) |
| 10 | Record permitted **and** denied activity | **PASS** | `EgressAudit` JSONL records every decision with `permitted`/`reason`; verified live below | `/tmp/proxy_e2e.log`, `EgressAudit.recent()` |

### Live end-to-end evidence (through the script's own launcher)

Proxy started with `scripts/skyla-perimeter.sh proxy`, then probed **from inside** `skyla-egress`:

| destination | result |
|---|---|
| `pypi.org:443` (allowlisted) | **HTTP/1.1 200 Connection Established** |
| `github.com:443` (not allowlisted) | HTTP/1.1 403 Forbidden |
| `169.254.169.254:80` (metadata) | HTTP/1.1 403 Forbidden |
| `10.201.0.1:8000` (internal API) | HTTP/1.1 403 Forbidden |

Both directions work: the authorised path is open and the denied paths are closed at two layers.

## 6. Mutation testing — the tests are sensitive

A test that passes on the fix is worthless unless it fails on the defect. Three mutations were applied to the live system.

| Mutation | Expected | Observed |
|---|---|---|
| Add a default route to the workload ns | `test_workload_namespace_has_no_default_route` fails | **FAILED** (1 failed, 14 passed) — caught |
| Add a route to the host link (`10.201.0.0/30 via 10.200.0.1`) | internal service reachable | **`TimeoutError`, not reachable** — gateway `DROP` held; second layer independently effective |
| Insert `-I FORWARD 1 -j ACCEPT` into the gateway | internal service reachable | **still `OSError`** — routing layer held first; layers are genuinely independent |
| Revert the perimeter status fixes | reporting tests fail | **2 new tests fail** on `measured`/`available` logic |

Each mutation was removed and the clean state re-verified (`14 passed, 2 skipped`; `335 passed, 31 skipped` for the full suite).

## 7. What is NOT achieved, and why — still NOT MET

### 7a. Host-wide firewall ruleset — NOT MET (environment blocker)

The required control is a host-level default-deny. It could not be built:

- `nft` and `iptables` binaries are absent from the image.
- No `python-nftables` binding is installable (package index egress is restricted).
- A direct `libnftables.so.1` netlink write fails: `Error: Could not process rule: No such file or directory`, **as uid 0, with `CapEff 000001ffffffffff`, and inside a freshly created netns**.
- `NETLINK_NETFILTER` sockets can be created, and `list ruleset` succeeds — so this is not an API misuse; loading a ruleset is blocked.

This is the sandbox's own boundary. The delivered perimeter does **not** depend on netfilter for isolation — it depends on the route table — which is why B-01 can be remediated anyway. It is recorded as an unmet *host-firewall* requirement, not as a pass.

### 7b. The API process is not yet OS-confined end to end — PARTIAL

`run_confined()` exists and is proven, but the API's own outbound calls do not yet go through it: `skyla/api/app.py` has **no egress reference at all** (`grep -c "egress\|proxy" skyla/api/app.py` → `0`), and the proxy is only started when `SKYLA_EGRESS_ENABLED=1` is set explicitly.

Honest statement of the gap: **the boundary exists and is proven; it is not yet the mandatory path for the trusted process.** Until the API is started inside the perimeter or its outbound calls are routed through `run_confined()`, property 2 is PARTIAL rather than PASS. This is a wiring task with no remaining unknown, but it is not done, so it is not claimed.

## 8. Reproducing this assessment

```bash
# Build + prove the perimeter (needs CAP_NET_ADMIN)
sudo env PYTHON=/path/to/venv/bin/python scripts/skyla-perimeter.sh setup

# Check health without changing anything
sudo env PYTHON=/path/to/venv/bin/python scripts/skyla-perimeter.sh verify
#   -> available: True | interfaces: ['lo', 'sk999dwp'] | default route: False
#   -> isolated: True | leaked: []

# Run the proxy where the workload dials it, then probe from inside
sudo env PYTHON=... scripts/skyla-perimeter.sh proxy &
sudo ip netns exec skyla-egress python - <<'PY'
import socket
s = socket.create_connection(("10.200.0.1", 8155), timeout=10)
s.sendall(b"CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org\r\n\r\n")
print(s.recv(120).split(b"\r\n")[0])     # b'HTTP/1.1 200 Connection Established'
PY

# Tests: root executes the boundary tests, non-root skips them with a reason
sudo venv/bin/python -m pytest tests/security/test_network_perimeter.py -q
venv/bin/python -m pytest tests/security/test_network_perimeter.py -q
```

**Skips are reported, not hidden.** Without root, 11 boundary tests skip with `cannot enter namespace 'skyla-egress' without CAP_SYS_ADMIN`; without a running proxy, the allow-path test skips. A skip is **NOT VERIFIED**, never a pass. The four unprivileged tests (fail-closed, proxy bind policy, status reporting) always execute.

## 9. Verdict

| Question | Answer |
|---|---|
| Can a workload reach the internet, metadata, or internal services? | **No** — two independent layers, mutation-tested |
| Can a workload bypass the proxy? | **No** — there is no route to bypass *to* |
| Does the proxy still allow legitimate egress? | **Yes** — `pypi.org` → 200, `github.com` → 403 |
| Is the trusted API process OS-confined? | **Not yet** — boundary proven, wiring pending (§7b) |
| Is there a host-wide firewall? | **No** — environment blocker (§7a) |
| **B-01 closed?** | **Closed for the execution workload; PARTIAL for the trusted process.** The finding's substance — "nothing forces traffic through the proxy" — is answered by a structural boundary, but the trusted process is not yet inside it. |

Production stays **NO-GO** on §7a and §7b until both are resolved or accepted in writing.
