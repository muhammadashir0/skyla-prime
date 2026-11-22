# API Network Isolation Design — v0.2.3 Mission 2

**Decision: Option A (API inside the restricted namespace) as the enforcement boundary, with Option B's broker pattern already realised by the existing proxy — combined, because neither alone answers B-01.**

- Selected after measuring both, at commit `5bace07`
- Test surface: `tests/security/test_api_egress.py` (22 tests)

---

## 1. What the two options actually protect

| | Option A — API in a namespace | Option B — dedicated outbound broker |
|---|---|---|
| Enforces against | **any** code in the process, including a compromised dependency | only code that calls the broker |
| Bypass possible by | nothing — there is no route | a direct socket, or a library that ignores the broker |
| Needs | CAP_NET_ADMIN once at deploy | a broker and a mandatory call path |
| Failure mode | process has no network at all | process has full network unless disciplined |

**Option B alone is what v0.2.2 shipped**, and it failed for exactly the reason the table shows: `skyla/egress.py` was a perfectly good broker that nobody was required to call. Eleven call sites bypassed it. A broker without a boundary is a convention.

**Option A alone is insufficient too**, for a subtler reason: a namespace with a default route to the gateway lets the workload reach *anything the gateway will forward*. Without a broker applying per-destination policy, the gateway would be an unrestricted router. The gateway's `FORWARD` chain does filter, but host/port allowlisting at that layer is coarse and expressed in iptables — hard to review, harder to test per capability.

So the design is **A for the boundary, B for the policy**:

```
   ┌─────────────────────── netns skyla-egress ────────────────────────┐
   │  uvicorn (uid 1001, caps dropped)                                 │
   │    └── skyla/egress_client.py ── only way to get a client ──┐     │
   │         route: 10.200.0.1 only, no default route, no IPv6   │     │
   └─────────────────────────────────────────────────────────────┼─────┘
                                                                 │ CONNECT
   ┌──────────────── netns skyla-egress-gw ──────────────────────▼─────┐
   │  DNAT tcp:8155 → host ; FORWARD: 8155 + established, then DROP    │
   └─────────────────────────────────────────────────────────────┬─────┘
                                                                 │
   ┌──────────────────────────── host ───────────────────────────▼─────┐
   │  egress proxy on 10.201.0.1:8155                                  │
   │    · Proxy-Authorization → capability → that policy ALONE         │
   │    · netguard: resolve, classify, dial the vetted IP              │
   │    · JSONL audit of every permit and denial                       │
   └───────────────────────────────────────────────────────────────┬───┘
                                                                   │
                                                              internet
```

## 2. Why each layer is load-bearing

The design was tested by removing each layer in turn (Mission 7). Each one stops an attack the others do not:

| Attack | Stopped by | Independent proof |
|---|---|---|
| A dependency opens a socket to `1.1.1.1` | **routing** — no default route | `test_the_api_namespace_cannot_reach_the_internet_directly`: `OSError` |
| A dependency reaches the metadata service | **routing** | same test: `OSError` for `169.254.169.254` |
| A dependency reaches the host API on `0.0.0.0:8000` | **routing**, then gateway `DROP` | `test_the_api_namespace_cannot_reach_internal_services` |
| A caller uses the proxy with the wrong capability | **proxy policy** | `google -> pypi` → 403 (Mission 4 sweep) |
| A policy is widened to a private IP by mistake | **netguard address check** | pinned by `test_a_widened_policy_still_cannot_reach_a_private_address` |
| A redirect points at an internal host | **`follow_redirects=False`** + per-hop re-vetting | `test_the_client_is_bound_...` asserts `follow_redirects is False` |
| `HTTPS_PROXY` is set to an attacker's proxy | **`trust_env=False`** | same test asserts `trust_env is False` |
| A process is started without the boundary | **startup refusal** | `RuntimeError` before serving (Mission 6) |

Removing the routing layer while keeping the firewall still blocked internal services in testing — but only because the gateway `DROP` caught it. Removing both is caught by the namespace tests. **No single layer is claimed sufficient; each is claimed necessary.**

## 3. The one-way client factory

`skyla/egress_client.py` is the design's central mechanism. Its contract:

```python
client("research")          # -> AsyncClient proxied to the gateway, capability-stamped
client("connector-google")  # -> same transport, Google-only policy
client("something-new")     # -> deny-all policy, not a permissive default
```

Properties enforced inside it, none optional:

1. **Proxy fixed to the gateway.** No parameter allows another destination.
2. **`trust_env=False`.** httpx honours `HTTP(S)_PROXY` from the environment by default; a stray variable would redirect every call.
3. **`follow_redirects=False`.** Redirects are re-vetted hop by hop by `research.fetch_url`; auto-following would let the first hop's approval carry an unvetted second hop.
4. **Capability stamped per call**, carried in `Proxy-Authorization` (see §4).
5. **Boundary proof in `enforce` mode:** gateway reachable **and** direct internet unreachable. If the internet *is* reachable, that is raised as an error — the perimeter is not doing its job and continuing would be the silent-success pattern.
6. **Refusal, never fallback.** `EgressUnavailable` is raised. There is no `try/except` anywhere in the codebase that converts it into a working client.

### Mode selection cannot be downgraded from inside

| Caller state | `resolve_mode()` | May it select `policy`? | May it select `legacy`? |
|---|---|---|---|
| Inside the perimeter | `enforce` | **No** — refusing | **No** — refusing |
| Host, perimeter installed | `enforce` | Yes, explicitly | No |
| Host, no perimeter | `policy` | Yes | Only with a second declaration |

Measured on the live unprivileged API: `policy → REFUSED`, `legacy → REFUSED`, `enforce → enforce`.

## 4. Why capability travels in `Proxy-Authorization`

**Measured, not assumed.** A custom `X-Skyla-Capability` header was tried first and the proxy logged `keys=['accept', 'host']` — httpx forwards only those two headers on a `CONNECT`. For HTTPS, which is every destination in the inventory, the capability would have been silently absent exactly where it was needed.

`Proxy-Authorization` is part of the CONNECT handshake, so it survives. Format: `Basic base64("<capability>:<secret>")`. The username names the policy; the password is a shared secret so an arbitrary process on the host cannot borrow a capability by naming it. `require_auth=True` makes an unstamped request a **denial** rather than a fall-through to the default policy.

Worth stating plainly: without this, "wrong capability denied" could not be distinguished from "default policy happened to deny it", and every scoping claim in §5 would have been hollow.

## 5. Capability scoping

| Capability | Hosts | Methods | Rationale |
|---|---|---|---|
| `research` | `*.wikipedia.org`, `wikipedia.org`, `example.com`, `*.example.com`, `pypi.org`, `files.pythonhosted.org` | GET, HEAD | reads untrusted documents |
| `model-provider` | `api.openai.com`, `api.deepseek.com`, `dashscope.aliyuncs.com`, `api.z.ai` | GET, POST | spends money, holds an API key |
| `connector-google` | `oauth2.googleapis.com`, `www.googleapis.com`, `gmail.googleapis.com`, `www.google.com`, `accounts.google.com` | GET, POST, PUT, PATCH | Gmail + Calendar + OAuth |
| `connector-telegram` | `api.telegram.org` | GET, POST | messaging |
| `deny-all` | *(empty)* | — | the default, and what an unknown name gets |

Separate policies exist because the capabilities are separate risks. `research` reads attacker-influenced content; `model-provider` holds the key that costs money. One policy would let a compromised fetcher inherit the spender's reach.

**There is no wildcard policy.** `test_there_is_no_wildcard_policy` asserts that no policy contains `*`, because one would make every other assertion meaningless.

## 6. Internal communication

The API needs no inbound route: it serves `10.200.0.2:8080` inside the namespace and nothing dials it from the host. Verified from the host: `curl http://10.200.0.2:8080/api/health` → `000` (unreachable). From inside: `200`.

For a deployment that must expose the API, the correct pattern is a reverse proxy on the host whose *upstream* is a static route to `10.200.0.2:8080` — inbound only, with the host's default-deny policies unchanged. That is not implemented here; it is stated so the gap is not mistaken for completeness.

SQLite and the audit log are file I/O and unaffected by the network namespace.

## 7. What this design does not do

| Not done | Why | Consequence |
|---|---|---|
| Host-wide default-deny egress | The API is confined; other host processes are not | A different process on this host still has free egress. NET-23 remains open. |
| Namespace for the `local` execution provider | `sandbox.py` inherits host networking; changing it alters an execution contract outside B-01 | Recorded as open in the inventory §4 |
| Inbound exposure for the API | Out of scope for an egress finding | Deployment must add a reverse proxy |
| Custom model endpoint support | Private LAN addresses are blocked by design | Operator must edit the policy; documented, not silently allowed |

## 8. Reproduction

```bash
sudo env PYTHON=... scripts/skyla-perimeter.sh setup        # once
sudo env PYTHON=... scripts/skyla-perimeter.sh proxy &      # broker on the gateway's host side
sudo ip netns exec skyla-egress setpriv --reuid=1001 --regid=1001 \
     --clear-groups --inh-caps=-all --bounding-set=-all \
     sh -c 'cd /repo && SKYLA_EGRESS_MODE=enforce \
            python -m uvicorn skyla.api.app:app --host 10.200.0.2 --port 8080'
```

Startup log must show `namespaced: True`. If it shows `False`, the process is not confined and `enforce` will refuse — that refusal is the control working, not a misconfiguration to route around.
