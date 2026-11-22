# Egress Gateway Deployment — v0.2.3

How to deploy the API so that its outbound traffic cannot bypass the approved gateway. Written to be followed literally; every command below was executed in this form.

---

## 0. Prerequisites

| Requirement | Check | If absent |
|---|---|---|
| Linux with network namespaces | `ip netns add t && ip netns del t` | not deployable |
| `CAP_NET_ADMIN` (root or `sudo`) for setup only | `sudo -n true` | setup only; the service itself runs unprivileged |
| `iptables` present | `sudo sh -c 'command -v iptables'` | gateway forwarding unavailable — see §7 |
| Python venv with the project installed | `venv/bin/python -c "import skyla"` | `pip install -e ".[dev]"` |

`iptables` and `nft` live in `/usr/sbin`, which is **not** on an unprivileged `PATH`. Check with `sudo sh -c 'command -v iptables'`, not `command -v iptables`.

## 1. One-time: build and prove the perimeter

```bash
sudo env PYTHON=/path/to/venv/bin/python scripts/skyla-perimeter.sh setup
```

Expected tail:

```
inside:
  public_dns       OSError
  public_dns2      OSError
  metadata_aws     OSError
  metadata_gcp     OSError
host control:
  public_dns       REACHED
  ...
host_has_network: True
leaked           : []
ISOLATED         : True
```

`host control` must be `REACHED` for the probe targets — that is what proves "blocked" is the perimeter and not an offline host. If `leaked` is non-empty, **stop**: the boundary is not holding.

Check health at any time without changing anything:

```bash
sudo env PYTHON=... scripts/skyla-perimeter.sh verify
# available: True | interfaces: ['lo', 'sk999dwp'] | default route: False
# isolated: True | leaked: []
```

## 2. Start the egress proxy

```bash
sudo env PYTHON=/path/to/venv/bin/python \
     SKYLA_EGRESS_SECRET="$(openssl rand -hex 16)" \
     scripts/skyla-perimeter.sh proxy
```

It prints:

```
egress proxy on 10.201.0.1:8155 policy=api-egress (reachable from the workload as 10.200.0.1:8155)
```

Why the proxy is on `10.201.0.1` and not loopback: the workload's only peer is the gateway, which DNATs port 8155 to that address. Bound to loopback it would be unreachable from inside; bound to `0.0.0.0` it would be an open relay for the whole host — `proxy_from_env()` now raises rather than allow that.

The secret is optional. With `SKYLA_EGRESS_SECRET` set, a process that guesses a capability name but not the secret is denied. In production, set it, and pass the same value to the API process.

## 3. Start the API inside the perimeter

```bash
sudo ip netns exec skyla-egress \
  setpriv --reuid=1001 --regid=1001 --clear-groups --inh-caps=-all --bounding-set=-all \
  sh -c 'cd /path/to/skyla-prime && \
         SKYLA_EGRESS_MODE=enforce \
         SKYLA_EGRESS_SECRET=... \
         /path/to/venv/bin/python -m uvicorn skyla.api.app:app \
             --host 10.200.0.2 --port 8080'
```

- `setpriv … --inh-caps=-all --bounding-set=-all` drops every capability. `ip netns exec` needs `CAP_SYS_ADMIN`; the service does not, so it must not keep it.
- `--host 10.200.0.2` binds inside the namespace. A `0.0.0.0` bind here means the namespace address only, since there is no other interface.
- `SKYLA_EGRESS_MODE=enforce` is the default when the perimeter is present; stating it makes intent explicit.

**Startup must print `namespaced: True`:**

```
egress route confirmed: {'mode': 'enforce', 'proxy': 'http://10.200.0.1:8155',
                         'namespaced': True, 'netns_inode': 'net:[4026532280]',
                         'policy': 'api-egress', 'enforced': True}
```

If it prints `namespaced: False`, the process is not confined. In `enforce` mode it will refuse to start if it can reach the internet directly — that refusal is the control, not a misconfiguration to work around.

## 4. Verify the deployment

```bash
API_PID=$(pgrep -f "uvicorn skyla.api.app:app --host 10.200.0.2")

# Exactly one reachable destination, and it is the proxy
sudo nsenter -t $API_PID -n python3 -c "
import socket
for h,p in [('1.1.1.1',53),('169.254.169.254',80),('10.201.0.1',8200),('10.200.0.1',8155)]:
    try: socket.create_connection((h,p),timeout=3); print(f'{h}:{p} REACHED')
    except Exception as e: print(f'{h}:{p} {type(e).__name__}')"

# Expected: three failures, then 10.200.0.1:8155 REACHED
```

## 5. Operator checklist

| # | Check | Expected | If not |
|---|---|---|---|
| 1 | `scripts/skyla-perimeter.sh verify` | `available: True`, `isolated: True` | re-run `setup` |
| 2 | proxy listening on `10.201.0.1:8155` | `ss -tln` shows it | start it; do not start the API without it |
| 3 | API startup log | `namespaced: True`, `enforced: True` | the process is not confined; fix the launch command |
| 4 | `nsenter` probe | only `10.200.0.1:8155` reachable | **stop**; the boundary is broken |
| 5 | API uid | `1001` (unprivileged) | `setpriv` was omitted |
| 6 | API reachable by clients | via reverse proxy (§6) | the API is namespace-private by design |

## 6. Exposing the API to clients

The API is not reachable from the host by design (`curl http://10.200.0.2:8080` → `000`). To serve clients, run a reverse proxy on the host whose upstream is the namespace address:

```nginx
# host nginx — INBOUND only; egress policy unchanged
location / {
    proxy_pass http://10.200.0.2:8080;
}
```

The host needs a route to `10.200.0.2`. Add it to the **gateway** namespace (which owns that link) rather than opening the workload namespace:

```bash
sudo ip netns exec skyla-egress-gw ip route add 10.200.0.0/30 dev <gw-if>
```

This keeps outbound traffic on the one permitted path while allowing inbound connections. Not implemented in this milestone; documented so the absence is visible.

## 7. If `iptables` is unavailable

The perimeter's isolation does **not** depend on iptables — it depends on having no default route. Without `iptables`, `setup` fails at the gateway forwarding steps, which means the proxy is unreachable from inside and the API refuses to start (correctly).

Options, in order of preference:
1. Install `iptables` (Debian: `apt-get install iptables`).
2. Do not deploy the namespace; run with `SKYLA_EGRESS_MODE=policy`, which enforces per-capability policy through the proxy **without** a network boundary. **This is a weaker configuration** and must be recorded as such — it is Option B without Option A, i.e. exactly the v0.2.2 posture that B-01 was raised against.

Option 2 exists for development. It must never be presented as equivalent to the perimeter.

## 8. Teardown

```bash
sudo env PYTHON=... scripts/skyla-perimeter.sh destroy
```

Terminates any process still inside the namespace first. To leave them alone (they will be stranded):

```bash
sudo python -c "
from skyla.perimeter import EgressPerimeter
EgressPerimeter('skyla-egress').destroy(kill_members=False)"
# reason: 'N process(es) remain inside ... and will lose all network reachability'
```

## 9. Failure behaviour you should expect

| Event | Behaviour | Action |
|---|---|---|
| Proxy dies | every protected operation raises `EgressUnavailable` | restart the proxy; no API restart needed |
| Perimeter removed at runtime | detected on the next client, refused | rebuild; **restart the API** (it is stranded) |
| API started without the boundary | refuses to start | start it inside the namespace |
| Deep code error (nothing else works) | diagnose with `scripts/skyla-perimeter.sh verify` | do **not** set `SKYLA_EGRESS_MODE=policy` to "unblock" — that removes the control |
