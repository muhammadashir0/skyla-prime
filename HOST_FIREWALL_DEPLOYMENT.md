# Host Firewall Deployment — v0.2.4 Mission 2 (NET-23)

**NET-23 is now implemented and verified on this host.** A default-deny host egress policy is deployed, persisted across reboot, and proven to compose with the namespace perimeter rather than conflict with it.

- Implementation: `scripts/skyla-host-firewall.sh` (commit `067bdf0`)
- Host: `e2b.local`, Debian 12, kernel 6.1.158+, `iptables` v1.8.9 (nf_tables backend)

---

## 1. Correction to the record

Earlier revisions classified NET-23 as impossible:

> No `nft`/`iptables` binary; no installable binding; direct `libnftables.so.1` netlink write returns `Could not process rule`

**That was wrong, and the cause was mundane:** both binaries live in `/usr/sbin`, which is not on an unprivileged `PATH`. `command -v iptables` returns nothing; `sudo sh -c 'command -v iptables'` returns `/usr/sbin/iptables`. The earlier `libnftables` experiment additionally targeted the `inet` family, which this kernel does not support — while the `ip` family (which `iptables-nft` actually uses) works fine.

The distinction matters for this release: "impossible" closed the item; "not deployed" left it as work with a known path. It is now done.

## 2. Policy

The policy is a dedicated chain `SKYLA-EGRESS`, jumped from `OUTPUT` at position 1, terminating in `DROP`.

| Rule | Purpose |
|---|---|
| `-o lo ACCEPT` | loopback: the API, database and proxy all use it |
| `-m conntrack --ctstate ESTABLISHED,RELATED ACCEPT` | without it the policy permits one packet per conversation and every reply is dropped |
| `-p tcp --dport 22 ACCEPT` | management; without it the host becomes unreachable on apply |
| `-d <resolver> -p udp/tcp --dport 53 ACCEPT` | name resolution to the configured resolvers only |
| `-s 10.201.0.2 -p tcp --dport 8155 ACCEPT` + `-d 10.201.0.2 ACCEPT` | **the perimeter gateway reaching the egress proxy** |
| `-d 169.254.169.254 ACCEPT` | sandbox metadata plane the provider code needs |
| `-j DROP` | default deny for everything else |
| IPv6: `lo`, established, then `DROP` | this host has no global IPv6; an unreviewed second path is removed rather than merely unrouted |

### The gateway exception is the critical one

Measured during development: a default-deny OUTPUT with **no gateway exception** stopped the gateway reaching the proxy and broke every authorised request — the firewall silently disabled the perimeter.

This is why the exception is one peer and one port (`10.201.0.2` → `tcp/8155`), not "allow the local subnet". It is the seam where two controls meet, so it is named and justified rather than broad.

## 3. Safety properties

Applying a host-wide firewall can end your session. Three mechanisms exist because each alternative is a lockout:

1. **Build before activate.** The chain is completed, and confirmed to end in `DROP`, *before* the jump is installed. A mid-build failure during development left a chain with no `DROP`; it was harmless only because the jump had not yet been added — and a jumped-to chain with no `DROP` is **fail-open**, absorbing and accepting all traffic. The ordering is now enforced: `apply` refuses to activate a chain without a terminal `DROP`.
2. **Dead-man timer.** `apply --safe-minutes N` arms automatic rollback. It was used, and it **fired correctly** during a long test, restoring `OUTPUT` to `ACCEPT` — the mechanism works, verified by accident under real conditions.
3. **Verified backup first.** A backup is written and checked for content before any rule changes. `rollback` removes the **jump before the chain**, so traffic can never fall through to `ACCEPT` mid-removal.

## 4. Demonstrated results

### Before

```
-P INPUT ACCEPT · -P FORWARD ACCEPT · -P OUTPUT ACCEPT   (no rules)
pypi.org:443 REACHED · github.com:443 REACHED
```

### After

| Probe | Result |
|---|---|
| `pypi.org:443` | **blocked** (`OSError`) |
| `github.com:443` | **blocked** (`TimeoutError`) |
| `203.0.113.99:443` (TEST-NET) | **blocked** (`TimeoutError`) |
| `1.1.1.1:53` | reachable (excepted) |
| `169.254.169.254:80` | reachable (excepted) |
| IPv6 `2001:db8::99:443` | **blocked** |

`verify` output:

```
=== 1. default deny: a non-excepted destination must not connect ===
  PASS  203.0.113.99:443 blocked
  PASS  198.51.100.99:443 blocked
=== 3. ipv6 default deny ===
  PASS  ipv6 egress blocked
=== 4. the policy is installed, not merely intended ===
  PASS  OUTPUT jumps to SKYLA-EGRESS
  PASS  SKYLA-EGRESS ends in DROP
VERIFY: PASS
```

### Persistence (simulated reboot)

```
after flush:   -P OUTPUT ACCEPT
iptables-restore < /etc/skyla-firewall.v4
after restore: -P OUTPUT ACCEPT
               -A OUTPUT -j SKYLA-EGRESS
```

The systemd unit `skyla-firewall.service` is enabled and restores the saved ruleset at boot.

### Rollback

```
policy removed; OUTPUT policy is -P OUTPUT ACCEPT
after rollback: pypi REACHED (policy removed)
```

### Composition with the perimeter — the proof that matters

With the host firewall **active** and the API inside the namespace perimeter:

| Case | Result |
|---|---|
| `research` → `pypi.org` | **HTTP 200** (through the proxy, on an excepted path) |
| `research` → `github.com` | `ProxyError` (denied by policy) |
| `research` → metadata | **403** (denied by policy) |
| `connector-google` → `pypi.org` | `ProxyError` (wrong capability) |

Both layers function simultaneously. Neither is decorative: the firewall stops everything the API is not authorised for, and the proxy stops everything the API's *capability* is not authorised for.

## 5. Interaction with the test suite

One test failed once the firewall was deployed: `test_per_task_policy_is_applied` makes a **real TCP connection** to `pypi.org`, which the policy now blocks. That is an environment dependency, not a regression, and it was triaged rather than re-run until green: the test is now guarded by the file's existing `_egress_allowed_for()` helper and skips with a stated reason. Skips rose 37 → 39.

## 6. What is still not done

| Item | Status | Note |
|---|---|---|
| Denial logging | **unavailable** | this kernel has no `limit`/`LOG` extension; the `DROP` is installed but denials are not logged. Permit decisions remain auditable in the proxy's JSONL audit. |
| Denials at the host level | observed indirectly | no `LOG` target, so counting denials requires conntrack inspection |
| Second-host deployment | **NOT VERIFIED** | the policy is deployed on this host only (`SECOND_HOST_FINAL_VALIDATION.md`) |
| Production approval to deploy | **operator decision** | this host is the project's own staging environment; applying it elsewhere requires approval |

Denial logging being unavailable is a genuine reduction in auditability for the *denied* path. It is recorded rather than papered over: the `DROP` is what enforces, and enforcement is verified, but the record of *attempts* is missing at the host layer.

## 7. Deployment instructions

```bash
# 1. establish access first, then arm the timer
sudo scripts/skyla-host-firewall.sh apply --safe-minutes 5

# 2. confirm you still have access, then disarm
sudo scripts/skyla-host-firewall.sh disarm

# 3. verify the policy does what it claims
sudo scripts/skyla-host-firewall.sh verify

# 4. persist only once you are confident (this is the step that survives reboot)
sudo scripts/skyla-host-firewall.sh apply --persist

# undo at any time
sudo scripts/skyla-host-firewall.sh rollback
```

**Never run `apply --persist` as the first command on a remote host.** If the policy is wrong, a reboot will reinstate it and you may lose access permanently. Arm the timer, confirm access, then persist.

## 8. Verdict

**NET-23: PASS on this host.**

The control exists, denies by default, excepts only what is justified, survives reboot, rolls back cleanly, and composes with the namespace perimeter. Its one weakness — no denial logging — is recorded above.

It is deployed on **one** host. Whether the policy is correct for a different network topology is exactly what HOST-01 would answer, and HOST-01 remains NOT VERIFIED.
