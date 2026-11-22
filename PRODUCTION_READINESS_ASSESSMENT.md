# Production Readiness Assessment — v0.2.5

**Verdict: NO-GO.**

Two release conditions are now met that were not met in v0.2.4 (execution boundary, resource enforcement).
Three remain unmet, and a new composition defect (FW-01) was found and recorded rather than worked around.

- Assessed commit: v0.2.5
- Suite: **406 passed / 21 skipped** (delegated) · **385 passed / 42 skipped** (unprivileged)
- Previous baseline: v0.2.4 — 360 passed / 39 skipped

---

## 1. The gate

| # | Release condition | v0.2.4 | v0.2.5 | Evidence |
|---|---|---|---|---|
| 1 | No unresolved critical/high findings | FAIL | **FAIL** | FW-01 (high, availability) |
| 2 | API network boundary verified | PASS | **PASS** | perimeter `isolated: True` |
| 3 | Execution network boundary verified | **FAIL** | **PASS** | EXE-01…08, 8 vectors |
| 4 | Host-wide firewall deployed | PASS (this host) | **PASS** (this host) | firewall `verify` |
| 5 | Second-host validation | NOT VERIFIED | **NOT VERIFIED** | no second host |
| 6 | DB recovery verified | PASS | **PASS** | unchanged |
| 7 | Live connector validation | NOT VERIFIED | **NOT VERIFIED** | no credentials; FW-01 blocks upstream |
| 8 | Independent external review | NOT VERIFIED | **NOT VERIFIED** | not appointed |
| 9 | Complete reproducible evidence with hashes | PASS | **PASS** | 156 records, manifest hashes |
| 10 | No requirement weakened to obtain approval | PASS | **PASS** | this document |

**4 PASS · 2 FAIL · 3 NOT VERIFIED → NO-GO.**

## 2. What changed for the better

| Item | v0.2.4 | v0.2.5 |
|---|---|---|
| EXEC-01: local sandbox inherited host networking | **open** | **closed** — verified netns isolation |
| Cgroup enforcement | 18 tests skipped | **18 passed**, limits measured against the kernel |
| Aggregate protection | unverified | **PASS** — 601 MB of a 1024 MB ceiling |
| Process-tree containment | partial | **PASS** — 0 survivors after 25 kills |
| Mutation coverage of execution controls | 0 | **8, all detected** |
| Suite | 360/39 | **405/21** |
| Registry | 109 records | **156** |

The most significant qualitative change: EXEC-01 was not a missing feature, it was a **false claim**. The
docstring said "no network" and nothing enforced it. That is now a verified property with a positive control,
and the provider that has it still refuses to call itself `safe_for_untrusted`.

## 3. The blocking items

### 3.1 FW-01 — the firewall blocks the proxy's own upstream (FAIL, high)

The egress proxy runs in the host namespace, so `SKYLA-EGRESS` governs its outbound connections, and no
exception matches them:

```
firewall active  → CONNECT api.openai.com:443 → 403 "upstream unreachable"
firewall rolled back → same CONNECT → 200 Connection Established
```

**It fails closed.** Nothing leaks; the system refuses to do remote work rather than permitting unaccounted
egress. But it means the firewall and useful egress are mutually exclusive on this kernel.

The specified fix is one rule — `-m owner --uid-owner <proxy_uid> -j ACCEPT` before the terminal `DROP` —
which requires `xt_owner`, absent here. The alternative (allow outbound 443 generally) would restore
availability by destroying the control, and was rejected.

**Consequence:** live connectors cannot be validated on this host with the firewall active. That was already
NOT VERIFIED for lack of credentials; FW-01 adds a second, independent reason.

### 3.2 HOST-01 — no second host (NOT VERIFIED)

Unchanged. No hypervisor, runtime, `/dev/kvm` or cloud CLI. `scripts/skyla-host-qualify.sh` is the runnable
package. **The delegated-cgroup configuration has now only ever been exercised on one kernel** — a second
host would test whether the delegation procedure generalises, which is the most likely thing to differ.

### 3.3 CONN-01/02/03 — live connectors (NOT VERIFIED)

Unchanged, no credentials. Zero capabilities are LIVE_VERIFIED.

### 3.4 EXT-01 — independent external review (NOT VERIFIED)

Not appointed. `EXTERNAL_REVIEW_PACKAGE.md` (v0.2.4) is the handover; §8 of that document lists the seven
things a reviewer should be most suspicious of.

## 4. Secondary gaps, recorded not hidden

| ID | Item | Why it matters |
|---|---|---|
| EXEC-02 | Restricted provider has no seccomp/Landlock/PID-kill | network-confined only; `safe_for_untrusted: False` |
| CG-06 | No disk/IO quota | a workload can fill the shared filesystem apart from `RLIMIT_FSIZE` |
| PT-06 | API restart during execution unexercised | the design keeps workloads independent; unproven |
| AGG-05/06 | Large-output and disk-exhaustion tests not run | testing an unconfigured control was judged not worth the risk to the environment |

## 5. Regression analysis

| Comparison | v0.2.4 | v0.2.5 | Assessment |
|---|---|---|---|
| Passed (unprivileged) | 360 | 384 | +24 (20 isolation + 4 other) |
| Skipped (unprivileged) | 39 | 42 | +3 cgroup mutations needing placement |
| Passed (delegated) | — | 405 | cgroup tests execute |
| Failures | 0 | 0 | none |

No test was deleted, weakened, or made unconditionally skipped. The two v0.2.4 skips caused by the firewall
denying real internet access remain, correctly guarded with a stated reason.

## 6. Security posture

| Boundary | Enforcement | Verified | Residual risk |
|---|---|---|---|
| Untrusted job → network | `unshare -n` + verified proof | **yes**, 8 vectors | none found |
| Untrusted job → host loopback | namespace | **yes** | none found |
| Untrusted job → resources | cgroup v2 per-job + aggregate | **yes**, kernel-measured | no disk quota |
| Job tree → survivors | PID namespace + `cgroup.kill` | **yes**, 0 survivors | API restart case unproven |
| API → internet | namespace + proxy + capability | **yes** | none found |
| Host → internet | iptables default-deny | **yes** | **FW-01: proxy upstream blocked** |
| Restricted provider depth | no seccomp/Landlock | disclosed | EXEC-02 |
| Provider auth | env-only, never in payload | yes | connectors unvalidated live |

## 7. What would change this verdict

| # | Action | Effort | Unblocks |
|---|---|---|---|
| 1 | Deploy on a host with `xt_owner`; add the one owner rule | hours (external host) | gate 1, partially 7 |
| 2 | Obtain test credentials; run `scripts/connector_validation.py` | days (external) | gate 7 |
| 3 | Obtain a second host; run `scripts/skyla-host-qualify.sh run` | external | gate 5 |
| 4 | Appoint an independent reviewer | external | gate 8 |
| 5 | Configure `io.max` and test disk bounds | hours | CG-06 |

All five are external or configuration work. None is "write more features", which is the correct shape for a
release whose remaining gaps are environmental.

## 8. Integrity statement

- The full suite ran unprivileged: **385 passed / 42 skipped**. Root is used for exactly one operation —
  placing a process into the delegated cgroup — after which the workload runs as the service user, because
  the supervisor refuses to execute untrusted jobs as root.
- Every skip is explained with its production significance. **No skip counts as a pass.**
- Historical evidence was not rewritten: the registry grew by **164 insertions and 0 deletions**, verified
  with `git diff --numstat`.
- No force-push, no amended commits, no rewritten audit output.
- No live connector result was fabricated. No external test was simulated.
- Host firewall rules were not modified; the backup and rollback path was exercised and verified.
- Two of my own measurement mistakes (a positive control placed where it could never pass; a latency probe
  against a 404) are recorded in `EXECUTION_SECURITY_EVIDENCE.md` §5 rather than quietly corrected.

## 9. Verdict

**NO-GO for production.**

Closed: the execution boundary. The local sandbox can no longer reach the network, the kernel enforces the
resource limits that were previously aspirational, and no workload process outlives its task. Those were the
two P0 items and they are done, with 8 mutations proving the tests can detect their removal.

Open: FW-01, second host, live connectors, external review. The first is a kernel limitation with a specified
fix; the other three are external dependencies that more code cannot close.

Production approval was not obtained, and no requirement was weakened to imply otherwise.
