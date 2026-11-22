# Production Readiness Assessment — v0.2.4

**Verdict: NO-GO.**

Not one requirement is weakened to reach a different answer. The release rules name conditions for approval;
five of them are unmet, and four of those are unmet because an external dependency is unavailable, which is a
fact about the environment rather than something more code would fix.

- Assessed commit: `067bdf0` (plus the v0.2.4 documentation in this commit)
- Previous baseline: v0.2.3 `6b489ef` — 359 passed / 37 skipped
- This release: **360 passed / 39 skipped**
- Environment: `e2b.local`, Debian 12, kernel 6.1.158+, 2 vCPU, 3939 MB, cgroup v2 (partial), Landlock ABI 2

---

## 1. The gate

| # | Release condition | Status | Evidence |
|---|---|---|---|
| 1 | No unresolved critical/high findings | **FAIL** | EXEC-01 (`sandbox.py` host network) is open and high |
| 2 | API network boundary verified | **PASS** | M1: ten confirmations, `COMPLETE_EGRESS_REVIEW.md` |
| 3 | Execution network boundary verified | **FAIL** | EXEC-01; cgroup binding unverified (18 skips) |
| 4 | Host-wide firewall deployed where the threat model requires it | **PASS (this host)** | NET-23, `HOST_FIREWALL_DEPLOYMENT.md` |
| 5 | Second-host validation | **NOT VERIFIED** | HOST-01, no second host |
| 6 | DB recovery verified | **PASS** | pre-existing DB-01…03, re-run in this suite |
| 7 | Live connector validation | **NOT VERIFIED** | CONN-01/02/03, no credentials |
| 8 | Independent external review | **NOT VERIFIED** | not appointed; package prepared |
| 9 | Complete reproducible evidence with hashes | **PASS** | 109 records, `RELEASE_MANIFEST_v0.2.4.md` |
| 10 | No requirement weakened to obtain approval | **PASS** | this document |

**4 PASS · 2 FAIL · 3 NOT VERIFIED → NO-GO.**

## 2. What genuinely improved since v0.2.3

| Item | v0.2.3 | v0.2.4 |
|---|---|---|
| Host egress firewall | absent (NET-23 FAIL) | **deployed, verified, persistent, reversible** |
| Outbound mechanism inventory | partial | **exhaustive — no SDKs, no gRPC, no `requests`** |
| Perimeter proof integrity | **broken** (control always failed; `isolated: True` still printed) | **fixed, fail-closed** |
| Second-host package | prose | **executable, capability-gated** |
| Connector safety harness | absent | **present, refuses unsafe runs** |
| Registry | 81 records | **109 records, append-only proven** |

The most valuable outcome of this milestone is not the firewall. It is the discovery that the v0.2.3 perimeter
"proof" could not fail: `perimeter.py` used `socket` without importing it, so the host-control probe raised
`NameError`, and the verdict still printed `isolated: True`. **For an unknown period, a passing proof proved
nothing.** That is a more serious finding than any individual gap, because it means a prior PASS was worth less
than it appeared.

## 3. The blocking items

### 3.1 EXEC-01 — `sandbox.py` inherits the host network (FAIL, high)

The `local` execution provider runs a child that inherits the host network namespace, so a job executed through
it is subject to the host firewall but not to the namespace perimeter. It is not the default
(`SKYLA_EXECUTION_PROVIDER=namespace`), and it was known in v0.2.3.

**Why it is still high:** it is a one-variable misconfiguration away from removing a layer of defence, and the
degradation is silent. Mitigation today is the host firewall; the fix is to route the `local` provider through
`unshare -n` or to remove it.

**Why it was not fixed in this milestone:** the mission scope was qualification, not implementation change.
Fixing it here would alter the execution path while the qualification was being measured — and the honest
sequence is to fix it, then re-qualify.

### 3.2 HOST-01 — no second host (NOT VERIFIED)

No hypervisor, container runtime, cloud CLI, `/dev/kvm`, or installable package path. The firewall exceptions
are correct for `10.201.0.2` and untested anywhere else; cgroup delegation is partial here; Landlock is ABI 2.
All three are kernel or network properties that only a different machine can settle.

### 3.3 CONN-01/02/03 — no live connector validation (NOT VERIFIED)

No credentials exist. Every connector capability is `IMPLEMENTED_NOT_LIVE_TESTED`; **zero are LIVE_VERIFIED**.
The unit tests prove request shape, not that Google or Telegram accept it, not that a refresh token works, and
not that a revoked token fails closed.

### 3.4 Independent external review (NOT VERIFIED)

Not appointed. The internal reviews in this repository say so explicitly and do not claim otherwise.

## 4. Regression analysis versus baseline

| Comparison | v0.2.3 | v0.2.4 | Assessment |
|---|---|---|---|
| Passed | 359 | 360 | +1 (new `test_a_failed_host_control_means_isolation_is_not_proven`) |
| Skipped | 37 | 39 | +2, both explained below |
| Failures | 0 | 0 | none |

The two additional skips are **not** silent regressions:

1. `test_egress.py:225` — "host cannot reach pypi.org (egress allowlist or host firewall)". This test makes a
   real internet connection; the newly deployed default-deny firewall makes it impossible. Guarded with a
   stated reason.
2. `test_egress.py:246` — same cause, sandbox allowlist.

Neither was silenced by deleting an assertion. The guard is the file's pre-existing `_egress_allowed_for()`
helper, which reports *why* it cannot run — a skip with a cause, not a disabled test.

**No test was weakened, deleted, or made unconditionally skipped to obtain a green run.**

## 5. Security posture summary

| Boundary | Enforcement | Verified | Residual risk |
|---|---|---|---|
| Untrusted job → network | netns + seccomp | kernel-level, manual + root tests | cgroup limits unproven (18 skips) |
| API → internet | namespace + proxy + capability policies | live sweep, both layers | none found |
| Host → internet | iptables default-deny | `verify` PASS, reboot-tested | **no denial logging** (NET-31) |
| `local` provider → network | **host firewall only** | — | **EXEC-01, high** |
| Provider auth | env-only, never in payload | grep + payload inspection | connectors unvalidated live |
| Data durability | SQLite + recovery | pre-existing, re-run | none found |

## 6. What would change this verdict

Ordered by cost, cheapest first:

| # | Action | Effort | Unblocks |
|---|---|---|---|
| 1 | Fix EXEC-01: `unshare -n` in the `local` provider, then re-run | hours | gate 1, 3 |
| 2 | Bootstrap the cgroup subtree; re-run to convert 18 skips into results | hours | gate 3 |
| 3 | Obtain test credentials; run `scripts/connector_validation.py` | days (external) | gate 7 |
| 4 | Obtain a second host; run `scripts/skyla-host-qualify.sh run` | external | gate 5 |
| 5 | Appoint an independent reviewer; hand them `EXTERNAL_REVIEW_PACKAGE.md` | external | gate 8 |

Four of the five are external dependencies. Only items 1 and 2 are work this repository can do alone — and
doing them would strengthen the assessment without being sufficient for approval.

## 7. Integrity statement

- The full suite ran unprivileged: **360 passed / 39 skipped**. Root runs are limited to namespace entry and
  firewall management, because the supervisor correctly refuses to execute untrusted jobs as root.
- Every skip is explained with its production significance (§N of the registry). No skip counts as a pass.
- Historical evidence was **not** rewritten. The registry grew by append only: 131 insertions, **0 deletions**,
  and the prefix is byte-identical to `git show 6b489ef:SECURITY_EVIDENCE_REGISTRY.md`.
- No force-push was used. No commit was amended or rewritten.
- No live connector result was fabricated. No external test was simulated.
- Mock operations remain labelled `MOCK_ONLY`; connectors report `mode=mock` from their own code.
- One placeholder hash was written into the registry appendix during authoring and corrected to the real
  computed value before commit — noted here because a fabricated hash in an evidence registry is the exact
  failure this document exists to prevent.

## 8. Verdict

**NO-GO for production.**

Two FAILs (EXEC-01; the execution boundary that inherits on, and cgroup limits that are unproven) and three
NOT VERIFIEDs (second host, live connectors, external review). None can be closed by re-running the suite, and
three cannot be closed from inside this environment at all.

What is defensible today: the API's network boundary is genuinely confined and was re-verified against a fresh,
exhaustive inventory; the host now denies egress by default and survives reboot; the verification machinery
itself is stronger, because it was found to be lying and was fixed.

That is meaningful progress and it is not approval. The requirement was not weakened to say otherwise.
