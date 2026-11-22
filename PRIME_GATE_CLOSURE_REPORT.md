# PRIME GATE CLOSURE REPORT — v0.2.3

**Objective:** establish whether SKYLA PRIME can move from conditional staging to independently reviewed production readiness.

**Answer: No. Production remains NO-GO.**

Two High findings were pursued to closure: one closed completely, one substantially remediated but not finished. That outcome, stated plainly, is the point of a gate like this: a milestone that reports "all clear" without an external reviewer, without a second host, and without live connectors would be worthless.

- HEAD: **`0a44454`** on `arena/2a497c0e-skyla-prime`
- Suite: **341 passed, 31 skipped** (372 collected), unprivileged
- Date: 2026-11-22 · host `e2b.local` · Debian 12 · kernel 6.1.158+

---

## 1. The gate at a glance

| # | Mandatory control | v0.2.2 | v0.2.3 |
|---|---|---|---|
| 1 | B-01 remediated | FAIL (control absent) | **PARTIAL** — boundary built; trusted-process wiring open |
| 2 | B-02 remediated | NOT VERIFIED | **PASS** — closed and mutation-verified |
| 3 | Independent retest | NOT VERIFIED | **NOT VERIFIED** — no external reviewer |
| 4 | Separate host | NOT VERIFIED | **NOT VERIFIED** — blocked |
| 5 | Per-job resource controls | PASS | **PASS** |
| 6 | Aggregate resource controls | PASS | **PASS** |
| 7 | Process-tree termination | PASS | **PASS** |
| 8 | Perimeter enforcement | FAIL | **PARTIAL** — 8/10 properties PASS |
| 9 | Cross-user boundaries | PASS | **PASS** |
| 10 | DB integrity + restore | PASS | **PASS** |
| 11 | Multi-worker idempotency | NOT VERIFIED | **PASS** |
| 12 | Live connectors | NOT VERIFIED | **NOT VERIFIED** — no credentials |
| 13 | No open critical/high | FAIL | **FAIL** — 8 open |
| 14 | Final tree passes suite | PASS | **PASS** |

**7 PASS · 2 PARTIAL · 1 FAIL · 3 NOT VERIFIED** across the 14 controls (row 13 FAIL is the aggregate of open findings; row 1 PARTIAL is B-01 itself).

## 2. B-02 — closed, and it can be trusted

Reproduced before any fix: **4, 6, 8 step rows** for 2, 3, 4 processes, every process exiting 0. Silent duplication with no error, no warning, no audit trail — the duplicate side effects indistinguishable from real work.

Two fixes were written and **both rejected by measurement**: a lease row with `DELETE` on release (sequential duplication), and a CAS accepting `planning` (`2/8` duplicates at n=4). The rule that emerged is the actual finding: **only `status='queued'` may ever be claimable.**

The fix is one database-arbitrated statement:

```sql
UPDATE tasks SET status='executing' WHERE id=? AND status='queued'
```

Result: **30/30 runs, exactly 2 step rows**, at n ∈ {2,3,4,6,8}. Three mutations caught — including restoring the **original vulnerable orchestrator**, which fails 4 of 10 tests. That last mutation is what makes the closure credible: the suite demonstrably fails on the defect it was written for.

A crucial methodological point: **the verdict is validated by its side effect, never by the API's return value.** An intermediate version returned `held` correctly while still executing the task.

## 3. B-01 — substantially remediated, not finished

The finding was not taken at face value. Probing first produced a scope correction: **untrusted-execution workloads were never exposed** — `unshare -n` plus a seccomp filter denying `socket()` means every connect returns `PermissionError` and `/proc/net/dev` shows no interfaces. B-01 is about the **trusted API process**, which has full host networking and, in v0.2.2, no enforcement at all (`grep -c "egress\|proxy" skyla/api/app.py` → **0**).

A single-veth topology was built, measured, and **rejected**: the workload could reach every `0.0.0.0`-bound host service, including the API. The delivered design adds a gateway namespace whose peer contains one port and nothing else.

The boundary is the **route table, not a filter**: no default route means no next hop, so a packet dies at `ENETUNREACH` regardless of what any application does. Measured from inside: internet, metadata, host `0.0.0.0:8200`, host loopback, and other gateway ports all unreachable; host control confirms all are reachable unconfined. The allow path survives: `pypi.org` → 200, `github.com` → 403, metadata → 403, internal API → 403.

Two mutations prove the layers are independent: adding a route to the host link turns `OSError` into `TimeoutError` (gateway `DROP` held); inserting `ACCEPT` into the gateway leaves it `OSError` (routing held first).

**Three defects were found in the perimeter's own status reporting, all in the reassuring direction:** `verify` rejected a healthy perimeter; `prove_no_egress` reported `isolated: True` for a caller that could not enter the namespace at all; and `available` was never set on success. All three fixed and pinned. Finding these in my own work is why B-01 is not called closed.

## 4. What is still open, and the exact blocker

| Finding | Status | Blocker |
|---|---|---|
| **NET-23** — host-wide nftables ruleset | NOT MET | No `nft`/`iptables` binary; no installable binding; direct `libnftables.so.1` netlink write returns `Could not process rule: No such file or directory` as uid 0, `CapEff 1ffffffffff`, inside a fresh netns. Environment boundary. |
| **NET-24** — API process OS-confined | PARTIAL | `run_confined()` proven but unused by `api/app.py`; proxy starts only when explicitly enabled |
| **HOST-01** — separate host | NOT VERIFIED | No hypervisor, no container runtime, apt egress blocked; and a container on this kernel would not satisfy the gate anyway |
| **CONN-01/02/03** — live connectors | NOT VERIFIED | Zero provider credentials; provider endpoints *are* reachable, so this is authorization, not network |
| **Independent review** | NOT VERIFIED | No qualified external reviewer |
| A-13, A-17, A-21, A-22, B-03…B-07 | Open | Medium/other findings, unchanged from v0.2.2 |

None is claimed as a pass. Each is documented with a blocker and, where possible, a path to closure.

## 5. Honesty accounting

This milestone's most useful output may be the failure modes it documented rather than the features it added:

1. **A control that reports success when it cannot measure is worse than one that reports nothing.** The perimeter reported `isolated: True` without ever entering the namespace. Fixed; pinned.
2. **A "held" verdict is not proof of a working lease.** Validate the side effect. Three of the four bugs in the lease work were invisible from the API's return value.
3. **Skipped tests hide lost controls.** 18 cgroup tests skip without a root bootstrap. A host that never bootstraps has no memory limits while the suite reads green. Reported with its release implication rather than buried.
4. **A fix that passes its own tests is unproven until a mutation fails.** Every closure here is backed by a mutation on the original defect.

## 6. Release decision

**PRODUCTION: NO-GO.**
- 3 mandatory controls not PASS (B-01 partial, 2 NOT VERIFIED)
- 1 control FAIL: 8 open findings including 1 partial High

**STAGING: CONDITIONAL — improved over v0.2.2.**
- B-02 closed with evidence a reviewer can attack
- A network boundary that holds independently of any application behaviour
- 341 passing tests, up from 322

## 7. What would move this to GO

In dependency order:

1. **Wire the API into the perimeter.** Replace the trusted process's direct egress with `run_confined()`, or start the service inside the namespace. Closes NET-24 and makes property 2 of the ten a PASS. No remaining unknown — a wiring task.
2. **Get a genuinely separate Linux host.** Closes HOST-01 and gives the first real test of whether these controls are properties of the code or of `e2b.local`.
3. **Authorize two isolated test accounts.** Closes live connectors; the network path is already verified reachable.
4. **Commission an external review** using `INDEPENDENT_REVIEW_PACKAGE.md`. Until then, items 3 and the review itself stay NOT VERIFIED no matter how much internal testing is done.
5. **Close A-13, A-21, A-22 and B-03…B-07**, or accept them in writing with a documented rationale.

## 8. Closing statement

The instruction was to build a system that can be trusted before making it more powerful. This milestone added no features. It closed one High finding completely, built and measured a real boundary for another, and documented — with exact blockers — everything it could not prove.

Two High findings remain not fully resolved against 14 mandatory controls, so the honest answer to "is this production ready" is **no**, and the manifest says so rather than arguing the point.
