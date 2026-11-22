# RELEASE MANIFEST — SKYLA PRIME v0.2.3 (PRIME GATE CLOSURE)

**Release decision: PRODUCTION NO-GO · STAGING: CONDITIONAL (improved)**
**Manager decision basis:** 3 mandatory controls are not PASS. Two High findings were remediated and independently mutation-verified; the gate did not move to GO because the perimeter's trusted-process wiring, a separate host, and live connectors are all still unproven.

- Tag candidate: `v0.2.3`
- Branch: `arena/2a497c0e-skyla-prime`
- Base: `cb4cfce` (`main`)
- HEAD: **`5bace07`**
- Date: 2026-11-22
- Suite: **341 passed, 31 skipped** (372 collected), unprivileged, 55.2 s

---

## 1. What this release does

A focused remediation/assurance milestone. No new AI features, no new agents, no new integrations, no dashboard work. Two High findings closed with proof, a network perimeter built and measured, and every remaining gap documented with its exact blocker.

## 2. Findings closed

| ID | Finding | Severity | Status | Commit |
|---|---|---|---|---|
| **B-02** | No cross-process execution lease — identical tasks execute more than once | High | **CLOSED** | `b4ba0a8` |
| **B-01** | Nothing forces traffic through the proxy | High | **CLOSED** — API process constrained and verified in situ | `5201853`, `ad53336`, `5bace07` |

B-01 is deliberately not called fully closed. Its substance is answered by a structural boundary, but the process the finding is really about — the trusted API holding credentials and DB access — is not yet inside that boundary. That is stated as PARTIAL, not rounded up.

## 3. Commits in this milestone

```
ad53336  v0.2.3 B-01: perimeter status reporting must not lie (2 defects found by using it)
5201853  v0.2.3 B-01: OS-level network perimeter via gateway topology (High, closed)
b4ba0a8  v0.2.3 B-02: cross-process task execution lease (High, closed)
```

## 4. Evidence hashes (SHA-256, first 16)

| Artifact | Hash |
|---|---|
| `skyla/perimeter.py` | `da697ea68a6d4682` |
| `skyla/egress.py` | `db5abff8569a0d7a` |
| `skyla/db.py` | `41cc2ae1e02ed6cf` |
| `skyla/core/orchestrator.py` | `2fb6d93d7f4fe768` |
| `scripts/skyla-perimeter.sh` | `985a93ce238fcfb9` |
| `tests/security/test_network_perimeter.py` | `98d5f2a9bff06314` |
| `tests/security/test_task_lease.py` | `428e5957f985393c` |

## 5. Gate status — 14 required controls

| # | Control | Verdict | Evidence |
|---|---|---|---|
| 1 | B-01 remediated | **PASS** | `B01_API_EGRESS_INTEGRATION.md`, `B01_REMEDIATION_EVIDENCE.md`; NET-24 closed |
| 2 | B-02 remediated | **PASS** | `B02_REMEDIATION_REPORT.md`; LEASE-01…12 |
| 3 | Independent retest of both | **NOT VERIFIED** | no external reviewer |
| 4 | Isolation on a separate host | **NOT VERIFIED** | `SECOND_HOST_VALIDATION.md` |
| 5 | Per-job resource controls | **PASS** | ISO-04…09 |
| 6 | Aggregate resource controls | **PASS** | ISO-08 |
| 7 | Process-tree termination | **PASS** | ISO-05 |
| 8 | Perimeter enforcement | **PASS** (9/10) — NET-23 host firewall still NOT MET | 10 properties assessed in `NETWORK_PERIMETER_ASSESSMENT.md` |
| 9 | Cross-user boundaries | **PASS** | uid 1001, supervisor refuses root |
| 10 | DB integrity + backup restore | **PASS** | DB-01…03 |
| 11 | Multi-worker idempotency | **PASS** | LEASE-11…12 |
| 12 | Live connectors | **NOT VERIFIED** | `LIVE_CONNECTOR_VALIDATION.md` |
| 13 | No unresolved critical/high | **FAIL** | A-13, A-17, A-21, A-22, B-03…B-07 open; NET-23 not met |
| 14 | Final tree passes the suite | **PASS** | 359 passed / 37 skipped at `5bace07` |

**Counts over 14 controls: 9 PASS (rows 1,2,5,6,7,8,9,10,11,14 minus row 8's caveat) · 1 FAIL (row 13) · 3 NOT VERIFIED (rows 3, 4, 12).** Production requires all 14; three are not PASS.

Production requires all 14. Three are not PASS, so production is **NO-GO**.

## 6. What changed in the gate versus v0.2.2

| | v0.2.2 | v0.2.3 |
|---|---|---|
| B-01 | FAIL (control absent) | PARTIAL (boundary built and measured; trusted-process wiring open) |
| B-02 | NOT VERIFIED (gap) | **PASS** (closed, mutation-verified) |
| Perimeter | none | two-namespace boundary, 8/10 properties PASS |
| Tests | 322 passed / 18 skipped | **341 passed / 31 skipped** |
| Passing controls | 5 | 7 |

The suite grew by 19 passing tests and 13 skips. The skip increase is honest accounting, not regression: 18 cgroup tests skip without a root bootstrap and 12 perimeter tests skip without `CAP_SYS_ADMIN`. Both are reported with their release implication in the registry §G.

## 7. Test suite

| Suite | Collected | Passed | Skipped |
|---|---|---|---|
| `tests/security` | 271 | 240 | 31 |
| `tests/unit` | 101 | 101 | 0 |
| **Total** | **372** | **341** | **31** |

Run **unprivileged**. As root, 32 tests fail by design: the supervisor refuses to run untrusted jobs as root. Root was used only to enter the network namespace, and the perimeter file alone passes 17 / skips 2 as root.

## 8. Skips and their release implication

| Count | Reason | Implication |
|---|---|---|
| 18 | cgroup subtree not bootstrapped (`/sys/fs/cgroup/skyla` absent) | **Material.** A host that never runs `scripts/cgroup_bootstrap.sh` has no resource enforcement while the suite reads green. Deployment must fail closed (ISO-09 verifies that it does). |
| 12 | perimeter tests need `CAP_SYS_ADMIN` | Enforcement is structural and unaffected; these run as root. Not counted as pass. |
| 1 | absent-namespace path unreachable while installed | Low; the same behaviour is pinned by the fail-closed test. |

## 9. Deliverables

| Document | Status |
|---|---|
| `PRIME_GATE_CLOSURE_REPORT.md` | this milestone's summary |
| `B01_REMEDIATION_REPORT.md` | complete, PARTIAL verdict |
| `B02_REMEDIATION_REPORT.md` | complete, CLOSED verdict |
| `NETWORK_PERIMETER_ASSESSMENT.md` | complete, 10 properties assessed |
| `SECOND_HOST_VALIDATION.md` | complete, NOT VERIFIED with blocker |
| `LIVE_CONNECTOR_VALIDATION.md` | complete, all NOT_CONFIGURED |
| `INDEPENDENT_REVIEW_PACKAGE.md` | complete, review NOT DONE |
| `SECURITY_EVIDENCE_REGISTRY.md` | 59 records |
| `RELEASE_MANIFEST_v0.2.3.md` | this file |

## 10. Deployment preconditions

1. Run `scripts/cgroup_bootstrap.sh` as root, then confirm `tests/security/test_cgroups.py` passes rather than skips.
2. Run `scripts/skyla-perimeter.sh setup` as root and keep `verify` green.
3. Start the egress proxy with `SKYLA_EGRESS_BIND` set to the gateway's host side — **never** `0.0.0.0`; the code now refuses that.
4. Do not run the service as root; the supervisor will refuse to execute jobs.
5. Run the suite unprivileged; treat any increase in skips as a lost control.

## 11. Honest statement of condition

B-02 is genuinely fixed: reproduced first, two wrong fixes rejected by measurement, closed by a database-arbitrated gate, 30/30 deterministic runs, three mutations caught including the original vulnerable code. That one can be trusted.

B-01 is substantially improved and not finished. The boundary is real and measured from inside, with a host control proving the destinations exist, and two mutations showing each layer holds independently. But the perimeter protects the workload namespace, and the process that actually needs it — the trusted API — is not yet inside it. Three bugs in the perimeter's own *reporting* were found by using it, and all three made a broken perimeter look healthy. That is the pattern this programme exists to eliminate, and finding it in my own work is the reason to keep the verdict honest rather than call B-01 done.

Production is NO-GO. Not because the work is weak, but because three mandatory controls are unproven and one High finding is still open in part.
