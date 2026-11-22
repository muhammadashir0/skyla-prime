# Independent Review Package — v0.2.3 PRIME GATE CLOSURE

**Independent external review: NOT VERIFIED — no qualified external reviewer has examined this work.**

This package exists so that an external reviewer can audit the claims without trusting the author. It is **not** a penetration test, and nothing in it may be described as one. The distinction is stated here first because it is the easiest thing in a document like this to overstate.

---

## 1. Scope and honest status

| Item | Status |
|---|---|
| Internal reassessment of B-01 and B-02 | Complete (`B01_REMEDIATION_REPORT.md`, `B02_REMEDIATION_REPORT.md`) |
| Internal adversarial testing (mutation) | Complete — 7 mutations, all caught |
| External penetration test | **NOT DONE** |
| Independent code review by a third party | **NOT DONE** |
| External verification of a second host | **NOT DONE** (blocked, `SECOND_HOST_VALIDATION.md`) |

Everything below is self-reported evidence produced by the author of the fixes. An external reviewer's central task is to assume that framing and try to break it.

## 2. What to review, in priority order

**P1 — B-02 lease correctness (`b4ba0a8`).** The concurrency claim is the easiest to fake and the most damaging to get wrong.
- `skyla/db.py`: `lease_task` (the CAS), `release_task`, `reap_expired_tasks`, and the `task_leases` / `task_recovery` schemas.
- `skyla/core/orchestrator.py`: `run_task` claim wrapper and `_run_claimed`.
- `tests/security/test_task_lease.py`: for each test, ask *what code change would make this pass while the bug remains?* Two such changes were found and rejected during development (a lease row with `DELETE` on release; a CAS accepting `planning`).
- **Try to break it:** run the same task concurrently across processes on a shared DB, then count `task_steps` rows. Do not trust the return value of `lease_task` — an earlier version returned `held` correctly while still executing.

**P2 — Network perimeter (`5201853`, `ad53336`).**
- `skyla/perimeter.py`, `scripts/skyla-perimeter.sh`, `tests/security/test_network_perimeter.py`.
- **Try to break it:** from inside `skyla-egress`, attempt to reach the host's `0.0.0.0`-bound API, the host loopback, the metadata service, and the internet. Then attempt the same from the host to prove the destinations exist. A "blocked" result without the host control is not evidence.
- Check the rejected topology in §3 of `NETWORK_PERIMETER_ASSESSMENT.md`: a single veth to the host leaked every `0.0.0.0` service. Verify the gateway design actually closes it.

**P3 — The honesty controls.** These are the claims most worth distrusting, because they were *introduced by the same process they describe*.
- `HON-01/02/03` in `SECURITY_EVIDENCE_REGISTRY.md`: two reporting bugs were found in the perimeter's own status output. Both made a broken or unmeasured perimeter look healthy. Find any others.
- Search every document for a claim that a control is PASS without a corresponding registry record.

**P4 — Scope decisions.** Confirm that nothing was quietly downgraded. Specifically: `EGRESS_PROXY_ASSESSMENT.md` called B-01 High; is it still treated as High despite the scope narrowing to the API process? Check the argument in `B01_REMEDIATION_REPORT.md` §2.

## 3. The seventeen review items

| # | Item | Location | Status |
|---|---|---|---|
| 1 | Branch / HEAD / provenance | `git log --oneline cb4cfce..HEAD` → 3 commits | available |
| 2 | Full v0.2.2 report set, unaltered | `PRIME_ASSURANCE_REPORT.md` et al., byte-identical to `9f4db1f` | available |
| 3 | B-01 finding text as originally written | `EGRESS_PROXY_ASSESSMENT.md` (frozen) | available |
| 4 | B-02 finding text as originally written | `MULTI_WORKER_CAPACITY_REPORT.md` §5 (frozen) | available |
| 5 | B-01 reproduction, before the fix | `B01_REMEDIATION_REPORT.md` §2 | available |
| 6 | B-02 reproduction, before the fix | `B02_REMEDIATION_REPORT.md` §2 (4/6/8 step rows) | available |
| 7 | B-01 code + tests | `skyla/perimeter.py`, `tests/security/test_network_perimeter.py` | available |
| 8 | B-02 code + tests | `skyla/db.py`, `skyla/core/orchestrator.py`, `tests/security/test_task_lease.py` | available |
| 9 | Mutation results, both findings | `B01…` §6 (4 mutations), `B02…` §8 (3 mutations) | available |
| 10 | Perimeter ten-property assessment | `NETWORK_PERIMETER_ASSESSMENT.md` §5 | available |
| 11 | Second-host validation | `SECOND_HOST_VALIDATION.md` | **NOT VERIFIED (blocked)** |
| 12 | Live connector validation | `LIVE_CONNECTOR_VALIDATION.md` | **NOT VERIFIED (no credentials)** |
| 13 | Evidence registry, all claims | `SECURITY_EVIDENCE_REGISTRY.md` (59 records) | available |
| 14 | Skip accounting with release impact | `SECURITY_EVIDENCE_REGISTRY.md` §G | available — 31 skips, 18 of them cgroup |
| 15 | Test suite totals | 341 passed / 31 skipped, unprivileged | available |
| 16 | Evidence hashes | `RELEASE_MANIFEST_v0.2.3.md` | available |
| 17 | Known open findings | §4 below | available |

## 4. Known open findings — do not report these as discoveries

Declared up front so the review spends its effort on what is not listed:

| ID | Finding | Status |
|---|---|---|
| NET-23 | No host-wide nftables/iptables ruleset | **NOT MET** — netfilter rulesets cannot be loaded in this environment |
| NET-24 | API process not yet OS-confined end to end | **PARTIAL** — `run_confined()` proven, not wired into `api/app.py` |
| HOST-01 | No second host | **NOT VERIFIED** — blocked, no hypervisor/runtime, apt blocked |
| CONN-01/02/03 | No live connector verification | **NOT VERIFIED** — no authorized accounts |
| A-17 | An `interrupted` task is not auto-resumed | Open by design — auto-resume risks duplicate side effects |
| A-13, A-21, A-22 | Medium findings from v0.2.2 | Open |
| B-03…B-07 | Findings from v0.2.2 | Open |

## 5. How to reproduce everything

```bash
git clone <repo> && cd skyla-prime
git checkout 0a44454

python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

# Full suite — MUST be unprivileged (the supervisor refuses to run as root)
.venv/bin/python -m pytest tests/ -q          # 341 passed, 31 skipped

# B-02: concurrency and mutation
.venv/bin/python -m pytest tests/security/test_task_lease.py -q          # 10 passed
git show b4ba0a8^:skyla/core/orchestrator.py > /tmp/orig.py               # restore original
cp /tmp/orig.py skyla/core/orchestrator.py
.venv/bin/python -m pytest tests/security/test_task_lease.py -q          # 4 FAILED
git checkout skyla/core/orchestrator.py

# B-01: perimeter (needs CAP_NET_ADMIN)
sudo env PYTHON=$PWD/.venv/bin/python scripts/skyla-perimeter.sh setup
sudo env PYTHON=$PWD/.venv/bin/python scripts/skyla-perimeter.sh verify

# B-01: the boundary, measured from inside
sudo ip netns exec skyla-egress python3 -c "
import socket
for h,p in [('1.1.1.1',53),('169.254.169.254',80)]:
    try: socket.create_connection((h,p),timeout=3); print(h,'REACHED - BOUNDARY BROKEN')
    except Exception as e: print(h,'blocked:',type(e).__name__)
"
```

## 6. Questions a reviewer should be able to answer "no" to

If any answer is "yes", the corresponding claim in this package is overstated:

1. Is any capability called `LIVE_VERIFIED` without a real provider response attached?
2. Is any internal reassessment described as a penetration test?
3. Is second-host validation implied or assumed anywhere, directly or by omission?
4. Is any skipped test counted toward a PASS anywhere?
5. Does any document claim a control works without a test, and a mutation showing the test is sensitive?
6. Was B-01's severity reduced in a way that the documented evidence does not support?
7. Does any historical audit report differ from commit `9f4db1f`?

## 7. Verdict

**Independent external review: NOT VERIFIED.** No qualified external party has reviewed this work. The package is assembled and reproducible; the review itself has not happened, and no part of this document should be read as though it had.
