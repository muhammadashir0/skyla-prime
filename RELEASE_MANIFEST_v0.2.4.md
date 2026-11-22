# Release Manifest — v0.2.4 (Prime Deployment Qualification)

**Release status: NOT APPROVED FOR PRODUCTION.** See `PRODUCTION_READINESS_ASSESSMENT.md`.

- Version: **0.2.4**
- Base: v0.2.3 (`6b489ef`) — 359 passed / 37 skipped
- This release: **360 passed / 39 skipped**, 0 failed, unprivileged
- Commit sequence: `067bdf0` (firewall + probe fixes) → this commit (documentation)
- No force-push, no amended commits, no rewritten audit output

---

## 1. Artifact hashes — SHA-256

Hashes are of the files **as committed in this release**. Verify with `sha256sum -c` on the block below.

```
d46824f10d545b15e0b069379d43aad6f71fde3c24029fdcdd74a31422acd0a9  COMPLETE_EGRESS_REVIEW.md
be17a7f74aef30466e3ed94e2131e15bd16c04c47566c18a847c5751bc973d61  HOST_FIREWALL_DEPLOYMENT.md
1498d807d82c5246d9cbeafa9f3fc41d471e6edb08493f32a3be419d409a447e  SECOND_HOST_FINAL_VALIDATION.md
d375232cf34ca0439b34206b916ebaae06af3ff52eba33676639e0676eb3743e  LIVE_CONNECTOR_FINAL_REPORT.md
74e238a81e68fd8922e9980980d9510dde3521e0bd4e936f0f01d6dab234d8ee  EXTERNAL_REVIEW_PACKAGE.md
4109c3f5624d4631e46e1ecbfc28053606e300ba7defade9997bef0042f5b7d5  SECURITY_EVIDENCE_REGISTRY.md
84a0ed60fa4dd3574d28929f0e07c201e4d691b428753aed490e2e2bb1d61d01  PRODUCTION_READINESS_ASSESSMENT.md
594b845e303c7d589b29e67c74d5fb065d81b99755ed9e13ae283637ff6b9348  scripts/connector_validation.py
80ca81ba10e19ef517215d4f9c129c190407abde1cfdfea3681f258826ca76c1  scripts/skyla-host-qualify.sh
3975c223ca0d8578caefbd34de155d5a1ef2beb6af2fb5d3b84e0f1044cbe58b  scripts/skyla-host-firewall.sh
```

This manifest is not self-hashed: a file cannot contain its own digest. Verify it by hashing the ten artifacts
above and comparing.

## 2. Security-critical source hashes

Hashes of the code that enforces the boundaries, so a reviewer can confirm the reviewed source is the shipped
source. First 16 hex characters shown; full digests in `git show <commit>:<path> | sha256sum`.

| Path | SHA-256 (16) | Role |
|---|---|---|
| `skyla/perimeter.py` | `6a8d3e286189ce43` | namespace creation, proof, teardown |
| `skyla/egress.py` | `d8f51dc319755ece` | capability policies, proxy |
| `skyla/egress_client.py` | `75ad298e391a93dc` | the single approved HTTPX factory |
| `skyla/netguard.py` | `d5431caeadefb679` | URL vetting, SSRF classification |
| `skyla/db.py` | `41cc2ae1e02ed6cf` | persistence, recovery |
| `skyla/core/orchestrator.py` | `2fb6d93d7f4fe768` | task lifecycle, lease |
| `skyla/api/app.py` | `5b6eba99c1e0675e` | API surface |
| `skyla/execution/workload.py` | `efd799702636794f` | job isolation (`unshare -n`, seccomp) |
| `scripts/skyla-perimeter.sh` | `780ca2e72706aaaf` | perimeter lifecycle |

## 3. Deliverables

The eight required documents:

| # | Deliverable | Status of the subject it documents |
|---|---|---|
| 1 | `COMPLETE_EGRESS_REVIEW.md` | B-01 **CONFIRMED**; 2 verification defects found and fixed; EXEC-01 open |
| 2 | `HOST_FIREWALL_DEPLOYMENT.md` | NET-23 **PASS on this host**; no denial logging |
| 3 | `SECOND_HOST_FINAL_VALIDATION.md` | **NOT VERIFIED** — no second host; package provided |
| 4 | `LIVE_CONNECTOR_FINAL_REPORT.md` | **NOT VERIFIED** — no credentials; harness provided |
| 5 | `EXTERNAL_REVIEW_PACKAGE.md` | package **prepared**; review **not performed** |
| 6 | `SECURITY_EVIDENCE_REGISTRY.md` | **updated**, 109 records, append-only (131 insertions, 0 deletions) |
| 7 | `PRODUCTION_READINESS_ASSESSMENT.md` | **NO-GO** |
| 8 | `RELEASE_MANIFEST_v0.2.4.md` | this file |

## 4. New and changed files

| Path | Change |
|---|---|
| `scripts/skyla-host-firewall.sh` | **new** — host default-deny egress (apply/status/verify/rollback/backup/disarm/persist) |
| `scripts/skyla-host-qualify.sh` | **new** — reproducible second-host qualification package |
| `scripts/connector_validation.py` | **new** — live connector harness, refuses unsafe runs |
| `skyla/perimeter.py` | **fixed** — missing `socket` import, real control target, fail-closed proof |
| `scripts/skyla-perimeter.sh` | **fixed** — fail closed with reason when the control is unavailable |
| `tests/security/test_network_perimeter.py` | **new test** — a failed host control means isolation is not proven |
| `tests/security/test_egress.py` | **guarded** — live-internet tests skip with a reason under default-deny |
| Eight documents | new / updated as listed above |

## 5. Test accounting

```
360 passed, 39 skipped, 1 warning in 66.86s
```

| Skips | Cause | Counted as pass? |
|---|---|---|
| 18 | cgroup subtree not delegated (`/sys/fs/cgroup/skyla` missing) | **no** |
| 10 | namespace tests need `CAP_SYS_ADMIN` | **no** (manual root evidence recorded) |
| 6 | API egress tests need `CAP_SYS_ADMIN` | **no** (live sweep recorded) |
| 2 | host cannot reach pypi — the new firewall denies it | **no** (expected consequence) |
| 1 | absent-namespace path cannot be exercised while the namespace exists | **no** |
| 2 | additional guards introduced this release | **no** |
| **39** | | |

The v0.2.3 baseline was 359/37. The difference is +1 test and +2 expected skips, both from the firewall being
correct. No test was deleted or weakened.

## 6. Deployment artifacts outside Git

Host state, recorded here so it can be reconstructed — not committed, because it belongs to the machine:

| Path | Purpose |
|---|---|
| `/etc/skyla-firewall.v4`, `/etc/skyla-firewall.v6` | persisted rulesets restored at boot |
| `/etc/systemd/system/skyla-firewall.service` | restore-on-boot unit (enabled) |
| `/var/lib/skyla/firewall/` | timestamped backups, `last-apply.env`, `armed` flag |

## 7. Reproduce this release

```bash
git clone <repo> && cd skyla-prime && git checkout 067bdf0   # + this documentation commit
python3.11 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

python -m pytest tests/ -q                    # 360 passed / 39 skipped
scripts/skyla-host-qualify.sh check           # capability report
sudo scripts/skyla-host-firewall.sh verify    # only on an isolated host
sha256sum -c <<'EOF'
d46824f10d545b15e0b069379d43aad6f71fde3c24029fdcdd74a31422acd0a9  COMPLETE_EGRESS_REVIEW.md
be17a7f74aef30466e3ed94e2131e15bd16c04c47566c18a847c5751bc973d61  HOST_FIREWALL_DEPLOYMENT.md
1498d807d82c5246d9cbeafa9f3fc41d471e6edb08493f32a3be419d409a447e  SECOND_HOST_FINAL_VALIDATION.md
d375232cf34ca0439b34206b916ebaae06af3ff52eba33676639e0676eb3743e  LIVE_CONNECTOR_FINAL_REPORT.md
74e238a81e68fd8922e9980980d9510dde3521e0bd4e936f0f01d6dab234d8ee  EXTERNAL_REVIEW_PACKAGE.md
4109c3f5624d4631e46e1ecbfc28053606e300ba7defade9997bef0042f5b7d5  SECURITY_EVIDENCE_REGISTRY.md
84a0ed60fa4dd3574d28929f0e07c201e4d691b428753aed490e2e2bb1d61d01  PRODUCTION_READINESS_ASSESSMENT.md
EOF
```

A hash mismatch means the artifact differs from the reviewed version — investigate before trusting any result
in it.

## 8. Open items carried forward

| ID | Item | Severity | Blocking |
|---|---|---|---|
| EXEC-01 | `sandbox.py` local provider inherits host network | **high** | yes (gate 1, 3) |
| ISO-CG | cgroup enforcement unverified (18 skips) | medium | yes (gate 3) |
| NET-31 | no host-level denial logging on this kernel | medium | no |
| HOST-01 | no second host | — | yes (gate 5) |
| CONN-01/02/03 | no live connector validation | — | yes (gate 7) |
| EXT-01 | no independent external review | — | yes (gate 8) |

## 9. Approval

**NOT APPROVED.** 4 PASS · 2 FAIL · 3 NOT VERIFIED. Five gate conditions are unmet, three of them because an
external dependency does not exist in this environment.

No requirement was weakened, no external test was simulated, and no live connector result was invented to
reach a different outcome.
