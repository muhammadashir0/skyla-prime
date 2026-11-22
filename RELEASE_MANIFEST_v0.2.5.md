# Release Manifest — v0.2.5 (Prime Execution Closure)

**Release status: NOT APPROVED FOR PRODUCTION.** Execution isolation and resource enforcement are now real;
four external dependencies remain unmet, and one composition defect (FW-01) is open.

- Version: **0.2.5** · Base: v0.2.4 `87511f6`
- Suite: **406 passed / 21 skipped** (delegated) · **385 passed / 42 skipped** (unprivileged)
- Baseline v0.2.4: 360 passed / 39 skipped
- No force-push, no amended commits, no rewritten audit output

---

## 1. Artifact hashes — SHA-256

```
7aa40e4c6bd0f7e29fbf39cbf44b5c1caa48ca1cc2df03003b9f07cc245c38f6  EXEC01_LOCAL_NETWORK_ISOLATION.md
70e9bcd9c9e9f3569406f07ae172c6d33f2145107760975e2606f180a0e3ed6e  CGROUP_DELEGATION_GUIDE.md
5205c8876d659a95907681a268279a2dcc21c9e128c50a4185aaa682145cd314  CGROUP_ENFORCEMENT_REPORT.md
df2a0306159f03bcd70d4ac6d3f3ddf1ea378838b201e6d4401a04093fb5bacb  PROCESS_TREE_CONTAINMENT_REPORT.md
d1f0ad07d625722381e9018dda4e2718f14ee514828ff630f6174cdd595470a7  AGGREGATE_RESOURCE_TESTS.md
06a67a5aaa5c10415212437f6c547c740213cfe4b124fa109b48ff9ffcba23ca  HOST_FIREWALL_REGRESSION.md
53e4e21d248571a1c394a0a4f8e3502180257e43df10c9f1b2723f92b23b105f  EXECUTION_SECURITY_EVIDENCE.md
```

## 2. Security-critical source hashes

| Path | SHA-256 | Role |
|---|---|---|
| `skyla/execution/sandbox.py` | `c1c2d3f38395782a294f4c7db6a8d09e7532db0e673752eb09c797ea5fd91596` | **EXEC-01 fix**: verified netns isolation |
| `skyla/execution/providers.py` | `4fbcdc26175f86caa85639fb63d68e98b1e3002ed9f1829374910e773605a7a1` | local provider honesty |
| `scripts/skyla-run.sh` | `1fe690796f71394b550c627ba7059d5f5cf53ad24d15956ddbf61c394602cbd2` | **cgroup placement fix** |
| `tests/security/test_local_execution_isolation.py` | `13550876a4814778020a2b6a4ac99cb83ec954c3d7b5430cc43f15957a40f6a5` | 20 isolation tests |
| `tests/security/test_execution_mutation_v025.py` | `3b3a213a8cb7ca023b0f4d9e4122d4b235756f17cc4b39df2cb25da702475c80` | 8 mutations |

Unchanged from v0.2.4: `skyla/execution/cgroups.py`, `skyla/execution/workload.py`,
`scripts/skyla-host-firewall.sh`.

## 3. Deliverables

| # | Deliverable | Subject status |
|---|---|---|
| 1 | `EXEC01_LOCAL_NETWORK_ISOLATION.md` | **CLOSED** for network inheritance; provider remains weaker and says so |
| 2 | `CGROUP_DELEGATION_GUIDE.md` | **WORKING**; two failure modes documented (POSIX `-w`, no-internal-processes) |
| 3 | `CGROUP_ENFORCEMENT_REPORT.md` | **PASS** — 18/18 tests, limits measured against the kernel |
| 4 | `PROCESS_TREE_CONTAINMENT_REPORT.md` | **PASS** — 0 survivors; API-restart case NOT VERIFIED |
| 5 | `AGGREGATE_RESOURCE_TESTS.md` | **PARTIAL** — memory/CPU/pids PASS; disk/output NOT VERIFIED |
| 6 | `HOST_FIREWALL_REGRESSION.md` | **PARTIAL** — enforcement PASS; authorised upstream **FAIL (FW-01)** |
| 7 | `EXECUTION_SECURITY_EVIDENCE.md` | 8/8 mutations detected |
| 8 | `RELEASE_MANIFEST_v0.2.5.md` | this file |

## 4. Changes

| Path | Change |
|---|---|
| `skyla/execution/sandbox.py` | **rewritten** — `unshare -n`, in-namespace probe, host-side positive control, refusal on unverified isolation |
| `skyla/execution/providers.py` | `RestrictedProvider` reports verified isolation, still `safe_for_untrusted: False` |
| `scripts/skyla-run.sh` | **placement verified from `/proc/self/cgroup`** instead of trusting `-w` |
| `tests/security/test_local_execution_isolation.py` | **new** — 20 tests |
| `tests/security/test_execution_mutation_v025.py` | **new** — 8 mutations |
| `SECURITY_EVIDENCE_REGISTRY.md` | appended (v0.2.5 section) |

No host firewall rules were modified. No existing test was weakened or deleted.

## 5. Test accounting

| Run | Passed | Skipped | Failed |
|---|---|---|---|
| Unprivileged | 385 | 42 | 0 |
| Delegated cgroup subtree (service user) | **406** | **21** | **0** |
| Baseline v0.2.4 | 360 | 39 | 0 |

21 skips in the delegated run: 9 namespace entry (CAP_SYS_ADMIN), 6 API egress (CAP_SYS_ADMIN), 2 real
internet reachability (firewall denies — expected), 1 absent-namespace path. **No skip counts as a pass.**

Note: running the cgroup tests **as root** produces 3 failures, because the supervisor refuses to execute
untrusted jobs as root. That refusal is a control, not a regression; the tests are run as the service user.

## 6. Open items

| ID | Item | Severity | Blocking |
|---|---|---|---|
| **FW-01** | Firewall blocks the proxy's own upstream; controls mutually exclusive on this kernel | **high** | yes |
| EXEC-02 | Restricted provider lacks seccomp/Landlock/PID-kill | medium | no (disclosed, `safe_for_untrusted: False`) |
| CG-06 | Disk / IO quota not enforced or tested | medium | no |
| PT-03 | API restart during execution NOT VERIFIED | medium | no |
| HOST-01 | No second host | — | yes |
| CONN-01/02/03 | Live connectors NOT VERIFIED | — | yes |
| EXT-01 | Independent external review not performed | — | yes |

## 7. Deploying

```bash
sudo scripts/cgroup_bootstrap.sh          # one-time delegation
scripts/skyla-run.sh <command>            # launch inside the delegated subtree
sudo scripts/skyla-host-firewall.sh verify
```

**FW-01 decision required:** with the firewall active, no provider is reachable. Deploying both requires
either a kernel with `xt_owner` (one rule, specified in `HOST_FIREWALL_REGRESSION.md` §3) or a deliberate
choice between them. This must be an explicit operator decision, not an emergent one.

## 8. Reproduction

```bash
git checkout <this commit>
python3.11 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt

python -m pytest -q                                     # 385 passed / 42 skipped
sudo -n scripts/cgroup_bootstrap.sh
sudo sh -c 'printf %s $$ > /sys/fs/cgroup/skyla/service/cgroup.procs
            exec setpriv --reuid=user --regid=user --clear-groups \
              .venv/bin/python -m pytest -q'            # 406 passed / 21 skipped

sha256sum -c <<'EOF'
7aa40e4c6bd0f7e29fbf39cbf44b5c1caa48ca1cc2df03003b9f07cc245c38f6  EXEC01_LOCAL_NETWORK_ISOLATION.md
70e9bcd9c9e9f3569406f07ae172c6d33f2145107760975e2606f180a0e3ed6e  CGROUP_DELEGATION_GUIDE.md
5205c8876d659a95907681a268279a2dcc21c9e128c50a4185aaa682145cd314  CGROUP_ENFORCEMENT_REPORT.md
df2a0306159f03bcd70d4ac6d3f3ddf1ea378838b201e6d4401a04093fb5bacb  PROCESS_TREE_CONTAINMENT_REPORT.md
d1f0ad07d625722381e9018dda4e2718f14ee514828ff630f6174cdd595470a7  AGGREGATE_RESOURCE_TESTS.md
06a67a5aaa5c10415212437f6c547c740213cfe4b124fa109b48ff9ffcba23ca  HOST_FIREWALL_REGRESSION.md
53e4e21d248571a1c394a0a4f8e3502180257e43df10c9f1b2723f92b23b105f  EXECUTION_SECURITY_EVIDENCE.md
EOF
```

## 9. Approval

**NOT APPROVED.**

Closed this release: EXEC-01 (network inheritance), cgroup delegation, per-job and aggregate enforcement,
process-tree containment, mutation sensitivity.

Unmet: FW-01 (composition), second host, live connectors, external review. Three are external dependencies;
FW-01 is a kernel limitation on this host with a specified fix elsewhere.

No requirement was weakened to reach this state. Where a control could not be measured, it is recorded as
NOT VERIFIED rather than assumed.
