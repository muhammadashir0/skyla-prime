# External Review Package — v0.2.4 Mission 5

A reviewer's starting point. It gathers what an independent party needs, states what they should be
sceptical of, and — importantly — does **not** present this as a completed external review.

---

## 1. Status of the external review

| Field | Value |
|---|---|
| Reviewer | **none appointed** |
| Independence | not established |
| Review performed? | **no** |
| Internal reassessment presented as external testing? | **no — this document is explicitly internal** |

**Nothing in this repository is an external penetration test.** The v0.2.3 and v0.2.4 assessments were
performed by the agent that wrote the remediation. `COMPLETE_EGRESS_REVIEW.md` calls itself a review, and it
is one — an *internal* one. The distinction is not pedantry: an implementer re-reading their own work shares
their own blind spots, which is exactly how two defects (M1-07, M1-08) survived in the "proof" code while
being described as verified.

An independent reviewer is required before production approval and has not been appointed.

## 2. What an independent review must cover

| # | Area | Why it needs outside eyes |
|---|---|---|
| 1 | Is the perimeter *complete*? | the implementer enumerated the paths and could have missed one; §4 lists what to attack |
| 2 | Is the egress proxy auditable? | one process holds the only egress capability — its policy logic is the whole boundary |
| 3 | Is the lease sound? | B-02 cross-process concurrency; a subtle TOCTOU would be invisible in passing tests |
| 4 | Is the DB recovery real? | "restart works" is not "data survives a crash at the wrong moment" |
| 5 | Is the host firewall correct *for another topology*? | the exceptions are tuned to one network |
| 6 | Are the honesty controls themselves honest? | who verifies the verifier's self-checks? |
| 7 | Is the sandbox escape-resistant? | `sandbox.py` (EXEC-01) inherits host network — already known |
| 8 | Are the tests meaningful? | a test that cannot fail passes forever; M1-07 is a live example |

## 3. Architecture in one page

```
                     ┌──────────────────────────────────────────┐
   untrusted job ───► │ netns skyla-egress (no interfaces)       │
                     │ seccomp: socket() denied                 │
                     │ cgroup: memory/cpu/pids (unverified)     │
                     └────────────────────┬─────────────────────┘
                                          │ no route out
   ┌──────────────┐    ┌──────────────────▼──────────────────┐
   │ host firewall│    │ API process (uid 1001, in netns)    │
   │ SKYLA-EGRESS │    │ every egress via egress_client      │
   │ default DENY │    │ capability → policy (deny by default)│
   └──────┬───────┘    └──────────────────┬──────────────────┘
          │                               │ allowed destination only
          │              ┌────────────────▼─────────────────┐
          └─────────────►│ egress proxy 10.201.0.2:8155     │
                         │ JSONL audit, per-capability rules │
                         └────────────────┬─────────────────┘
                                          ▼
                                     internet
```

Two independent layers. The firewall stops the *host*; the proxy stops the *API's capabilities*. Neither is
sufficient alone: the firewall would let the API reach anything if it had a route, and the proxy cannot
constrain a process that bypasses it.

## 4. Where to attack — concrete suggestions

| Attack | What should happen |
|---|---|
| Reach the internet from a job process | `socket()` denied by seccomp; no route; no interface |
| Use a `research` client to reach a model provider | `ProxyError` — wrong capability |
| Set `HTTPS_PROXY` in a subprocess and call out | env allowlist excludes it; no route regardless |
| Follow a redirect to a blocked host | each hop re-vetted; the redirect is refused |
| Request a URL resolving to `169.254.169.254` | blocked by `netguard` classification |
| Connect to an IPv6 address | no v6 route; firewall `DROP`s v6 |
| Restart the API and expect downgraded networking | `enforce` re-verified per client |
| Kill the proxy and expect a direct fallback | raise, no fallback path |
| Destroy the perimeter with jobs running | members terminated before removal |
| Run a job via `sandbox.py` (local provider) | **it inherits host network — known gap, EXEC-01** |

## 5. Evidence index

| Artifact | Contents | Hash |
|---|---|---|
| `COMPLETE_EGRESS_REVIEW.md` | M1: outbound inventory, ten confirmations, two found defects | see manifest |
| `HOST_FIREWALL_DEPLOYMENT.md` | M2: policy, safety mechanisms, measured before/after | see manifest |
| `SECOND_HOST_FINAL_VALIDATION.md` | M3: NOT VERIFIED + the runnable package | see manifest |
| `LIVE_CONNECTOR_FINAL_REPORT.md` | M4: no live validation, harness behaviour | see manifest |
| `SECURITY_EVIDENCE_REGISTRY.md` | 109 records, historical rows byte-identical | see manifest |
| `PRODUCTION_READINESS_ASSESSMENT.md` | the gate, item by item | see manifest |
| `RELEASE_MANIFEST_v0.2.4.md` | **full SHA-256 of every artifact above** | self |

Full hashes are in `RELEASE_MANIFEST_v0.2.4.md`; hashing this document inside itself would be circular.

## 6. Source and commits

The complete history, unmodified — no rebase, no force-push, no rewritten audit:

```
9f4db1f  security audit
b29c8f5  M1–M7 remediation
41614fc  M8
872647b  M2–M4
381795e 0356454 278eb73 3ab461d f669668 4df7abc b4ba0a8 5201853 ad53336 0a44454 a3bf461
5bace07  v0.2.3 B-01 remediation
6b489ef  v0.2.3 documentation (8 deliverables)
067bdf0  v0.2.4 M1–M2: firewall + perimeter probe fixes
```

A reviewer should verify that `git log` matches this list and that `git show 6b489ef:SECURITY_EVIDENCE_REGISTRY.md`
hashes to the value recorded in the v0.2.4 extension — that is a checkable proof that historical evidence was
not edited.

## 7. Reproduction

```bash
python3.11 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests/ -q                       # expect 360 passed / 39 skipped unprivileged

scripts/skyla-host-qualify.sh check              # capability report; non-zero on MISSING
sudo scripts/skyla-host-firewall.sh verify       # host policy (only on an isolated host)
sudo env PYTHON=.venv/bin/python scripts/skyla-perimeter.sh setup
sudo env PYTHON=.venv/bin/python scripts/skyla-perimeter.sh verify
```

**The full suite must run unprivileged.** As root, the supervisor refuses to execute untrusted jobs
(`refusing to run: supervisor must not be setuid/root`) and 32 tests fail by design. That refusal is a
control. Root is used only to enter the namespace and to manage the firewall.

## 8. What the reviewer should be most suspicious of

Ordered by how likely the implementation is to be wrong:

1. **`sandbox.py` inherits the host network (EXEC-01).** Known, disclosed, unfixed. An operator who switches
   the execution provider to `local` loses execution-layer isolation and relies on the host firewall alone.
2. **No host-level denial logging (NET-31).** The `DROP` is in place but attempts are not recorded. Detection
   of probing is therefore absent at the host layer.
3. **cgroup enforcement is unverified (18 skips).** Resource limits are configured but the tests that would
   prove they bind cannot run.
4. **Connectors are entirely unvalidated against real providers.** Every connector claim rests on stubs.
5. **The firewall is tuned to one network.** `10.201.0.2` is correct here; elsewhere it may be wrong, and the
   failure would be a working policy that denies the proxy — the perimeter silently disabled.
6. **Landlock ABI 2, not 3.** Network restriction at the syscall layer is weaker than intended.
7. **The implementer also wrote the tests.** Mutation testing mitigates this; it does not eliminate it.

## 9. Reviewer deliverables requested

- findings with severity (critical / high / medium / low), each with a reproduction;
- confirmation that the historical evidence hashes match, i.e. nothing was rewritten;
- a verdict on whether the two verification defects (M1-07, M1-08) indicate a systemic weakness in how this
  project verifies itself, or were isolated mistakes;
- explicit confirmation that this review was performed by someone independent of the implementation.

## 10. Verdict

**Package: prepared. Review: not performed. Reviewer: not appointed.**

Production approval cannot be granted on the strength of this document. It exists so that when an independent
reviewer is available, they can start immediately and attack the specifics rather than re-deriving the
architecture.
