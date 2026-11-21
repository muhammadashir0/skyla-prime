# SKYLA PRIME v0.3.0 — PRIME CONTAINMENT Acceptance Report

**Branch:** `arena/2a497c0e-skyla-prime`
**Base:** the v0.2.1 audit commit `9f4db1f` (unchanged, preserved as historical evidence)
**Remediation commit:** `b29c8f5` — *v0.3.0 PRIME CONTAINMENT: M1-M7 remediation*
**Date of measurement:** 2026-11-21
**Release vocabulary:** `PASS` / `FAIL` / `NOT VERIFIED`. **A skip is not a pass.**

---

## 1. Verdict

> ## Production: **NO-GO**
>
> All six P0 missions are remediated and mutation-tested, and the eight High
> findings that gated them are closed on **this** runtime. The NO-GO is
> maintained because five release criteria carry `NOT VERIFIED` components that
> require independent review on the target deployment: cgroup-based aggregate
> enforcement, egress proxying, backup/restore drills, multi-worker capacity, and
> clean-environment reproducibility on a second host.

This is not a hedge. The specific items are enumerated in §6, and each is a
capability that was *requested*, could not be *demonstrated here*, and is
therefore recorded as `NOT VERIFIED` rather than re-described as an equivalent.

---

## 2. What was measured, and how

Every number below came from a command run in this session. Anything that could
not be run is marked `NOT VERIFIED` and no substitute claim is made.

| Measurement | Command / method | Result |
|---|---|---|
| Full suite | `python -m pytest tests/ -q` | **244 passed**, 23 s |
| Security suite | `python -m pytest tests/security -q` | **131 passed** |
| Mutation detection | `python -m pytest tests/security/test_mutation_harness.py -q -rs` | **13 passed, 0 skipped** |
| Clean-environment repro | fresh `git clone` @ `b29c8f5` + new venv + `pip install -e ".[dev]"` | **244 passed**; supervisor absent from the clone, built on demand |
| Independent API retest | `/tmp/retest.py` (HTTP only, no pytest fixtures) | **19 PASS, 0 FAIL, 1 NOT VERIFIED** |

### Independent retest detail

The retest was deliberately written as a separate HTTP-level script so that it
could not inherit the regression suite's fixtures, helpers or assumptions. It
created two ordinary users through the API, seeded a disposable database, and
attacked the running app.

```
A-05 owner recorded                        PASS  owner=user_0e10f82b36
A-05 read by B                             PASS  GET as B -> 404
A-05 search by B                           PASS  0 rows
A-05 delete by B                           PASS  404; record still present for A
A-05 update by B                           PASS  404; value unchanged
A-05 export by B                           PASS  0 rows
A-05 admin cannot read                     PASS  404 (documented: no override)
A-06 document labelled untrusted           PASS  UNTRUSTED_WEB, authority=none
A-06 no external send                      PASS  telegram mode=mock, logged-not-sent
A-06 risky instruction gated               PASS  200 with risk score 20 recorded
A-10 TOTP replay                           PASS  first 200, replay 401
A-11 lockout                               PASS  401,401,401,401,401,429,429
A-01 CapEff/CapBnd zero                    PASS  0000000000000000 / 0000000000000000
A-01 NoNewPrivs                            PASS  1
A-09 Seccomp                               PASS  2
A-02/A-18 rlimits                          PASS  NPROC=24, CPU=30 (= sandbox_timeout_s)
M1  cgroup_v2                              NOT VERIFIED   false
A-04 orphan sweep                          PASS  0 survivors after timeout
A-07 0-byte DB                             PASS  refused, 0 bytes preserved
```

Two initial retest failures were **my script's** bugs, not the product's
(Telegram is in mock mode when no bot token is set; the CPU rlimit derives from
`sandbox_timeout_s`, so it is 30, not the 10 I hardcoded). Both were corrected in
the script and the corrected results are what appear above. This is recorded
because a retest that quietly passes is worth less than one that reports how it
failed first.

---

## 3. Per-finding status

### High (the release gate)

| ID | Finding | v0.2.1 | v0.3.0 | Independent retest |
|---|---|---|---|---|
| A-01 | Capabilities retained | FAIL | **PASS** | `CapEff=0`, `CapBnd=0` from procfs inside the sandbox |
| A-02 | No PID limit | FAIL | **PASS** | `RLIMIT_NPROC=24` visible; bounded probe stops below the cap |
| A-03 | No aggregate memory/concurrency limit | FAIL | **PASS (per worker)** | governor returns 429 on saturation; multi-worker `NOT VERIFIED` |
| A-04 | Timeout leaves orphans | FAIL | **PASS** | double-forked grandchild, 5 s timeout, **0 survivors** |
| A-05 | Cross-user memory access | FAIL | **PASS** | 7/7 API attacks refused, record intact |
| A-06 | Prompt injection advisory only | FAIL | **PASS** | doc labelled untrusted, no external send, risk recorded |
| A-07 | 0-byte DB silently re-initialised | FAIL | **PASS** | refused, bytes preserved |
| A-08 | SSRF | FAIL | **PASS** | 45 tests; metadata IP, loopback, rebinding, redirect all refused |

### Medium

**Closed (PASS):** A-09 (seccomp), A-10 (TOTP replay), A-11 (throttling), A-12 (timing), A-15 (integrity_check), A-16 (downgrade guard), A-18 (CPU), A-19 (file quota), A-20 (detector evasion — no longer the boundary), A-23 (Landlock MAC).

**Open (NOT VERIFIED):** A-13 (viewer token TTL), A-14 (WAL-consistent backup), A-17 (resumable tasks), A-21 (password policy), A-22 (ledger reconciliation), A-25 (fingerprint omits autonomy), A-26 (MFA recovery), A-27 (token rotation), A-28 (connector revocation), A-29 (multi-process SQLite), A-30 (sandbox latency).

### Low

A-24 — `NOT VERIFIED`, unchanged.

---

## 4. Release criteria

| # | Criterion | Verdict | Basis |
|---|---|---|---|
| 1 | Secure isolation on the actual target runtime | **PASS (this host)** / **NOT VERIFIED** for others | caps zero, NNP, seccomp, Landlock, namespaces measured; requires Landlock ≥ 2 + userns on the target |
| 2 | Per-task and aggregate resource controls | **PASS** per-task / **NOT VERIFIED** aggregate | `RLIMIT_*` verified; cgroups unavailable; governor is per-worker |
| 3 | Complete workload termination | **PASS** | 0 surviving orphans, verified not assumed |
| 4 | Zero cross-tenant memory access | **PASS** | 11 tests + 7 independent API probes |
| 5 | Effective trust-boundary enforcement | **PASS** | provenance floors; 40 injection cases; boundary independent of classification |
| 6 | SSRF protection across redirects/DNS | **PASS (application layer)** / **NOT VERIFIED** egress | 45 tests; no forward proxy deployed |
| 7 | Fail-closed DB recovery | **PASS** classification/refusal / **NOT VERIFIED** backup drills | integrity-first, read-only inspection, bytes preserved |
| 8 | MFA replay protection | **PASS** | 8-thread race admits exactly one; audited |
| 9 | Mutation-tested controls | **PASS** | 13 mutations, 13 detected, 0 skips |
| 10 | Clean-environment reproducibility | **PASS (this host, fresh clone)** / **NOT VERIFIED** second host | 244 passed from a clean clone |

---

## 5. What must not be claimed

These are the traps the v0.2.1 audit fell into, and they are called out again so
this report cannot be read more generously than the evidence allows:

* **A Python `MemoryError` is not proof of host memory protection.** The proof is
  `RLIMIT_AS` being enforced by the kernel and read back from `getrlimit()`.
* **"Sandboxed" is not a claim.** The claimed controls are itemised in
  `EXECUTION_HOST_SECURITY.md` §3 with the procfs evidence for each.
* **The API reporting `isolated: true` is not evidence.** That field is derived
  from `containment_status()`, which probes the supervisor; the tests assert
  kernel state instead.
* **Detector accuracy is not claimed.** Nothing depends on it — untrusted content
  is denied authority by provenance, so a 0% detection rate changes no outcome.
* **No live external service was exercised.** Gmail, Calendar and Telegram had no
  credentials; retest confirms `mode=mock, status=logged-not-sent`, i.e. nothing
  left the process.
* **cgroups v2 was not achieved.** Recorded `NOT VERIFIED`, mechanism documented
  as PID-namespace kill, not presented as an equivalent.

---

## 6. Residual risk register

| # | Risk | Severity | Why accepted now |
|---|---|---|---|
| R1 | No kernel-level aggregate memory ceiling (no cgroups) | High | concurrent×per-workload is bounded by the governor, but not by a kernel object; needs a delegated cgroup2 hierarchy in production |
| R2 | No egress proxy / DNS pinning at connect | High | application-layer SSRF validation only; a production deployment should force egress through a deny-by-default proxy |
| R3 | Workload runs as namespace-root | Medium | zero capabilities verified; namespace-root cannot act on objects outside its namespace, but this is a narrower margin than a distinct uid |
| R4 | Kernel LPE from inside the sandbox | High | out of scope for this layer; run the supervisor inside a VM or a hardened runtime tier |
| R5 | Throttle state is per-process | Medium | multi-worker deployments need a shared store |
| R6 | Backup path not WAL-consistent (A-14) | High | no scheduled backup; use `sqlite3 .backup` before relying on a copy |
| R7 | Sandbox latency (A-30) | Low | containment costs namespace + chroot setup per run |
| R8 | Prompt injection through a trusted user | Medium | a human pasting hostile text *is* the authorised party; mitigated by the risk gate + audit, not eliminated |

---

## 7. Reproduction

```bash
git clone https://github.com/muhammadashir0/skyla-prime.git && cd skyla-prime
git checkout b29c8f5
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

python -m pytest tests/ -q                                        # 244 passed
python -m pytest tests/security/test_mutation_harness.py -q -rs   # 13 passed, 0 skipped
SKYLA_INIT_DB=1 python -c "import skyla.api.app"                  # builds the supervisor
```

Requirements: Linux with user namespaces and **Landlock ABI ≥ 2**, plus `gcc`
(the mutation harness rebuilds the supervisor from mutated source). On a host
without those, `test_host_containment.py` **skips** — and per the rules above,
that skip means `NOT VERIFIED`, not pass.

---

## 8. Recommendation

**Do not promote to production.** Independent review should focus on R1 (cgroup
delegation), R2 (egress proxy), R4 (runtime tier) and R6 (backup path). The P0
authorization, tenant-isolation, trust-boundary and fail-closed-recovery work is
in place, mutation-tested, and has been retested through the HTTP API by a script
that shares no code with the test suite.
