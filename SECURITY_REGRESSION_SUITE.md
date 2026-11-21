# PRIME CONTAINMENT — Security Regression Suite

**Scope:** Mission 7. Tests must fail when a control is weakened, and that claim must itself be tested.
**Status:** **PASS**. 244 tests total; 131 security tests; 13 mutations applied, **13 detected, 0 undetected, 0 skipped**.

---

## 1. The rule this suite follows

> *Do not pass solely because a model/child process/API returns expected text.*

Every security assertion reads state the **kernel or the database** produces, not a value the code being tested composed:

| Instead of | Assert on |
|---|---|
| `result["isolated"] is True` | `CapEff` read from `/proc/self/status` **inside** the workload |
| `"sandboxed" in response` | `RLIMIT_NPROC` read back via `resource.getrlimit()` in the workload |
| a mocked `socket.blocked = True` | an actual `connect()` to a real host listener that receives nothing |
| `memory.deleted == True` | re-read the record as its owner; try as another tenant |
| `db.state == "healthy"` | `PRAGMA integrity_check` on a deliberately page-corrupted file |

A test that reads its own output back proves nothing; the mutation harness is what proves the suite is load-bearing.

---

## 2. Layout

```
tests/
  unit/                     101 tests (pre-existing behaviour, kept green)
  security/
    test_host_containment.py   20   live kernel, real sandbox
    test_memory_tenant.py      11   API x method cross-tenant matrix
    test_trust_boundary.py     25   provenance authority + injection battery
    test_ssrf.py               45   URL/IP/redirect matrix
    test_db_integrity.py       17   fail-closed DB states
    test_auth_mfa.py           12   replay, throttling, timing
    test_mutation_harness.py   13   weakened-control proofs
```

---

## 3. Coverage against the required failure modes

The mission lists specific ways the tests must be able to fail. Each is mapped to a test that fails when that control is removed.

| Required failure mode | Test | Mutation proof |
|---|---|---|
| cap dropping removed | `test_capabilities_are_actually_zero`, `test_bounding_set_is_empty` | `test_mutation_capability_drop_is_load_bearing` |
| NNP disabled | `test_no_new_privs_is_set` | `test_mutation_no_new_privs_is_load_bearing` |
| PID limits disappear | `test_process_limit_is_enforced`, `test_rlimit_values_are_visible_to_the_workload` | `test_mutation_pid_limit_is_load_bearing` |
| memory limits not applied | `test_memory_limit_is_enforced`, `test_memory_rlimit_matches_configuration` | `test_mutation_memory_limit_is_load_bearing` |
| CPU limits removed | `test_cpu_limit_is_set_and_enforced` | (asserted from `getrlimit`, not mutation-tested) |
| process-tree cleanup broken | `test_double_forked_grandchild_is_killed` | (verified by orphan count = 0) |
| user ownership filters removed | `test_cannot_read/search/list/delete/update/enumerate/export` | `test_mutation_owner_filter_is_load_bearing` |
| injection policy enforcement disabled | `test_untrusted_content_cannot_authorize_actions` (40 cases) | `test_mutation_trust_floor_is_load_bearing` |
| URL redirect validation omitted | `test_redirect_hop_is_revalidated` | `test_mutation_redirect_revalidation_is_load_bearing` |
| DB integrity validation bypassed | `test_permissions_never_mask_real_state`, `test_enforce_refuses_*` | `test_mutation_db_integrity_check_is_load_bearing` |
| bootstrap silently recreates admin | `test_enforce_blocks_init_when_disabled`, `test_empty_existing_file_is_not_new` | `test_mutation_bootstrap_guard_is_load_bearing` |
| unsafe provider fallback | fail-closed selection assertions | `test_mutation_execution_fallback_is_load_bearing` |
| MFA replay | `test_totp_code_cannot_be_reused`, `test_concurrent_replay_allows_exactly_one` | `test_mutation_mfa_replay_claim_is_load_bearing` |

---

## 4. How mutations are applied

Two techniques, chosen so production code is never left modified.

### C-level: rebuild a weakened supervisor

```python
def _mutate_supervisor(tmpdir, old, new, *, count=1):
    src = SUP_SRC.read_text()
    if old not in src:
        pytest.skip(...)                       # anchors are exact
    (tmpdir / "sup-mut.c").write_text(src.replace(old, new, count))
    subprocess.run(["gcc", "-O2", "-o", tmpdir / "sup-mut", ...])
    return tmpdir / "sup-mut"
```

The mutant binary is then run against the same probe the real suite uses, and the assertion is inverted: **the probe must now show the weakness**. If it does not, the mutation is "not detected" and the test fails.

Notes earned during implementation:

* `no_new_privs` is set in **two** places (explicitly, and inside the Landlock setup). A single-site mutation does not weaken the runtime, so the harness replaces **all** occurrences (`count=-1`).
* Replacing a call with a *comment* breaks the build (`if (/* … */ != 0)`); the harness substitutes `0`, which compiles and is a genuine no-op.
* A mutation that fails to compile **skips**, and a skip is not a pass. The suite is run with `-rs` and required to report **0 skips**; the NNP mutant originally skipped and was fixed for exactly this reason.

### Python-level: monkeypatch at lookup time

Functions that consult module-level tables (`AUTHORITY_FLOOR`, `is_blocked_ip`) are patched on the module, so the production code path sees the weakened value without any file being touched:

```python
monkeypatch.setattr(trust, "AUTHORITY_FLOOR",
                    {k: Provenance.MODEL_OUTPUT for k in trust.AUTHORITY_FLOOR})
assert trust.require_authority(hostile, "connector:write")   # now passes = weakness
```

Each such test first asserts the **control** (the real code refuses), then asserts the **mutant** (the weakened code allows). Both directions are required: the first proves the control exists, the second proves the test would notice its absence.

---

## 5. Adversarial content used

* 8 injection payloads × 5 untrusted provenances (40 authorization cases), including "SYSTEM OVERRIDE", "developer mode", `<INST>` tags, HTML comments, and system-prompt extraction.
* Zero-width obfuscation (`ig\u200bnore … prior instruc\u200btions`).
* 22 hostile SSRF URLs, 14 blocked IP literals incl. IPv4-mapped IPv6, a resolver double for DNS rebinding, and a public→loopback redirect chain.
* A 300 MB-class allocation against a 128 MB limit; a 64 MB write against a 4 MB `RLIMIT_FSIZE`; a bounded 40-attempt fork probe against `RLIMIT_NPROC=12`.
* A double-forked grandchild under a 5 s timeout, with an orphan sweep of `/proc`.
* A 200-row database with 4 KB of pages overwritten, and a 0666 corrupt file to prove permissions cannot mask corruption.
* 8 concurrent threads racing a single TOTP code.

---

## 6. Bounding (mandatory)

Adversarial tests are resource-bounded by construction:

* no unbounded fork storms — the probe is capped at 40 attempts and asserts a limit below that;
* every workload has `cpu_s`, `memory_mb`, `nproc` and `timeout_s` set explicitly in the helper (`run()` in `test_host_containment.py`);
* the mutation harness runs single workloads, never concurrently;
* the suite completes in ~23 s wall clock, which is itself evidence that nothing ran away.

---

## 7. Running it

```bash
python -m pytest tests/                          # 244 passed
python -m pytest tests/security -q               # 131 passed
python -m pytest tests/security/test_mutation_harness.py -q -rs   # 13 passed, 0 skipped
```

Requirement: a C compiler (mutants are rebuilt) and a kernel with user namespaces + Landlock ABI ≥ 2. Where the contained supervisor is unavailable, `test_host_containment.py` **skips** (via the module-level `skipif`), and that skip must be treated as **NOT VERIFIED**, never as a pass — the acceptance report records `cgroup_v2` in exactly this way.
