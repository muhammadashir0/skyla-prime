# PRIME CONTAINMENT — MFA & Authentication Hardening

**Scope:** Mission 6, audit findings **A-10** (TOTP replay), **A-11** (no throttling), **A-12** (timing enumeration).
**Priority:** P1. Related P1 findings **A-13** (30-day viewer token), **A-21** (no password policy), **A-26** (no MFA recovery), **A-27** (no token rotation) are **NOT VERIFIED** in v0.3.0 — see §7.

---

## 1. TOTP replay prevention (A-10)

### The finding

v0.2.0 accepted any code matching within a ±1 step window (±30 s). The same code could be replayed for the rest of that window. The audit authenticated twice with one code and both succeeded.

### The fix

Replay protection is a database decision, not an in-process one:

```python
def _claim_totp_step(self, user_id: str, step: int) -> bool:
    cur = self.db.execute(
        "UPDATE users SET mfa_last_step=? WHERE id=? AND mfa_last_step < ?",
        (step, user_id, step))
    return cur.rowcount == 1
```

`users.mfa_last_step INTEGER NOT NULL DEFAULT 0` (migration 6). The predicate `mfa_last_step < step` makes acceptance **monotonic and single-use**:

* a code already used → `rowcount == 0` → refused;
* an *older* code → `rowcount == 0` → refused, so replaying "backwards" is also impossible;
* atomicity is delegated to SQLite: two concurrent logins cannot both read-modify-write, so exactly one wins.

Verification order is: credentials → MFA match → **claim**. A claim is only attempted after the code has already matched, so a wrong code never advances `mfa_last_step` (which would otherwise let an attacker lock out a legitimate user).

`verify_totp()` (stateless) is retained for diagnostics only; authentication goes through `verify_totp_step()` + `_claim_totp_step()`.

### Evidence

| Test | Asserts |
|---|---|
| `test_totp_code_cannot_be_reused` | same code: first login succeeds, second refuses |
| `test_older_code_cannot_be_used_after_newer` | a `t-30s` code is refused after a newer one |
| `test_concurrent_replay_allows_exactly_one` | **8 threads, one code → exactly 1 success** |
| `test_replay_rejection_is_audited` | `auth.mfa.replay_rejected` written to `audit_log` |
| `test_wrong_code_still_fails` | `000000` refused |
| `test_password_still_required_with_mfa` | correct code + wrong password refused |

Mutation proof: `test_mutation_mfa_replay_claim_is_load_bearing` replaces `_claim_totp_step` with `lambda: True` and shows the replay then succeeds — confirming the claim is what enforces the control, not an accident of ordering.

---

## 2. Login throttling and account lockout (A-11)

`skyla/throttle.py` implements two independent counters:

| Counter | Default | Purpose |
|---|---|---|
| per-account | 5 failures / 900 s window → 900 s lockout | protect one account |
| per-source | 20 failures / 900 s → 900 s lockout | slow distributed guessing from one host |

API behaviour: `HTTP 429` with a `Retry-After` header and an audit event (`auth.login.blocked`). The lockout is checked **before** credential verification, so once locked even the correct password is refused (no oracle during lockout).

`record_success` clears the counter, so a user who mistypes once is not penalised for the rest of the day.

Verified by `test_repeated_failures_are_throttled`, `test_lockout_blocks_before_credential_check`, `test_per_remote_throttle`, `test_success_resets_the_counter`.

---

## 3. User enumeration (A-12)

The audit measured unknown-user responses at ~3 ms and known-user-wrong-password at ~77 ms — a 25× oracle.

Fix: an unknown user is verified against a fixed dummy hash (`_DUMMY_HASH`), so both paths pay the same PBKDF2 cost. `test_unknown_user_costs_the_same_as_a_wrong_password` measures both and fails if the unknown path is more than 4× faster than the wrong-password path.

The API response body is identical for every failure: `"Invalid credentials or MFA code"`.

---

## 4. Session and token handling (current state)

* Sessions and API tokens are stored hashed (`_hash_token`), never in plaintext.
* Tokens carry an expiry and are revocable; revocation is checked on every request.
* `AuthService.authenticate()` is the single credential path; there is no second implementation to drift.

---

## 5. Concurrency

`test_concurrent_replay_allows_exactly_one` is the concurrency test the mission requires for MFA. Session invalidation concurrency is covered by the existing v0.2.0 session tests (`tests/unit/test_auth.py`), which assert a revoked token is refused on the next request; v0.3.0 does not change that code path.

---

## 6. Audit events

| Event | When |
|---|---|
| `auth.login.blocked` | throttle/lockout refused an attempt |
| `auth.mfa.replay_rejected` | a TOTP step was already consumed |
| `auth.login` / `auth.logout` | successful transitions |
| `token.*` | issue / revoke |

---

## 7. Not verified (P1 items still open)

| Finding | Status | Note |
|---|---|---|
| A-13 viewer token 30-day lifetime | **NOT VERIFIED** | token TTL configuration unchanged; a shorter default was not adopted because the deployment contract for the viewer was not reconstructed |
| A-21 no password policy | **NOT VERIFIED** | no complexity/length enforcement added; bootstrap password remains operator-supplied |
| A-26 no MFA recovery path | **NOT VERIFIED** | no recovery codes; an operator can reset `mfa_enabled` directly, which is an administrative action, not a recovery flow |
| A-27 no credential rotation | **NOT VERIFIED** | no scheduled rotation of API tokens or the bootstrap credential |
| A-28 no connector revocation | **NOT VERIFIED** | connector credentials cannot be revoked through the API |

These are recorded as open in the acceptance report. Mission 6 is **P1**, and the release criteria require MFA replay protection specifically (now **PASS**), not the closure of every P1 item.

---

## 8. Limits

* Throttle state is **in-process**. A multi-worker deployment gets per-worker counters, so the effective limit is `workers × max`. A shared store (Redis, or a SQLite table) is required for a hard global limit — **NOT VERIFIED**, and noted as a documented limitation, consistent with A-29 (multi-process SQLite untested).
* `RLIMIT`-style lockout is not applied to the MFA *claim* path beyond the throttle; repeated replay attempts are refused but only counted as normal auth failures.
