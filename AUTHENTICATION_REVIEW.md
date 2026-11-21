# AUTHENTICATION & AUTHORIZATION REVIEW — SKYLA PRIME v0.2.1

**Target:** `skyla/auth.py`, auth/authz paths in `skyla/api/app.py`
**Method:** source review + live attack against a running instance
**Date:** 2026-11-21
**Result: 6 PASS · 8 FAIL · 2 NOT VERIFIED**

---

## 1. Summary

The v0.2.0 identity layer is architecturally sound: passwords are properly salted and slow-hashed,
tokens are hashed at rest, sessions are revocable, capabilities are enforced server-side at the route,
and the role∩scope intersection correctly blocks token-based escalation. Independent testing
confirmed that the *stated* escalation paths are closed.

However, several operational security properties that matter in a real deployment are absent or
mis-specified: **no login throttling**, **no MFA replay protection**, **username enumeration by
timing**, **credential minting by read-only principals**, and a **cross-user memory leak**.

## 2. Results

| # | Property | Result | Evidence |
|---|---|---|---|
| 1 | Password hashing | **PASS** | PBKDF2-HMAC-SHA256, 200 000 iterations, 16-byte per-user salt, `hmac.compare_digest` |
| 2 | Password strength policy | **FAIL (Medium)** | none enforced; `"x"` accepted as a password at user creation |
| 3 | TOTP MFA | **PASS** | RFC 6238, ±1 window; wrong/absent code → 401 |
| 4 | **MFA replay protection** | **FAIL (Medium)** | same code accepted 5/5 times; no last-used step tracking |
| 5 | MFA recovery mechanism | **FAIL (Low)** | no recovery codes; a lost device is unrecoverable without admin DB surgery |
| 6 | Session expiry | **PASS** | 8 h `expires_at` enforced in SQL |
| 7 | Session invalidation | **PASS** | logout → `revoked=1` → immediate 401 |
| 8 | Token rotation | **FAIL (Low)** | no rotation endpoint; requires revoke + re-mint |
| 9 | Token hashing at rest | **PASS** | SHA-256 of the token, never plaintext |
| 10 | Scoped token enforcement | **PASS** | viewer-minted `["execute","tasks:create","*"]` still 403 on `POST /api/tasks` |
| 11 | Role permissions | **PASS** | viewer 403 on create-user and task-create; operator 403 on create-user |
| 12 | Explicit permission denial | **PASS** | `-capability` entries override role/wildcard grants |
| 13 | Per-agent authorization | **PASS** | plan is computed, and every agent in it is checked before execution |
| 14 | Per-connector authorization | **PASS** | `connector:<name>:write` required on all three write endpoints |
| 15 | **Cross-user isolation — tasks** | **PASS** | Bob sees 0 of Alice's tasks; direct fetch → 404 |
| 16 | **Cross-user isolation — documents** | **PASS** | search/list filtered by `owner_id` |
| 17 | **Cross-user isolation — memories** | **FAIL (High)** | Bob read Alice's value and **deleted** her record (200) |
| 18 | CSRF | **N/A / PASS** | bearer-token design, no cookie-based session ⇒ not CSRF-susceptible |
| 19 | Cookie security | **N/A** | no cookies used; session token is held in memory by the SPA |
| 20 | Bootstrap account security | **PASS (partial)** | generated password → `0600` file, never logs; but see #21 |
| 21 | Bootstrap idempotence | **FAIL (High)** | a 0-byte DB silently re-bootstraps an admin (see DB report) |
| 22 | **Login throttling / lockout** | **FAIL (Medium)** | 12 consecutive failures, no delay, no lockout |
| 23 | **Username enumeration** | **FAIL (Medium)** | unknown user 3 ms vs real user 77 ms (PBKDF2 runs only for real users) |
| 24 | Credential minting capability | **FAIL (Medium)** | `POST /api/auth/tokens` gated on `tasks:read` ⇒ **viewers can mint 30-day tokens** |
| 25 | Audit attribution | **PASS** | actor is the username; `authz.denied` recorded |
| 26 | Legacy shared token | **PASS (documented risk)** | maps to `legacy-admin`; attributable but all-powerful — must be disabled in production |
| 27 | Live credential compromise blast radius | **NOT VERIFIED** | no live OAuth/bot credentials available |
| 28 | Rate limiting at transport | **NOT VERIFIED** | none in-app; depends on a reverse proxy that is not part of this repo |

## 3. Detailed findings

### 3.1 Cross-user memory disclosure and destruction — **HIGH**

`POST /api/knowledge/memory` creates the record, but — unlike documents and tasks — it **never stamps
`owner_id`**, so the row defaults to the migration's `'admin'`. Both read paths then omit the
`_visible()` filter that the rest of the codebase applies.

Reproduction (two operators, Alice and Bob):
```
alice → POST /api/knowledge/memory {"key":"alice_secret","value":"ALICE-PRIVATE-CONTENT-9931"}
alice → id = mem_ace8f4d354
bob   → GET    /api/knowledge/memory?q=ALICE-PRIVATE
        [{"id":"mem_ace8f4d354","key":"alice_secret",
          "value":"ALICE-PRIVATE-CONTENT-9931","owner_id":"admin"}]      <-- leaked in full
bob   → DELETE /api/knowledge/memory/mem_ace8f4d354   -> 200             <-- destroyed
```

So any authenticated principal can read **and delete** every memory in the system. This directly
contradicts the v0.2.0 claim of cross-user isolation, and memories are exactly where personal
preferences and context are stored.

**Remediation.**
1. `remember()` must accept and persist `owner_id`.
2. `recall()` must filter by owner (`_visible`), like `search()`/`docs()` do.
3. `forget()` must verify ownership and return **404** for foreign ids.

### 3.2 No MFA replay protection — **MEDIUM**

`verify_totp` is stateless: it recomputes the expected code for `now-30, now, now+30` and compares.
Nothing records which time-step was last accepted.

```
first use : True
replay #1 : True
replay #2 : True
replay #5 : True
```

An attacker who observes a code (shoulder-surf, phishing proxy, or a compromised client) can reuse it
for the remainder of its window — up to ~90 s with `window=1`, longer if the code is cached. The
standard control is to persist `last_used_step` per user and reject `step <= last_used_step`.

**Remediation.** Add a `mfa_last_step INTEGER` column; inside `verify_totp` accept a step only if it
is strictly greater than the stored value, and update it atomically in the same transaction.

### 3.3 No login throttling — **MEDIUM**

Twelve consecutive wrong passwords returned twelve 401s with no delay, no `Retry-After`, no lockout
and no audit anomaly entry. Any internet-reachable deployment is open to offline-speed online guessing
against a known username. Mitigating factor: PBKDF2 at 200k iterations costs ~75 ms per attempt, which
caps a single-threaded attacker at ~13 attempts/second — meaningful, but not a substitute for
throttling, and it does nothing against distributed attempts.

**Remediation.** Per-account and per-IP counters with exponential backoff, a temporary lock after
N failures, `Retry-After`, and an audit event. Enforce at the proxy for distributed protection.

### 3.4 Username enumeration by timing — **MEDIUM**

```
unknown user  -> 401 in 0.0034 s
real user     -> 401 in 0.0770 s      (≈25× slower: the PBKDF2 verify actually ran)
```

The response text is identical (good), but the timing distinguishes registered from unregistered
usernames, enabling account discovery before an attack.

**Remediation.** When the user does not exist, verify against a fixed dummy hash so both paths cost
the same; return the same message (already correct).

### 3.5 Read-only principals can mint durable credentials — **MEDIUM**

```
viewer → POST /api/auth/tokens {"scopes":["execute","tasks:create","*"],"ttl_days":30} → 201
```

The endpoint requires only `tasks:read`, which a **viewer** holds. The minted token is correctly
limited by the viewer's role (no escalation — verified), but a read-only principal can still:
issue long-lived credentials, consume the token table, and create credentials that outlive their own
session. Credential issuance is an administrative act.

**Remediation.** Gate on an `auth:tokens:create` capability held only by admin (or by admin + an
explicit grant), and cap `ttl_days` server-side.

### 3.6 No password policy — **MEDIUM**

`create_user` accepts any string, including `"x"`. Combined with §3.3 an operator with a one-character
password is trivially compromised.

**Remediation.** Minimum length (12+), reject top-10k breached passwords (a small embedded list is
enough), and reject the username as password.

### 3.7 No MFA recovery path — **LOW**

If a user loses their authenticator, there is no recovery code and no admin endpoint to *clear* MFA —
only `enable_mfa` (which overwrites the secret). Operational lockout is likely in practice.

**Remediation.** One-time recovery codes issued at enrolment (hashed), plus an admin `mfa/reset`
endpoint that is audited.

### 3.8 No token rotation — **LOW**

No rotation endpoint. Rotation = revoke + mint, which forces a coordinated client change. Acceptable
for now; document the procedure.

## 4. What is genuinely well-built (independently confirmed)

- **Password storage** is textbook: per-user salt, high iteration count, constant-time comparison, no
  password ever logged or returned.
- **Token storage**: only SHA-256 hashes are persisted; the raw token is shown once.
- **Revocation is immediate and server-side** for both sessions and API tokens (verified: after
  logout, the same token yields 401).
- **Role ∩ scope is correctly implemented.** This is the single most commonly bungled part of a
  scoped-token design, and the attempt to escalate a viewer's token to `execute` + `*` failed.
- **Authorization is genuinely server-side** and applied at the route, not merely hidden in the UI.
- **Explicit-deny grants** are an unusual and correct refinement — revoking a role-provided capability
  actually works, which is a defect most implementations carry.
- **Foreign-record access returns 404**, not 403 — no existence oracle (for tasks and documents).
- **Audit attribution** uses the principal's username, including `authz.denied` events.

## 5. Authorization matrix (verified live)

| Actor | create task | create user | mint token | read others' tasks | read others' memories | execute code |
|---|---|---|---|---|---|---|
| unauthenticated | 401 | 401 | 401 | 401 | 401 | 401 |
| viewer | **403** | **403** | **201** ⚠ | 404/0 ✅ | **LEAK** ❌ | 403 |
| operator | 200 | **403** | 201 | 404/0 ✅ | **LEAK** ❌ | 200 |
| operator + scoped `tasks:read` | **403** | 403 | 403 | n/a | n/a | **403** |
| admin | 200 | 201 | 201 | 200 (by design) | 200 | 200 |
| legacy token | 200 | 201 | 201 | 200 (by design) | 200 | 200 |

## 6. Verdict

**Authentication: PASS with one High finding.** The cryptographic and structural design is sound and
resisted every escalation attempt. The High finding (cross-user memory disclosure/destruction) is a
missing ownership filter on one endpoint pair, not a flaw in the auth model itself, and is a small,
well-understood fix.

**Authorization on protected routes: PASS.** Server-side enforcement, capability-based, correctly
intersected with token scopes, with 404 semantics for foreign records.

**Operational hardening: FAIL.** No throttling, no MFA replay protection, no password policy, timing
enumeration, and token minting available to read-only principals. These are deployment-blocking for
any internet-facing instance even though the core model is right.
