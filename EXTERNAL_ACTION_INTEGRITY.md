# EXTERNAL ACTION INTEGRITY — SKYLA PRIME v0.2.1

**Target:** action ledger (`skyla/db.py`), write endpoints in `skyla/api/app.py`, connectors
**Method:** source review + live duplicate/conflict/in-flight attacks against a running instance
**Date:** 2026-11-21
**Result: 7 PASS · 2 FAIL · 1 NOT VERIFIED**

---

## 1. Complete inventory of external-write operations

Independently enumerated from the route table (not from the implementer's list):

| Endpoint | Connector | Operation | External effect | Ledger-guarded |
|---|---|---|---|---|
| `POST /api/workflows/gmail/draft` | gmail | `draft.create` | Gmail draft created | **Yes** |
| `POST /api/workflows/meeting` | google-calendar | `event.create` | Calendar event created | **Yes** |
| `POST /api/workflows/telegram` | telegram | `message.send` | Message delivered | **Yes** |
| `POST /api/tasks` | core | `task.create` | internal only | **Yes** (belt-and-braces) |
| `POST /api/workflows/inbox` | gmail | *read-only* (search + summarise) | none | n/a |
| `POST /api/workflows/research` | web | *read-only* (GET) | none | n/a |

**Completeness check:** there are exactly **three** genuine external writes, and all three are
guarded. No send-mail path exists in the Gmail connector (drafts only), so email delivery — the highest
consequence action — is not implementable today. This is a genuinely good design property: the most
dangerous operation is absent rather than merely disabled.

**Residual risk:** `POST /api/workflows/inbox` and `/research` are `POST` but read-only; they are
correctly *not* ledgered. If either gains a write side effect later, the route-table invariant test
will not catch it (it only asserts that named paths have keys). Recommend making the test enforce
"every endpoint whose connector method is a write must be guarded" rather than a hard-coded list.

## 2. Results

| # | Property | Result | Evidence |
|---|---|---|---|
| 1 | All writes identified | **PASS** | route-table enumeration, 3 external writes, all guarded |
| 2 | Idempotency enforced on all writes | **PASS** | `_ledger_guard` on all three + a build-time test |
| 3 | Duplicate returns recorded result | **PASS** | second Telegram call returned `duplicate: true`, `original_state: completed` **and the same body text** |
| 4 | Fingerprint mismatch rejected | **PASS** | same key + different text → **409** |
| 5 | In-progress cannot execute twice | **PASS** | `pending` key → **409 "Operation with this idempotency key is in flight"** |
| 6 | Unknown outcome blocks blind retry | **PASS** | `recover_interrupted_ledger()` sets `unknown`; a retry is refused, not executed |
| 7 | Ledger durability across restart | **PASS** | key resolved from SQLite after process restart (single-file DB) |
| 8 | **Recovery/reconciliation implemented** | **FAIL (Medium)** | the *routine* that reconciles provider state for `unknown` entries is **not implemented**; `unknown` is a terminal parked state |
| 9 | Fingerprint covers effect-determining fields | **FAIL (Low)** | see §3.2 — autonomy level is included for meetings but the fingerprint for tasks covers *only* the instruction |
| 10 | Live provider idempotency / reconciliation | **NOT VERIFIED** | no live credentials; providers were never contacted |

## 3. Detailed findings

### 3.1 Reconciliation is documented but not built — **MEDIUM**

`IDEMPOTENCY_DESIGN.md` §6 is honest about this: the ledger correctly classifies a crashed write as
`unknown`, and the system correctly refuses to retry it blindly. That is the safe half. The **other**
half — "list recent provider drafts/events/messages, match the fingerprint, adopt the found record" —
does not exist in code.

Consequence: a crash between *provider accepted* and *ledger completed* leaves an operation that can
never be resolved automatically. An operator must inspect the provider manually. The system fails
*safe* (no duplicate), but the operation is stuck and the user is never told the outcome.

Because no live credential exists in this environment, implementers must not claim this is resolved;
it is correctly labelled here as **not implemented**.

**Remediation.** For each connector add `find_by_fingerprint(fp, window)`, and on startup (or on
explicit `POST /api/ledger/{key}/reconcile`) attempt adoption; if the provider has no read-back (or the
window has passed) mark `unreconcilable` and notify the operator through an audit event + `/api/metrics`
counter.

### 3.2 Task fingerprint is narrower than the effect — **LOW**

`POST /api/tasks` fingerprints `sha256(instruction)` only. `autonomy_level` and `title` are part of
the request but not the fingerprint, so the same key with `autonomy_level: 0` and then
`autonomy_level: 2` is treated as an identical request and replayed, even though the second request
asked for a materially different execution policy. The meeting endpoint *does* include
`autonomy_level` in its fingerprint, so this is an inconsistency.

**Remediation.** Include every effect-determining field in the canonical fingerprint; centralise
fingerprinting so new fields are not forgotten.

## 4. Adversarial scenarios exercised

| Scenario | Result |
|---|---|
| Client retries a Telegram send after a timeout | **Replayed**, no second message |
| Same key, edited message body | **409** |
| Two clients race with the same key | Second sees `pending` → **409 in flight** |
| Process crashes after claim, before record | Entry becomes `unknown` at startup; retry **refused** |
| Server restart, then duplicate | Replay from SQLite, no re-execution |
| Gmail draft retried | Replay; mock mode never sends |
| `idempotency_key` omitted | Executes normally (no protection) — by design, and documented |

**Note on the last row:** because the key is caller-supplied, a client that omits it gets no
protection. All three write endpoints accept `null`. Consider a server-generated dedup window (e.g.
`connector + fingerprint` within N seconds) as a safety net for clients that forget.

## 5. Secrets and egress safety (connector-level)

| Check | Result |
|---|---|
| Gmail can *send* mail | **No such code path** (drafts only) — strongest available guarantee |
| Mock mode cannot masquerade as live | **PASS** — `mode: mock`, `live: False`, responses say `logged-not-sent` |
| Credentials in sandbox | **PASS** — connectors run on the host, never inside the sandbox |
| Credentials in logs | **PASS** — tokens are not logged; redaction covers `Bearer`/`api_key`/`token` |
| Per-connector write capability | **PASS** — all three gated |
| Per-connector credential revocation | **FAIL (Low)** — no endpoint; requires env change + restart |

## 6. Verdict

**External action integrity: PASS** for the properties that can be verified without live providers.
The ledger design is correct and the three dangerous operations are all guarded, with duplicate,
conflict, in-flight and crash-recovery behaviour independently reproduced.

**Reconciliation: FAIL (Medium)** — the safe-failure half exists; the resolution half does not. Until
it does, an interrupted external write is a permanently stuck operation requiring manual provider
inspection. This should be closed before any live connector is enabled, because it is precisely the
scenario the ledger exists to handle.
