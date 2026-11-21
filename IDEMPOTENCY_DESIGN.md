# IDEMPOTENCY DESIGN — SKYLA PRIME v0.2.0

**Status:** implemented and tested (`tests/unit/test_idempotency_e2e.py`,
`tests/unit/test_idempotency_context.py`, 15 tests).
**Scope:** Workstream 3 — action ledger for every external write.

---

## 1. The failure this prevents

v0.1.0 forwarded a Telegram/Calendar/Gmail call and returned the provider's answer. If the process
died between "provider accepted the request" and "we recorded the result", a retry produced a
**second real message / second calendar event / second email draft**. There was no operation
identity, so nothing on either side could tell the two attempts apart. This is the classic
at-least-once delivery hazard, and for outbound communications the duplicate is *user-visible and
irreversible*.

## 2. The ledger

Table `action_ledger` (schema migration 2):

| Column | Purpose |
|---|---|
| `id` | internal record id (`op_…`) — the unique operation ID |
| `idempotency_key` | **UNIQUE**; caller-supplied operation identity |
| `fingerprint` | SHA-256 of the canonical request payload |
| `connector` | `gmail` / `google-calendar` / `telegram` / `core` |
| `operation` | `draft.create` / `event.create` / `message.send` / `task.create` |
| `state` | `pending` → `completed` \| `failed` \| `unknown` |
| `attempts` | retry tracking (incremented on completion) |
| `provider_response` | recorded provider result (truncated to 2 000 chars), used for replay |
| `created_at` / `updated_at` | timing / staleness detection |

## 3. Lifecycle

```
      ┌──────────── begin(key, fingerprint) ────────────┐
      │                                                  │
  status=new                                       status=duplicate
      │                                                  │
 state=pending                              ┌───────────┴───────────┐
      │                                     │                       │
 perform external write                 state=completed         state=pending
      │                                → REPLAY recorded result   → 409 "in flight"
      ├── success → complete(key,"completed", response)
      └── failure → complete(key,"failed", error)          status=conflict → 409
```

1. **Claim** — `ledger_begin` inserts `pending`, or classifies an existing key.
2. **Execute** — the provider call happens only on `status=new`.
3. **Record** — `ledger_complete` stores the state and the provider response.
4. **Replay** — a duplicate returns the *recorded* result verbatim, plus
   `duplicate: true`, `idempotency_key`, `original_state`. No second external write occurs.
5. **In flight** — a duplicate while the original is still `pending` returns **409** rather than
   racing a second write.
6. **Conflict** — same key, different fingerprint returns **409**. Reusing a key for different
   content is always a caller bug; silently honouring either side would be worse.

## 4. Request fingerprint

`SHA-256` over the canonical fields that determine the external effect:

| Endpoint | Fingerprint input |
|---|---|
| `POST /api/tasks` | instruction |
| `POST /api/workflows/meeting` | `attendee \| autonomy_level` |
| `POST /api/workflows/telegram` | `chat_id \| text` |
| `POST /api/workflows/gmail/draft` | `message_id \| body` |

Only effect-determining fields are included; transport noise (headers, trace ids) is excluded so a
legitimate retry of the same intent still matches.

## 5. Coverage — the invariant is tested, not asserted

`test_all_external_writes_are_ledger_guarded` *introspects the live route table* and fails if any
external-write POST endpoint lacks an `idempotency_key` field:

```
/api/tasks                    ✓   /api/workflows/telegram     ✓
/api/workflows/meeting        ✓   /api/workflows/gmail/draft  ✓
```

Adding a future integration write endpoint without a ledger guard breaks the build.

## 6. Interrupted operations — no blind retry

`recover_interrupted_ledger()` runs at startup and moves any entry left in `pending` to `unknown`:
the process died between claim and record, so **the external effect is indeterminate**. The design
rule is that `unknown` must **never** be retried blindly:

1. Read the ledger record for the key.
2. If `state=unknown`, **reconcile against the provider** — list recent drafts / events / messages and
   look for one matching the fingerprint payload.
3. Found → mark `completed` with the provider's record and return it (no second write).
4. Not found → safe to re-execute with the *same* key.
5. If the provider offers no read-back (or the reconciliation window has passed) → surface to the
   operator for a decision. Never auto-retry.

**Honest status of step 2–5:** the ledger bookkeeping and the `unknown` classification are
implemented and tested (`test_recover_interrupted_ledger`,
`test_interrupted_operation_is_not_silently_reexecuted`). The automatic provider-side reconciliation
routine is **NOT IMPLEMENTED** — no live credentials or safe test account exist in this environment
(Workstream 6 blocker). Today, an `unknown` entry stays `unknown` and blocks blind re-execution,
which is the safe behaviour; the reconciliation helper is documented as the required next step.

## 7. Where provider idempotency is unavailable

- **Telegram Bot API** has **no** native idempotency key. Duplicate protection is therefore
  entirely ledger-side; ledger-side is sufficient for the single-writer case, and reconciliation is
  required for the crash-between-call-and-record case (§6).
- **Google Calendar** supports client-supplied event IDs — a stronger guarantee is available by
  deriving the event id deterministically from the fingerprint. This is **documented as the
  preferred upgrade and NOT implemented** (needs a live test account to validate).
- **Gmail drafts** have no idempotency key; draft creation is cheap and reconcilable by listing
  drafts, so replay-plus-reconcile is the accepted approach.

## 8. Auditability

Every terminal state is written to `audit_log`: `idempotency.replay` and `idempotency.conflict`
record connector, operation and key. A reviewer can reconstruct, for any external write, exactly how
many execution attempts occurred and whether the answer returned to the caller came from a live call
or a replay. `LIMITATION:` the replay audit entry currently records the key but not the actor
identity for replays triggered before authentication resolution; callers are authenticated before
`_ledger_guard` runs, so the acting user is recorded by the corresponding `workflow.*` entry when a
write actually executes.

## 9. Tests

| Test | Assertion |
|---|---|
| `test_ledger_new_duplicate_conflict` | new → duplicate → conflict transitions, attempts counted |
| `test_meeting_workflow_duplicate_replays_same_result` | replay returns identical slots, no second run |
| `test_telegram_workflow_duplicate_replays` | duplicate flagged, `original_state=completed` |
| `test_gmail_draft_is_ledger_guarded` | second draft request replays, mock mode never sends |
| `test_idempotency_fingerprint_conflict` (×2) | different payload on same key → 409 |
| `test_interrupted_operation_is_not_silently_reexecuted` | pending key → 409 in flight |
| `test_recover_interrupted_ledger` | startup recovery marks `unknown` |
| `test_all_external_writes_are_ledger_guarded` | route-table invariant |
| `test_no_real_sends_in_mock_mode` | no live credentials ⇒ mock only |

## 10. Decision record

- **ADR-3.1** Caller-supplied idempotency keys (Stripe pattern) rather than server-derived hashes:
  the caller knows the intent boundary; a hash of the payload would conflate two deliberately
  identical messages.
- **ADR-3.2** Replay the recorded provider result, not just a marker — callers must not have to
  special-case the duplicate path.
- **ADR-3.3** 409 on fingerprint mismatch and on in-flight duplicates: loud failure over silent guess.
- **ADR-3.4** `unknown` is a first-class state that blocks retry, because for outbound
  communications a duplicate is worse than a manual check.
- **ADR-3.5** Store the provider response (truncated) in the ledger so reconciliation has evidence
  and replays are faithful.
