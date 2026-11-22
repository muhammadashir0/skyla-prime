# CONNECTOR RELIABILITY REPORT — v0.2.2 PRIME QUALIFICATION

**Mission 6.** Gmail, Google Calendar, Telegram: authentication, token renewal,
revocation, scopes, idempotent execution, duplicate recovery, provider errors,
mock/live separation, provider-confirmed state.

## Verdict

> **Mock/live separation: PASS.** No connector can represent a mock success as a
> real external action, and this is enforced by status verbs plus tests.
> **Live provider behaviour: NOT VERIFIED.** No authorised test accounts exist in
> this environment, and no credential was available. Nothing in this release
> demonstrates a real Gmail read, a real Calendar write, or a real Telegram message.

The mission explicitly forbids representing mock success as a real action. The
strongest statement supportable here is: *the connectors cannot currently lie about
their mode, and their failure paths are exercised against stubs.*

---

## 1. Mock/live model

Every connector derives its mode from credentials at construction:

```python
self.live = bool(settings.google_refresh_token and settings.google_oauth_client_id)
self.mode = "live" if self.live else "mock"
self.detail = "Live Gmail API" if self.live else "Mock mode — set GOOGLE_OAUTH_* ..."
```

Verified in this environment (`tests/security/test_connector_reliability.py`):

| Connector | `mode` | `live` |
|---|---|---|
| Gmail | `mock` | False |
| Google Calendar | `mock` | False |
| Telegram | `mock` | False |

Partial credentials do **not** enable live mode — a client id without a refresh
token stays mock (`test_partial_credentials_do_not_enable_live_mode`). This matters
because a half-configured deployment would otherwise attempt real API calls and fail
obscurely mid-workflow.

## 2. Status verbs: a mock cannot look like a write

This is the core defence against the "mock success presented as a real action"
failure mode. Each write returns a status that cannot be mistaken for completion:

| Connector | Operation | Mock status | Live status |
|---|---|---|---|
| Telegram | `send_message` | `logged-not-sent` | `live` + provider result |
| Gmail | `draft_reply` | `draft-prepared-not-sent` | `live` + provider object |
| Calendar | `create_event` | `event-prepared-not-created` | `live` + provider object |

Tests assert the negative explicitly (`!= "sent"`, `!= "created"`) **and** that no
provider payload key (`result`, `event`, `draft`) is present in a mock response —
so a caller checking for `response["event"]` gets a `KeyError`, not a fabricated
success.

Read paths return fixtures but are labelled: `summarize_inbox()` includes
`note: "Mock data"` and `mode: "mock"`.

## 3. Error handling (exercised against stubs)

Provider stubs returning HTTP 500, and a failing OAuth refresh, both propagate:

| Case | Test | Behaviour |
|---|---|---|
| Telegram POST 500 | `test_telegram_provider_error_is_not_reported_as_success` | raises, no success dict |
| Calendar POST 500 | `test_calendar_provider_error_is_not_reported_as_success` | raises |
| Gmail POST 500 | `test_gmail_provider_error_is_not_reported_as_success` | raises |
| OAuth refresh 500 | `test_token_refresh_failure_aborts_the_action` | raises; action does not proceed |

`raise_for_status()` is used throughout, so no error path converts a failure into a
success. There is **no retry/backoff policy** — a transient 500 surfaces to the
caller rather than being retried, which is safe (no duplicate risk) but not
resilient. Recorded as a limitation.

## 4. Idempotency and duplicate recovery

Duplicate external actions are prevented by the shared ledger, not by the
connectors:

```
key claimed -> provider called once -> ledger_complete(state=completed, response=...)
second attempt -> status=duplicate -> recorded provider response replayed
```

Verified: `test_ledger_prevents_a_duplicate_provider_call` counts provider
invocations and asserts exactly **1** for two attempts with the same key; the replay
carries the stored `provider_response`. Cross-process behaviour is covered in
`MULTI_WORKER_CAPACITY_REPORT.md` (executed=1, replayed=15 across 4 workers).

## 5. Not verified (all live items)

| Requirement | Status | Reason |
|---|---|---|
| Authentication against Google | **NOT VERIFIED** | no OAuth client/refresh token; no authorised account |
| Token renewal against Google | **NOT VERIFIED** | refresh path exercised only against a stub |
| Token revocation | **NOT VERIFIED** | no API path exists to revoke a stored refresh token (also A-28, still open) |
| Permission scopes | **NOT VERIFIED** | actual granted scopes can only be confirmed from a live token response |
| Telegram live send | **NOT VERIFIED** | no bot token |
| Provider-confirmed state | **NOT VERIFIED** | requires a live write followed by a live read-back |
| Provider error taxonomies (429, quota, invalid_grant) | **NOT VERIFIED** | only generic 500 stubs used |

Because none of these could be shown, the connector requirement for release
criterion 8 is **not met**. Live connectors must remain disabled until authorised
test accounts are provisioned.

## 6. Reproducing the controlled environment

When credentials become available, the intended procedure is:

1. Provision a dedicated Google Cloud project and a **test** account (never a
   personal mailbox).
2. Set `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`,
   `GOOGLE_REFRESH_TOKEN` for that account only.
3. Set `TELEGRAM_BOT_TOKEN` for a **throwaway** bot and a private channel.
4. Verify `connector.mode == "live"` before any workflow runs.
5. For each write: perform it, then **read it back from the provider** and compare.
   Only a provider-confirmed read-back counts as verified.
6. Revoke the credentials at the end of the drill and confirm subsequent calls fail.

Step 5 is the one that distinguishes "we called the API" from "the action happened";
it is the reason live status is `NOT VERIFIED` rather than assumed.

## 7. Residual risk

| Risk | Severity | Note |
|---|---|---|
| Live paths entirely unexercised | High | first live call may reveal scope/payload defects |
| No retry/backoff | Medium | transient provider errors surface to the user |
| No connector credential revocation (A-28) | High | a leaked refresh token cannot be withdrawn via the API |
| Refresh token stored in settings | Medium | file permissions only; no KMS/secret manager integration |
