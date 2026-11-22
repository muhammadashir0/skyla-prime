# Live Connector Final Report — v0.2.4 Mission 4

**Verdict: no connector is LIVE_VERIFIED. All remain NOT VERIFIED for production.**

No provider credentials exist in this environment, so no live call was made. Nothing below is inferred from the implementation; a connector is LIVE_VERIFIED only after an authorised call against the real provider, and this release made none.

---

## 1. What was checked

| Connector | Credentials present | Mode reported by the code | Production verdict |
|---|---|---|---|
| Gmail | **no** | `mock` — "Mock mode — set GOOGLE_OAUTH_* + GOOGLE_REFRESH_TOKEN for live" | **NOT VERIFIED** |
| Google Calendar | **no** | `mock` | **NOT VERIFIED** |
| Telegram | **no** | `mock` | **NOT VERIFIED** |

```
$ grep -icE "GOOGLE_|TELEGRAM_|OAUTH|REFRESH_TOKEN" <<< env   →  0
```

Config reads `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`, `GOOGLE_REFRESH_TOKEN`, `TELEGRAM_BOT_TOKEN`, all empty.

**Positive finding:** the connectors do not disguise this. `GmailConnector().mode` returns `mock`, `.live` returns `False`, and the detail string names the missing variables. The platform's established rule — mocks are `MOCK_ONLY`, never reported as live — holds here.

## 2. Capability classification

Per the mission's taxonomy. "Implemented" means the code path exists and is unit-tested against a stub; it does **not** mean it works against the provider.

| Capability | Implementation | Live verdict |
|---|---|---|
| Gmail OAuth + token refresh | implemented | **IMPLEMENTED_NOT_LIVE_TESTED** |
| Gmail message list / search | implemented | **IMPLEMENTED_NOT_LIVE_TESTED** |
| Gmail thread retrieval | implemented | **IMPLEMENTED_NOT_LIVE_TESTED** |
| Gmail draft creation | implemented | **IMPLEMENTED_NOT_LIVE_TESTED** |
| Gmail controlled send | implemented | **IMPLEMENTED_NOT_LIVE_TESTED** |
| Gmail token **revocation** | implemented | **IMPLEMENTED_NOT_LIVE_TESTED** |
| Calendar availability | implemented | **IMPLEMENTED_NOT_LIVE_TESTED** |
| Calendar event create / update | implemented | **IMPLEMENTED_NOT_LIVE_TESTED** |
| Calendar attendee invite | implemented | **IMPLEMENTED_NOT_LIVE_TESTED** |
| Calendar conference link | implementation-dependent | **IMPLEMENTED_NOT_LIVE_TESTED** (Workspace-tier dependent) |
| Telegram bot auth | implemented | **IMPLEMENTED_NOT_LIVE_TESTED** |
| Telegram message delivery | implemented | **IMPLEMENTED_NOT_LIVE_TESTED** |
| Telegram command authorization | implemented | **IMPLEMENTED_NOT_LIVE_TESTED** |
| Telegram duplicate prevention | implemented | **IMPLEMENTED_NOT_LIVE_TESTED** |

**Zero capabilities are LIVE_VERIFIED.** The unit tests prove the request is *shaped* correctly; they cannot prove Google accepts it, that a token refresh returns a usable token, or that a revoked token then fails. Those are precisely the failures that only appear in production.

## 3. The validation harness

`scripts/connector_validation.py` exists so that live validation is one command for an operator who has credentials. Its safety properties were verified:

```
$ python -m scripts.connector_validation
refusing: set SKYLA_CONNECTOR_TEST=1 to acknowledge these are authorised test accounts

$ SKYLA_CONNECTOR_TEST=1 python -m scripts.connector_validation
refusing: missing GOOGLE_OAUTH_CLIENT_ID, ... — cannot validate live

$ _guard_recipient('victim@example.com')
refusing: recipient 'victim@example.com' is not the declared test address
```

Three refusals, each tested:

1. **No accidental production run** — requires explicit acknowledgement.
2. **No missing-credential half-run** — refuses rather than reporting a partial result as complete.
3. **No wrong recipient** — a harness that can email an arbitrary address is a liability, so the target must match `SKYLA_TEST_EMAIL`.

The classifier returns `NOT_CONFIGURED` (not `FAIL`) when credentials are absent, so an unconfigured system is not confused with a broken one.

Deliberate design choices:

- **It does not auto-send email.** A controlled send is an external action; the harness marks it an operator step and records the provider-side message id for verification. Automating it would mean the harness could send mail as a side effect of a test run.
- **It does not auto-invite attendees.** Invitations notify real people and cannot be un-sent.
- **Duplicate prevention is reported, not asserted.** The harness sends the same content twice and reports whether the ids matched; it does not claim deduplication works because a stub said so.

## 4. What live validation must establish

The unit tests cannot reach these. Each is a separate failure mode:

| Question | Why a stub cannot answer it |
|---|---|
| Does Google accept the request shape? | scopes, encoding, and required fields are enforced server-side |
| Does a refresh token yield a working access token? | this is the entire OAuth lifecycle; a stub returns a fake token with no expiry semantics |
| **Does a revoked token fail closed?** | the security-critical case: after revocation the connector must error, not silently continue with a cached token |
| Do threads and drafts round-trip? | drafts have provider-side ids and quota |
| Does an event land on the provider's calendar? | "created" locally ≠ present in the provider's API |
| Do invites reach the attendee? | delivery is provider-side and asynchronous |
| Does Telegram deliver, and is duplication prevented? | requires the real API's message ids |
| Is a command from an unauthorised chat rejected? | an authorization boundary that only exists in mocks is untested |

## 5. Exact missing requirement

> **Dedicated test credentials, not production ones:**
> - a Google Cloud project with Gmail and Calendar APIs enabled, an OAuth client, and a refresh token for a **test account**;
> - a Telegram bot created solely for validation, plus a test chat id;
> - authorisation to send one email, create one event on a test calendar, and post to a test chat;
> - a recipient for the controlled email that is the test account itself.
>
> Absent: no such credentials exist in this environment; no external communication is authorised.

Credentials must enter through the secure config path, **never** Git and never the model context — consistent with the M1 finding that provider credentials are read from the environment and never appear in a model payload.

## 6. Consequences for the release gate

Live connector validation is one of the required release conditions. It cannot be met by testing more code. The production assessment therefore records connectors as **NOT VERIFIED**, and this alone is sufficient to withhold production approval regardless of every other result.

The honest position: the integration code is plausible, shaped correctly, and untested against the systems it exists to talk to. That is a weaker claim than "connectors work", and the weaker claim is the true one.

## 7. Verdict

**NOT VERIFIED.** No live call was made because no credentials exist. The harness is ready and refuses to run unsafely. Not one connector capability is LIVE_VERIFIED, and none will be until an authorised test account is exercised against the real provider.
