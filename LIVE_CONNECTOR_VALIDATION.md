# Live Connector Validation — v0.2.3 Mission D

**Verdict: all three connectors NOT VERIFIED for live behaviour. No authorized test account exists in this environment.**

A capability is classified `LIVE_VERIFIED` only after a real call against a real provider returned a real result. A mock that returns a canned success is `MOCK_ONLY`, and representing it as a completed external action is prohibited.

---

## 1. Requirement

> Gmail/Calendar/Telegram validated with isolated authorized test accounts; classify each capability `LIVE_VERIFIED` / `IMPLEMENTED_NOT_LIVE_TESTED` / `MOCK_ONLY` / `DISABLED` / `NOT_CONFIGURED`.

## 2. Why live validation could not proceed

**No credentials exist in this environment.** Measured:

```
env | grep -icE "GOOGLE_|TELEGRAM_|OAUTH|REFRESH_TOKEN"   ->  0
~/.config, ~/.skyla*                                     ->  empty
```

Creating an authorized test account requires either interactive OAuth consent (a human with a Google account, plus a configured client ID and redirect URI) or a BotFather-issued Telegram token (a human with a Telegram account). Neither can be produced from a sandbox, and neither may be fabricated.

**The network prerequisite is satisfied**, which matters: if egress were also blocked, the blocker would be ambiguous. It is not.

| endpoint | DNS | TCP 443 |
|---|---|---|
| `www.googleapis.com` | resolves (`172.217.112.4`) | **OK** |
| `oauth2.googleapis.com` | resolves (`192.179.26.95`) | — |
| `api.telegram.org` | resolves (`149.154.166.110`) | **OK** |

So the blocker is **credentials**, not connectivity. A live test is one authorized account away, and would be executed against the `connector-google` / `connector-telegram` egress policies already defined in `skyla/egress.py`.

## 3. Classification

| Capability | Class | Basis |
|---|---|---|
| Gmail — read messages | **NOT_CONFIGURED** | no client ID, no refresh token, no account |
| Gmail — send message | **NOT_CONFIGURED** | same; and sending requires explicit authorization that was never granted |
| Gmail — modify labels / archive | **NOT_CONFIGURED** | same |
| Calendar — list events | **NOT_CONFIGURED** | no credentials |
| Calendar — create event | **NOT_CONFIGURED** | same; calendar mutation requires explicit authorization |
| Calendar — update/delete event | **NOT_CONFIGURED** | same |
| Telegram — send message | **NOT_CONFIGURED** | no bot token |
| Telegram — read updates | **NOT_CONFIGURED** | same |
| All of the above, against the mock transport | **MOCK_ONLY** | exercised by `tests/security/` connector tests; proves code paths, proves nothing external |

**No capability in this release may be described as `LIVE_VERIFIED` or even `IMPLEMENTED_NOT_LIVE_TESTED` on the basis of these results.** `IMPLEMENTED_NOT_LIVE_TESTED` would at least require the code path to be exercised against the real provider's request/response contract with credentials present but a call withheld. That has not happened either, because with no credentials the code cannot reach the point of constructing an authenticated request.

## 4. What the existing evidence does support

| Check | Result | What it proves |
|---|---|---|
| Connector code paths execute against a mock | PASS (`tests/security/`) | routing, argument validation, error handling |
| A mock response is never reported as an external action | **PASS** — `EXTERNAL_ACTION_INTEGRITY.md` | the honesty control that this mission is most concerned with |
| Provider endpoints reachable (TLS, DNS) | PASS (§2) | the network would permit a live test |
| Egress policy exists per connector | PASS (`connector-google`, `connector-telegram`) | a live test would be confined |

The honesty control is the one that matters most and it holds: in this release a simulated send is labelled as simulated. That is better than a live integration whose mock is indistinguishable from reality — but it is not live validation, and it is not counted as such.

## 5. Instructions to complete this gate

1. Create two **isolated** test accounts (not personal, not production): one Google account, one Telegram account with a bot via BotFather.
2. Register an OAuth client; complete consent once to obtain a refresh token. Store it outside the repository.
3. Run each capability against the real provider with `SKYLA_EGRESS_POLICY=connector-google` / `connector-telegram` so the calls travel the same confined path a deployment would use.
4. Record for each: request shape, provider response, HTTP status, message ID returned, and a screenshot or export proving the message arrived in the isolated account.
5. **Sending is an external action**: do not send to any address or chat other than the isolated test account. No real user contact without explicit authorization.
6. Update §3 with `LIVE_VERIFIED` only for capabilities whose real result is in hand.

## 6. Verdict

**CONN-01/02/03: NOT VERIFIED.** Blocker: no authorized test accounts and no provider credentials in this environment; provider endpoints are reachable, so the blocker is authorization rather than network.

Release implication: live connectors are a mandatory production control. Production stays **NO-GO** until at least one read and one write path per provider is verified against a real authorized account.
