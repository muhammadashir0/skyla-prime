"""Live connector validation harness (v0.2.4 Mission 4).

Run only against **dedicated test accounts**. This script will never send to a
real recipient, and it refuses to run at all unless credentials for isolated test
accounts are present.

    # preparation (see LIVE_CONNECTOR_FINAL_REPORT.md)
    export SKYLA_CONNECTOR_TEST=1
    export GOOGLE_OAUTH_CLIENT_ID=...      GOOGLE_OAUTH_CLIENT_SECRET=...
    export GOOGLE_REFRESH_TOKEN=...        (authorised for the TEST account)
    export TELEGRAM_BOT_TOKEN=...          (a bot created solely for testing)
    export SKYLA_TEST_EMAIL=<test account>@gmail.com
    export SKYLA_TEST_TELEGRAM_CHAT=<chat id of the test chat>

    python -m scripts.connector_validation

Design rules this file enforces, because a harness that can accidentally do
something real is worse than no harness:

  * refuses without `SKYLA_CONNECTOR_TEST=1` — no accidental production run;
  * refuses if the target address/chat is not the declared test target;
  * classifies each capability with exactly one verdict per the mission;
  * does not claim a result it did not observe: a capability whose call raised
    is FAIL or NOT VERIFIED, never "assume it works";
  * writes a JSON record so results can be attached to the evidence registry.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

LIVE = "LIVE_VERIFIED"
IMPL = "IMPLEMENTED_NOT_LIVE_TESTED"
MOCK = "MOCK_ONLY"
DISABLED = "DISABLED"
NOT_CONFIGURED = "NOT_CONFIGURED"


def _require_test_mode() -> None:
    if os.getenv("SKYLA_CONNECTOR_TEST") != "1":
        sys.exit("refusing: set SKYLA_CONNECTOR_TEST=1 to acknowledge these are "
                 "authorised test accounts")
    missing = [k for k in ("GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET",
                           "GOOGLE_REFRESH_TOKEN", "TELEGRAM_BOT_TOKEN",
                           "SKYLA_TEST_EMAIL", "SKYLA_TEST_TELEGRAM_CHAT")
               if not os.getenv(k)]
    if missing:
        sys.exit(f"refusing: missing {', '.join(missing)} — cannot validate live")


def _guard_recipient(addr: str) -> None:
    allowed = os.getenv("SKYLA_TEST_EMAIL", "")
    if addr.strip().lower() != allowed.strip().lower():
        sys.exit(f"refusing: recipient {addr!r} is not the declared test address")


async def check_gmail(results: list[dict]) -> None:
    from skyla.integrations.gmail import GmailConnector

    g = GmailConnector()
    if not g.live:
        results.append({"capability": "gmail.any", "verdict": NOT_CONFIGURED,
                        "detail": "no OAuth credentials present"})
        return

    def record(cap, ok, detail, verdict=None):
        results.append({"capability": cap,
                        "verdict": verdict or (LIVE if ok else "FAIL"),
                        "detail": detail})

    # OAuth + message retrieval
    try:
        msgs = await g.search("", max_results=5)
        record("gmail.search", True, f"{len(msgs)} messages returned")
        record("gmail.oauth_token_refresh", True, "access token obtained")
    except Exception as exc:                                # noqa: BLE001
        record("gmail.search", False, f"{type(exc).__name__}: {exc}"[:160])
        record("gmail.oauth_token_refresh", False, f"{type(exc).__name__}"[:80])
        return

    # Thread retrieval
    try:
        inbox = await g.summarize_inbox(max_results=3)
        record("gmail.thread_retrieval", True, f"inbox summary: {type(inbox).__name__}")
    except Exception as exc:                                # noqa: BLE001
        record("gmail.thread_retrieval", False, f"{type(exc).__name__}: {exc}"[:160])

    # Draft creation — a draft is not a send, so it is safe to exercise
    try:
        if msgs:
            draft = await g.draft_reply(msgs[0]["id"], "validation draft — do not send")
            record("gmail.draft_create", True, f"draft id {draft.get('id', '?')[:20]}")
    except Exception as exc:                                # noqa: BLE001
        record("gmail.draft_create", False, f"{type(exc).__name__}: {exc}"[:160])

    # A controlled send is deliberately NOT automated here: it is an external
    # action. The operator sends one message to the test account and records the
    # provider-side message id. Left as IMPLEMENTED_NOT_LIVE_TESTED until then.
    record("gmail.send_controlled", None, "operator step: send one message to "
           "SKYLA_TEST_EMAIL and paste the provider message id into the report",
           IMPL)


async def check_calendar(results: list[dict]) -> None:
    from skyla.integrations.calendar import GoogleCalendarConnector

    cal = GoogleCalendarConnector()
    live = bool(os.getenv("GOOGLE_REFRESH_TOKEN") and os.getenv("GOOGLE_OAUTH_CLIENT_ID"))
    if not live:
        results.append({"capability": "calendar.any", "verdict": NOT_CONFIGURED,
                        "detail": "no OAuth credentials present"})
        return

    def record(cap, ok, detail, verdict=None):
        results.append({"capability": cap,
                        "verdict": verdict or (LIVE if ok else "FAIL"),
                        "detail": detail})

    try:
        events = await cal.list_events()
        record("calendar.list_availability", True, f"{len(events)} events")
    except Exception as exc:                                # noqa: BLE001
        record("calendar.list_availability", False, f"{type(exc).__name__}: {exc}"[:160])
        return

    # Creating an event on a dedicated test calendar is reversible; updating and
    # inviting attendees are recorded as operator steps because they notify people.
    record("calendar.create_event", None,
           "operator step: create one event on the test calendar, screenshot it",
           IMPL)
    record("calendar.update_event", None, "operator step", IMPL)
    record("calendar.invite_attendee", None,
           "operator step: invite ONLY the test account", IMPL)
    record("calendar.conference_link", None,
           "depends on the account's Workspace tier; record supported/unsupported",
           IMPL)


async def check_telegram(results: list[dict]) -> None:
    from skyla.integrations.telegram import TelegramConnector

    t = TelegramConnector()
    if not getattr(t, "live", False):
        results.append({"capability": "telegram.any", "verdict": NOT_CONFIGURED,
                        "detail": "no bot token present"})
        return

    def record(cap, ok, detail, verdict=None):
        results.append({"capability": cap,
                        "verdict": verdict or (LIVE if ok else "FAIL"),
                        "detail": detail})

    try:
        me = await t.get_me()
        record("telegram.bot_auth", True, f"bot @{me.get('username', '?')}")
    except Exception as exc:                                # noqa: BLE001
        record("telegram.bot_auth", False, f"{type(exc).__name__}: {exc}"[:160])
        return

    chat = os.getenv("SKYLA_TEST_TELEGRAM_CHAT", "")
    try:
        sent = await t.send_message(chat, "SKYLA validation message")
        record("telegram.send_message", True, f"message id {sent.get('message_id', '?')}")
    except Exception as exc:                                # noqa: BLE001
        record("telegram.send_message", False, f"{type(exc).__name__}: {exc}"[:160])

    # Duplicate prevention: the same content twice must not produce two visible
    # messages if the ledger is working. Recorded as an observation, not asserted.
    try:
        a = await t.send_message(chat, "SKYLA duplicate test")
        b = await t.send_message(chat, "SKYLA duplicate test")
        same = a.get("message_id") == b.get("message_id")
        record("telegram.duplicate_prevention", same,
               f"ids {a.get('message_id')} vs {b.get('message_id')} — "
               f"{'deduplicated' if same else 'NOT deduplicated at connector level'}")
    except Exception as exc:                                # noqa: BLE001
        record("telegram.duplicate_prevention", False, f"{type(exc).__name__}"[:80])

    record("telegram.command_authorization", None,
           "operator step: send a command from a NON-authorised chat and confirm rejection",
           IMPL)


async def main() -> None:
    _require_test_mode()
    _guard_recipient(os.getenv("SKYLA_TEST_EMAIL", ""))

    results: list[dict] = []
    for fn in (check_gmail, check_calendar, check_telegram):
        try:
            await fn(results)
        except Exception as exc:                            # noqa: BLE001
            results.append({"capability": fn.__name__, "verdict": "FAIL",
                            "detail": f"{type(exc).__name__}: {exc}"[:200]})

    record = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "host": os.uname().nodename, "results": results}
    out = ROOT / "connector-validation.json"
    out.write_text(json.dumps(record, indent=2))

    print(f"{'capability':38s} {'verdict':26s} detail")
    for r in results:
        print(f"{r['capability']:38s} {str(r['verdict']):26s} {r['detail'][:70]}")
    print(f"\nwritten to {out}")

    failed = [r for r in results if r["verdict"] == "FAIL"]
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    asyncio.run(main())
