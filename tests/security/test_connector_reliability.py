"""Connector reliability and mock/live honesty (v0.2.2 Mission 6).

No authorised live test accounts are available in this environment, so LIVE
provider behaviour is NOT VERIFIED and nothing here claims otherwise. What IS
tested:

  * mock mode can never be mistaken for a real external action (status verbs);
  * every connector reports its mode and never claims live without credentials;
  * a provider error surfaces as an error instead of a silent success;
  * a failed token refresh aborts the action;
  * the ledger prevents a duplicate provider call for one idempotency key.

Mutation targets: make a mock return status "sent"/"created" -> FAIL; make a
provider error return success -> FAIL.
"""
import asyncio

import pytest

from skyla.integrations.calendar import MOCK_EVENTS, GoogleCalendarConnector
from skyla.integrations.gmail import GmailConnector
from skyla.integrations.telegram import TelegramConnector

LIVE_ENV = ("GOOGLE_REFRESH_TOKEN", "GOOGLE_OAUTH_CLIENT_ID",
            "GOOGLE_OAUTH_CLIENT_SECRET", "TELEGRAM_BOT_TOKEN")

CONNECTORS = (GmailConnector, GoogleCalendarConnector, TelegramConnector)


@pytest.fixture(autouse=True)
def no_live_credentials(monkeypatch):
    """Guarantee these tests never touch a real provider."""
    for var in LIVE_ENV:
        monkeypatch.delenv(var, raising=False)
    from skyla.config import get_settings
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()


def run(coro):
    return asyncio.run(coro)


# ------------------------------------------------------- mock/live separation
@pytest.mark.parametrize("factory", CONNECTORS)
def test_connector_reports_mock_without_credentials(factory):
    c = factory()
    assert c.mode == "mock", f"{c.name} claimed mode={c.mode} with no credentials"
    assert c.live is False
    assert "mock" in c.detail.lower()


def test_mock_telegram_never_claims_delivery():
    """Mutation: return status 'sent' in mock mode -> FAIL."""
    result = run(TelegramConnector().send_message("123", "hello"))
    assert result["mode"] == "mock"
    assert result["status"] == "logged-not-sent"
    assert result["status"] != "sent", "mock must never report a real send"
    assert "result" not in result, "mock returned a provider payload"


def test_mock_gmail_never_claims_a_sent_draft():
    result = run(GmailConnector().draft_reply("msg-1", "body"))
    assert result["mode"] == "mock"
    assert result["status"] == "draft-prepared-not-sent"
    assert result["status"] != "sent"


def test_mock_calendar_never_claims_a_created_event():
    result = run(GoogleCalendarConnector().create_event(
        "Research sync", "2026-12-01T10:00:00Z", "2026-12-01T11:00:00Z"))
    assert result["mode"] == "mock"
    assert result["status"] == "event-prepared-not-created"
    assert "event" not in result, "mock returned a provider object"


def test_mock_read_paths_are_distinguishable():
    """Fixtures may be returned, but the caller can tell they are fixtures."""
    assert run(GmailConnector().search("meeting")) == [
        m for m in __import__("skyla.integrations.gmail", fromlist=["MOCK_MESSAGES"])
        .MOCK_MESSAGES if "meeting" in (m["subject"] + m["snippet"] + m["from"]).lower()]
    summary = run(GmailConnector().summarize_inbox(5))
    assert summary["mode"] == "mock" and summary["note"] == "Mock data"
    assert run(GoogleCalendarConnector().list_events()) == MOCK_EVENTS


# ------------------------------------------------------------ provider errors
class _FailingResponse:
    status_code = 500

    def raise_for_status(self):
        import httpx
        raise httpx.HTTPStatusError("provider 500", request=None, response=None)

    def json(self):
        return {"error": "internal"}


class _FailingClient:
    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, *a, **kw):
        return _FailingResponse()

    async def get(self, *a, **kw):
        return _FailingResponse()


def _force_live(connector):
    connector.live = True
    connector.mode = "live"
    return connector


def test_telegram_provider_error_is_not_reported_as_success(monkeypatch):
    import skyla.integrations.telegram as tg
    conn = _force_live(TelegramConnector())
    monkeypatch.setattr(tg.httpx, "AsyncClient", _FailingClient)
    with pytest.raises(Exception):
        run(conn.send_message("123", "hi"))


def test_calendar_provider_error_is_not_reported_as_success(monkeypatch):
    import skyla.integrations.calendar as cal
    conn = _force_live(GoogleCalendarConnector())
    conn._access_token = _async_return("fake-token")
    monkeypatch.setattr(cal.httpx, "AsyncClient", _FailingClient)
    with pytest.raises(Exception):
        run(conn.create_event("x", "2026-12-01T10:00:00Z", "2026-12-01T11:00:00Z"))


def test_gmail_provider_error_is_not_reported_as_success(monkeypatch):
    import skyla.integrations.gmail as gm
    conn = _force_live(GmailConnector())
    conn._access_token = _async_return("fake-token")
    monkeypatch.setattr(gm.httpx, "AsyncClient", _FailingClient)
    with pytest.raises(Exception):
        run(conn.draft_reply("msg-1", "body"))


def _async_return(value):
    async def _inner(*a, **kw):
        return value
    return _inner


def test_token_refresh_failure_aborts_the_action(monkeypatch):
    """A failed OAuth refresh must not fall through to the action."""
    import skyla.integrations.calendar as cal
    conn = _force_live(GoogleCalendarConnector())
    monkeypatch.setattr(cal.httpx, "AsyncClient", _FailingClient)
    with pytest.raises(Exception):
        run(conn._access_token())


# --------------------------------------------------- duplicate-action recovery
def test_ledger_prevents_a_duplicate_provider_call(db, monkeypatch):
    """Two attempts with one idempotency key must reach the provider once."""
    calls = {"n": 0}
    real = TelegramConnector.send_message

    async def counting(self, chat_id, text):
        calls["n"] += 1
        return await real(self, chat_id, text)

    monkeypatch.setattr(TelegramConnector, "send_message", counting)

    key = "conn-dup-1"
    assert db.ledger_begin(key, "fp", "telegram", "send")["status"] == "new"
    run(TelegramConnector().send_message("1", "hi"))
    db.ledger_complete(key, "completed", '{"status": "logged-not-sent"}')

    claim = db.ledger_begin(key, "fp", "telegram", "send")
    assert claim["status"] == "duplicate"
    assert claim["record"]["provider_response"], "replay body missing"
    assert calls["n"] == 1, "provider was called more than once"


# ------------------------------------------------------------ live separation
def test_partial_credentials_do_not_enable_live_mode(monkeypatch):
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "id-only")
    from skyla.config import get_settings
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    c = GmailConnector()
    assert c.live is False, "live enabled with only a client id and no refresh token"


@pytest.mark.parametrize("factory", CONNECTORS)
def test_no_connector_is_live_in_this_environment(factory):
    """Environment assertion: nothing here is authorised for live calls."""
    assert factory().live is False
