"""WS3 end-to-end idempotency through the API (no real external sends)."""
from fastapi.testclient import TestClient

from skyla.api.app import app
from tests.conftest import AUTH

client = TestClient(app)


def test_meeting_workflow_duplicate_replays_same_result():
    body = {"attendee": "professor@example.edu", "idempotency_key": "mtg-e2e-1"}
    r1 = client.post("/api/workflows/meeting", json=body, headers=AUTH)
    r2 = client.post("/api/workflows/meeting", json=body, headers=AUTH)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r2.json()["duplicate"] is True
    # Replay returns the recorded provider result, not a fresh execution.
    assert r1.json()["proposed_slots"] == r2.json()["proposed_slots"]
    assert r1.json()["mode"] == r2.json()["mode"]


def test_telegram_workflow_duplicate_replays():
    body = {"text": "status", "idempotency_key": "tg-e2e-1"}
    r1 = client.post("/api/workflows/telegram", json=body, headers=AUTH)
    r2 = client.post("/api/workflows/telegram", json=body, headers=AUTH)
    assert r1.json()["mode"] == "mock"
    assert r2.json()["duplicate"] is True
    assert r2.json()["original_state"] == "completed"


def test_idempotency_fingerprint_conflict():
    body = {"text": "first", "idempotency_key": "tg-conflict"}
    assert client.post("/api/workflows/telegram", json=body, headers=AUTH).status_code == 200
    body2 = {"text": "different payload", "idempotency_key": "tg-conflict"}
    assert client.post("/api/workflows/telegram", json=body2, headers=AUTH).status_code == 409


def test_no_real_sends_in_mock_mode():
    r = client.post("/api/workflows/telegram",
                    json={"text": "audit check", "idempotency_key": "tg-mock-only"},
                    headers=AUTH)
    assert r.json()["mode"] == "mock"  # no live credential => mock, never a real send


def test_interrupted_operation_is_not_silently_reexecuted():
    """A key claimed but never completed blocks immediate re-execution."""
    import hashlib

    from skyla.api.app import db
    fp = hashlib.sha256("mock-chat|status".encode()).hexdigest()
    db.ledger_begin("tg-interrupted", fp, "telegram", "message.send")
    r = client.post("/api/workflows/telegram",
                    json={"text": "status", "idempotency_key": "tg-interrupted"},
                    headers=AUTH)
    assert r.status_code == 409
    assert "in flight" in r.json()["detail"].lower()


def test_gmail_draft_is_ledger_guarded():
    body = {"message_id": "msg-1", "body": "Draft reply text",
            "idempotency_key": "gmail-e2e-1"}
    r1 = client.post("/api/workflows/gmail/draft", json=body, headers=AUTH)
    r2 = client.post("/api/workflows/gmail/draft", json=body, headers=AUTH)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["mode"] == "mock"          # mock mode: nothing is sent
    assert r2.json()["duplicate"] is True       # second write never executed
    assert r2.json()["draft_body"] == r1.json()["draft_body"]


def test_gmail_draft_conflict():
    a = {"message_id": "m2", "body": "one", "idempotency_key": "gmail-conflict"}
    b = {"message_id": "m2", "body": "two", "idempotency_key": "gmail-conflict"}
    assert client.post("/api/workflows/gmail/draft", json=a, headers=AUTH).status_code == 200
    assert client.post("/api/workflows/gmail/draft", json=b, headers=AUTH).status_code == 409


def test_all_external_writes_are_ledger_guarded():
    """WS3 invariant: every external-write endpoint accepts an idempotency_key."""
    import inspect
    import typing

    from skyla.api import app as api

    write_paths = ["/api/tasks", "/api/workflows/meeting",
                   "/api/workflows/telegram", "/api/workflows/gmail/draft"]
    routes = {(r.path, m): r.endpoint for r in api.app.routes
              if hasattr(r, "endpoint") for m in getattr(r, "methods", set())}
    for path in write_paths:
        assert (path, "POST") in routes, f"missing POST endpoint {path}"
        hints = typing.get_type_hints(routes[(path, "POST")])
        body_models = [h for h in hints.values() if hasattr(h, "model_fields")]
        assert any("idempotency_key" in m.model_fields for m in body_models), path
