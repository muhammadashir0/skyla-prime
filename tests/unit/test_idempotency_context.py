"""WS3 idempotency ledger + WS4 context manager tests."""
from skyla.core.context import ContextManager, estimate_tokens, truncate


def test_ledger_new_duplicate_conflict(db):
    """v0.2.2 tightened this contract for multi-worker correctness.

    Before completion the key IS in flight: a second worker must be told that, not
    told "duplicate", because replaying a result that does not exist yet would
    return an empty body and the caller might proceed to act.
    """
    r1 = db.ledger_begin("k1", "fp-a", "telegram", "message.send")
    assert r1["status"] == "new"
    r2 = db.ledger_begin("k1", "fp-a", "telegram", "message.send")
    assert r2["status"] == "in_flight", "a pending claim must report in_flight"
    r3 = db.ledger_begin("k1", "fp-b", "telegram", "message.send")
    assert r3["status"] == "conflict"
    db.ledger_complete("k1", "completed", "provider-msg-123")
    # Once settled, the same request is a genuine duplicate with a replayable body.
    r4 = db.ledger_begin("k1", "fp-a", "telegram", "message.send")
    assert r4["status"] == "duplicate"
    assert r4["record"]["provider_response"] == "provider-msg-123"
    rec = db.ledger_get("k1")
    assert rec["state"] == "completed" and rec["attempts"] == 1


def test_ledger_distinct_keys(db):
    assert db.ledger_begin("k-a", "fp", "gmail", "draft")["status"] == "new"
    assert db.ledger_begin("k-b", "fp", "gmail", "draft")["status"] == "new"


def test_estimate_tokens():
    assert estimate_tokens("a" * 400) == 100
    assert estimate_tokens("") == 1


def test_truncate_flags():
    text, flag = truncate("x" * 4000, 100)
    assert flag and estimate_tokens(text) <= 110
    text2, flag2 = truncate("short", 100)
    assert not flag2 and text2 == "short"


def test_context_fit_prioritizes_instructions():
    cm = ContextManager(model_id="skyla-mock-0.1")  # 8192 limit
    system = "sys" * 100
    user = "important instruction " * 50
    context = "y" * 100000
    fitted = cm.fit(system, user, context)
    assert fitted["tokens"] <= fitted["budget"]
    assert "important instruction" in fitted["user"]  # instructions preserved
    assert fitted["truncated"] is True  # context truncated, flagged


def test_context_fit_small():
    cm = ContextManager(model_id="skyla-mock-0.1")
    fitted = cm.fit("sys", "hello", "ctx")
    assert fitted["truncated"] is False
    assert fitted["context"] == "ctx"


def test_compaction_keeps_recent():
    outputs = [f"output-{i} " + "z" * 300 for i in range(5)]
    compacted = ContextManager.compact_step_outputs(outputs, keep_last=2)
    assert "output-4" in compacted and "output-3" in compacted  # recent kept
    assert "Compacted earlier step outputs" in compacted
    assert len(compacted) < sum(len(o) for o in outputs)


def test_context_limits_per_model():
    from skyla.core.context import context_limit_for
    assert context_limit_for("skyla-mock-0.1") == 8192
    assert context_limit_for("unknown-model") == 8192
