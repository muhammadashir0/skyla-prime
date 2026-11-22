"""Multi-worker idempotency and shared-state correctness (v0.2.2 Mission 5).

These tests use REAL SEPARATE PROCESSES, not threads: a thread-local lock would
pass every test here while the deployed system (multiple uvicorn workers) failed.
Each worker opens its own SQLite connection to the same file.

The question each test answers: can two workers independently execute the same
external action? If yes, that is a duplicate side effect in production.
"""
import json
import multiprocessing as mp
import os
import sqlite3
import tempfile
import time

import pytest

from skyla.db import Database


def _worker_claim(args):
    """Runs in a separate OS process."""
    db_path, key, fingerprint, barrier, results_path = args
    db = Database(db_path)
    try:
        barrier.wait(timeout=30)          # line all workers up at the same instant
        r = db.ledger_begin(key, fingerprint, "telegram", "message.send")
        outcome = {"status": r["status"], "pid": os.getpid(),
                   "id": r["record"].get("id", "")}
    except Exception as exc:                                    # noqa: BLE001
        outcome = {"status": f"EXC:{type(exc).__name__}", "pid": os.getpid(),
                   "detail": str(exc)[:120]}
    finally:
        db._conn.close()
    with open(results_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(outcome) + "\n")
    return outcome


def _read_as_other_tenant(args):
    """Module-level so the 'spawn' start method can pickle it."""
    db_path, results = args
    d = Database(db_path)
    try:
        from skyla.knowledge.store import KnowledgeStore as KS
        hits = KS(d).recall("WORKER-SECRET", owner_id="some-other-tenant")
        with open(results, "w") as fh:
            json.dump({"hits": len(hits)}, fh)
    finally:
        d._conn.close()


def run_race(db_path: str, n: int = 8, key: str = "k1", fingerprint: str = "fp"):
    results_path = os.path.join(tempfile.mkdtemp(), "results.jsonl")
    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(n)
    procs = [ctx.Process(target=_worker_claim,
                         args=((db_path, key, fingerprint, barrier, results_path),))
             for _ in range(n)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
    out = []
    if os.path.exists(results_path):
        for line in open(results_path, encoding="utf-8"):
            if line.strip():
                out.append(json.loads(line))
    return out


@pytest.fixture()
def shared_db():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "shared.db")
    db = Database(path)
    db.audit("init", "boot", "x")
    yield path
    db._conn.close()


# ------------------------------------------------------------- the core claim
def test_only_one_process_owns_an_idempotency_key(shared_db):
    """THE requirement: 'two workers cannot independently execute the same
    external action'.

    Mutation: revert ledger_begin to check-then-insert -> several workers report
    'new' -> FAIL.
    """
    out = run_race(shared_db, n=8, key="dup-action-1")
    owners = [r for r in out if r["status"] == "new"]
    assert len(out) == 8, f"only {len(out)} workers reported"
    assert len(owners) == 1, (
        f"{len(owners)} workers claimed the same action: "
        f"{[(r['pid'], r['status']) for r in out]}")


def test_losers_get_a_clean_status_not_an_exception(shared_db):
    """A losing worker must be told it lost. An uncaught IntegrityError is a 500
    in production, and 500s get retried."""
    out = run_race(shared_db, n=8, key="dup-action-2")
    exceptions = [r for r in out if r["status"].startswith("EXC:")]
    assert not exceptions, f"workers crashed instead of reporting: {exceptions}"
    statuses = {r["status"] for r in out}
    assert statuses <= {"new", "in_flight", "duplicate"}, statuses


def test_conflicting_fingerprint_is_detected_across_processes(shared_db):
    """Same key + different payload must be a conflict, in every worker."""
    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(2)
    results_path = os.path.join(tempfile.mkdtemp(), "r.jsonl")
    procs = [
        ctx.Process(target=_worker_claim,
                    args=((shared_db, "conflict-key", "fp-A", barrier, results_path),)),
        ctx.Process(target=_worker_claim,
                    args=((shared_db, "conflict-key", "fp-B", barrier, results_path),)),
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
    rows = [json.loads(l) for l in open(results_path, encoding="utf-8") if l.strip()]
    statuses = sorted(r["status"] for r in rows)
    assert "new" in statuses
    assert "conflict" in statuses, f"different payloads not detected: {statuses}"


# ------------------------------------------------------------ committed state
def test_committed_action_is_visible_to_every_worker(shared_db):
    """Global, not per-process: a completed action must replay for a worker that
    never saw the original request."""
    db = Database(shared_db)
    assert db.ledger_begin("global-1", "fp", "telegram", "message.send")["status"] == "new"
    db.ledger_complete("global-1", "completed", json.dumps({"message_id": 42}))
    db._conn.close()

    out = run_race(shared_db, n=4, key="global-1", fingerprint="fp")
    for r in out:
        assert r["status"] == "duplicate", (
            f"worker {r['pid']} saw {r['status']} for an already-completed action")


def test_wal_allows_concurrent_readers_during_a_write(shared_db):
    """Multi-worker SQLite requires WAL; a rollback journal serialises everything."""
    con = sqlite3.connect(shared_db)
    mode = con.execute("PRAGMA journal_mode").fetchone()[0]
    con.close()
    assert mode.lower() == "wal", f"journal_mode is {mode}, multi-worker unsafe"


# --------------------------------------------------------- worker recovery
def test_stale_claim_is_reaped_so_a_key_is_not_blocked_forever(shared_db):
    """A worker that dies mid-action leaves a 'pending' row. Without reaping, that
    idempotency key is poisoned permanently."""
    db = Database(shared_db)
    assert db.ledger_begin("crashed-key", "fp", "telegram", "send")["status"] == "new"
    # Simulate the owning worker dying: never calls ledger_complete, and the claim
    # is aged past the reaping threshold.
    db.execute("UPDATE action_ledger SET updated_at=? WHERE idempotency_key=?",
               (time.time() - 3600, "crashed-key"))
    reaped = db.ledger_reap_stale(older_than_s=300)
    assert "crashed-key" in reaped
    state = db.query_one("SELECT state FROM action_ledger WHERE idempotency_key=?",
                         ("crashed-key",))["state"]
    assert state == "unknown", f"reaped claim left in state {state}"
    db._conn.close()


def test_fresh_claim_is_not_reaped(shared_db):
    """Reaping must not steal a live claim."""
    db = Database(shared_db)
    assert db.ledger_begin("live-key", "fp", "telegram", "send")["status"] == "new"
    assert db.ledger_reap_stale(older_than_s=300) == []
    state = db.query_one("SELECT state FROM action_ledger WHERE idempotency_key=?",
                         ("live-key",))["state"]
    assert state == "pending"
    db._conn.close()


# ------------------------------------------------------- cross-worker auth
def test_tenant_scoping_holds_across_processes(shared_db):
    """Mission 5 'cross-worker authorization': user state written by one worker
    must be enforced by another."""
    from skyla.auth import AuthService
    db = Database(shared_db)
    auth = AuthService(db)
    u = auth.create_user("worker_user", "Worker-Pass-2026", "operator")
    from skyla.knowledge.store import KnowledgeStore
    KnowledgeStore(db).remember("k", "WORKER-SECRET", owner_id=u["id"])
    db._conn.close()

    results = os.path.join(tempfile.mkdtemp(), "r.json")
    ctx = mp.get_context("spawn")
    p = ctx.Process(target=_read_as_other_tenant, args=((shared_db, results),))
    p.start()
    p.join(timeout=60)
    assert json.loads(open(results).read())["hits"] == 0, (
        "another worker's process could read a foreign tenant's memory")


# ------------------------------------------------------------ throughput
def test_sequential_claim_throughput_is_recorded(shared_db):
    """Baseline numbers for MULTI_WORKER_CAPACITY_REPORT.md."""
    db = Database(shared_db)
    start = time.perf_counter()
    n = 200
    for i in range(n):
        assert db.ledger_begin(f"perf-{i}", "fp", "telegram", "send")["status"] == "new"
        db.ledger_complete(f"perf-{i}", "completed", "{}")
    elapsed = time.perf_counter() - start
    db._conn.close()
    rate = n / elapsed
    print(f"\nclaim+complete throughput: {rate:.0f} ops/s ({n} in {elapsed:.2f}s)")
    assert rate > 20, f"throughput implausibly low: {rate:.1f} ops/s"
