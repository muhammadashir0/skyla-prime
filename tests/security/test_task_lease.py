"""B-02: cross-process task execution must not duplicate (v0.2.3).

The finding
-----------
v0.2.2 `Orchestrator.run_task()` decided ownership with check-then-act:

    if task["status"] in ("completed", "failed"): return task
    self.db.update_task(task_id, status="planning")

Two API workers — or two scheduler ticks, or one retried request — could both read
`queued` and both execute the whole plan. Every step calls an agent, so a duplicate
run doubles model spend and repeats every external action the plan performs.
Measured on the unfixed code: 2 processes produced 4 `task_steps` rows where 2 are
correct, and the duplication scaled linearly (n processes -> n x steps).

These tests use REAL SEPARATE PROCESSES, because an in-process check would not
distinguish a threading lock from a database-level guarantee. Every test compares a
database fact written by the children against the count that a single execution
would produce.

B-02 is closed only when these pass against the fixed code AND fail against the
original, which was verified by restoring `HEAD:skyla/core/orchestrator.py` and
re-running (3/3 reproductions, 4 rows each).
"""
import asyncio
import multiprocessing as mp
import os
import sqlite3
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# --------------------------------------------------------------------------- child
def _child_run(barrier, task_q, db_path):
    """One 'API worker': claim and execute a task, record what happened."""
    sys.path.insert(0, ROOT)
    os.environ["SKYLA_DB_PATH"] = db_path
    from skyla.core.orchestrator import Orchestrator
    from skyla.db import Database

    db = Database(db_path)
    try:
        tid = task_q.get()
        orch = Orchestrator(db)
        barrier.wait()                      # all workers start together
        try:
            asyncio.run(orch.run_task(tid))
            outcome = "ran"
        except Exception as exc:            # noqa: BLE001
            outcome = f"error:{type(exc).__name__}"
        db._conn.close()
        return outcome
    finally:
        try:
            db._conn.close()
        except Exception:                   # noqa: BLE001
            pass


def _spawn(n, db_path):
    """Run n children against one queued task. Returns the task id."""
    from skyla.db import Database

    db = Database(db_path)
    tid = db.create_task("B-02 probe", "count to three", "general", 0)
    db._conn.close()

    barrier = mp.Barrier(n)
    q = mp.Queue()
    for _ in range(n):
        q.put(tid)
    procs = [mp.Process(target=_child_run, args=(barrier, q, db_path)) for _ in range(n)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=180)
    return tid


def _steps(db_path, tid):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT idx FROM task_steps WHERE task_id=? ORDER BY idx", (tid,)).fetchall()
        return [r["idx"] for r in rows]
    finally:
        con.close()


@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "b02.db")


# ---------------------------------------------------------------- the B-02 defect
@pytest.mark.parametrize("n", [2, 3, 4])
def test_two_or_more_processes_never_execute_a_task_twice(db_path, n):
    """THE regression test. n concurrent processes, one queued task, exactly one run.

    A duplicate shows up as more than one row per step index. Asserting on the
    index multiset (not on a row count) is what makes this independent of how many
    steps the planner chooses.
    """
    tid = _spawn(n, db_path)
    idxs = _steps(db_path, tid)
    assert idxs, f"task {tid} produced no steps at all — the probe did not run"
    duplicates = len(idxs) - len(set(idxs))
    assert duplicates == 0, (
        f"{n} processes produced duplicate steps {idxs}; "
        f"{duplicates} step indexes ran more than once (B-02)")
    assert len(idxs) == len(set(idxs)) == 2, (
        f"expected the 2-step plan once, got {idxs}")


def test_losing_workers_do_not_kill_or_fail_the_task(db_path):
    """A worker that loses the claim must return cleanly, not crash or mark failed.

    The failure mode in the old ledger code was an uncaught IntegrityError; the
    same mistake here would turn a duplicate request into an HTTP 500 and invite
    the client to retry, which is how duplicates become external actions.
    """
    tid = _spawn(4, db_path)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        status = con.execute("SELECT status FROM tasks WHERE id=?", (tid,)).fetchone()["status"]
        errors = con.execute(
            "SELECT COUNT(*) AS c FROM audit_log WHERE action LIKE 'task.lease.%'"
        ).fetchone()["c"]
    finally:
        con.close()
    assert status == "completed", f"task ended as {status!r} with 4 contenders"
    assert errors >= 1, "no lease decision was recorded — losers were not audited"


# --------------------------------------------------- the claim is what stops it
def test_lease_claim_is_atomic_across_processes(db_path):
    """Directly: N processes claim one task; exactly one is told 'acquired'."""
    from skyla.db import Database

    db = Database(db_path)
    tid = db.create_task("lease", "x", "general", 0)
    db._conn.close()

    barrier = mp.Barrier(5)
    q = mp.Queue()
    for _ in range(5):
        q.put(tid)
    out = mp.Queue()

    def claimer(bar, tq, results, path):
        sys.path.insert(0, ROOT)
        from skyla.db import Database as D
        d = D(path)
        t = tq.get()
        bar.wait()
        results.put(d.lease_task(t, f"pid{os.getpid()}")["status"])
        d._conn.close()

    procs = [mp.Process(target=claimer, args=(barrier, q, out, db_path)) for _ in range(5)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=120)

    statuses = []
    while not out.empty():
        statuses.append(out.get())
    assert len(statuses) == 5, f"only {len(statuses)} claims reported: {statuses}"
    assert statuses.count("acquired") == 1, (
        f"exactly one process may own a task; got {statuses.count('acquired')} — {statuses}")


def test_a_completed_task_cannot_be_reacquired(db_path):
    """Sequential re-acquisition is also a duplicate.

    An earlier version of this fix released its lease row on completion, so a
    worker that had already read `queued` could acquire afterwards and re-run.
    The CAS on `tasks.status` must make a finished task unclaimable.
    """
    from skyla.db import Database

    db = Database(db_path)
    tid = db.create_task("done", "x", "general", 0)
    assert db.lease_task(tid, "first")["status"] == "acquired"
    db.update_task(tid, status="completed")
    db.release_task(tid, "first")

    again = db.lease_task(tid, "second")
    assert again["status"] == "terminal", (
        f"a completed task was claimable again: {again}")

    db.update_task(tid, status="failed")
    assert db.lease_task(tid, "third")["status"] == "terminal"


def test_an_executing_task_cannot_be_reacquired(db_path):
    """While a holder is mid-run the task is unclaimable.

    The first CAS implementation accepted 'planning' as claimable, which let a late
    worker take a task whose holder had already started it (4 step rows at n=4).
    """
    from skyla.db import Database

    db = Database(db_path)
    tid = db.create_task("busy", "x", "general", 0)
    assert db.lease_task(tid, "holder-a")["status"] == "acquired"
    # The orchestrator moves the task through planning/running while it owns it.
    for live_status in ("planning", "running", "verifying"):
        db.update_task(tid, status=live_status)
        assert db.lease_task(tid, "holder-b")["status"] == "held", (
            f"task was re-claimed while its holder had it in {live_status!r}")


def test_interrupted_task_is_not_silently_rerun(db_path):
    """A crashed holder's task must be parked for a decision, not re-executed.

    Re-running would duplicate every agent call and external action. A-17 (no
    resume path) is still open, so the honest behaviour is `interrupted`.
    """
    from skyla.db import Database

    db = Database(db_path)
    tid = db.create_task("crash", "x", "general", 0)
    assert db.lease_task(tid, "dead-holder", ttl_s=0.05)["status"] == "acquired"
    db.update_task(tid, status="running")
    time.sleep(0.1)

    recovered = db.reap_expired_tasks()
    assert any(r["task_id"] == tid for r in recovered), "stale lease was not reaped"
    row = db.get_task(tid)
    assert row["status"] == "interrupted", f"expected 'interrupted', got {row['status']!r}"

    # And running it now must be refused rather than executed again.
    assert db.lease_task(tid, "eager")["status"] == "terminal"


def test_recovery_is_recorded_with_the_previous_holder(db_path):
    """Evidence, not just a status change: who held it and what it was doing."""
    from skyla.db import Database

    db = Database(db_path)
    tid = db.create_task("crash2", "x", "general", 0)
    db.lease_task(tid, "ghost-worker", ttl_s=0.05)
    db.update_task(tid, status="running")
    time.sleep(0.1)
    db.reap_expired_tasks()

    rec = db.query_one("SELECT * FROM task_recovery WHERE task_id=?", (tid,))
    assert rec is not None, "no recovery record was written"
    assert rec["previous_holder"] == "ghost-worker"
    assert rec["previous_status"] == "running"
    assert rec["reason"] == "lease expired"


def test_a_live_lease_is_not_reaped(db_path):
    """Control: reaping must not steal work from a live holder."""
    from skyla.db import Database

    db = Database(db_path)
    tid = db.create_task("alive", "x", "general", 0)
    db.lease_task(tid, "live-worker", ttl_s=600)
    db.update_task(tid, status="running")

    assert db.reap_expired_tasks() == [], "a live lease was reaped"
    assert db.get_task(tid)["status"] == "running"
