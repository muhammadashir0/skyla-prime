"""WS5 database tests: migrations, concurrency, backup/recovery, integrity."""
import sqlite3
import threading

from fastapi.testclient import TestClient

from skyla.api.app import app
from skyla.db import MIGRATIONS, Database
from tests.conftest import AUTH

client = TestClient(app)


def test_schema_version_tracked(db):
    assert db.schema_version() == max(v for v, _ in MIGRATIONS)


def test_migrations_idempotent(tmp_path):
    path = str(tmp_path / "m.db")
    v1 = Database(path).schema_version()
    d2 = Database(path)  # re-open must not re-apply or corrupt
    assert d2.schema_version() == v1
    assert d2.query_one("SELECT COUNT(*) AS n FROM schema_version")["n"] == v1


def test_expected_tables_exist(db):
    names = {r[0] for r in db.query(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"users", "sessions", "api_tokens", "action_ledger",
            "provider_usage", "schema_version", "tasks"} <= names


def test_concurrent_writes(tmp_path):
    """8 threads x 30 writes (WAL + lock) must all land with no errors."""
    d = Database(str(tmp_path / "c.db"))
    errors = []

    def worker(n):
        try:
            for i in range(30):
                d.audit(f"w{n}", "concurrency.test", f"{n}-{i}")
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert d.query_one("SELECT COUNT(*) AS n FROM audit_log")["n"] == 240


def test_backup_and_recovery(tmp_path):
    """Online backup -> simulate total DB loss -> restore -> verify."""
    path = str(tmp_path / "prod.db")
    d = Database(path)
    d.audit("operator", "critical.record", "must-survive")
    expected_version = d.schema_version()

    backup_path = str(tmp_path / "backup.db")
    dst = sqlite3.connect(backup_path)
    d._conn.backup(dst)          # SQLite online backup API
    dst.close()

    d._conn.close()              # simulate disaster
    with open(path, "wb") as fh:
        fh.write(b"corrupted")

    restored = Database(backup_path)
    rows = restored.audit_recent(10)
    assert any(r["detail"] == "must-survive" for r in rows)
    assert restored.schema_version() == expected_version


def test_integrity_check_after_concurrency(tmp_path):
    d = Database(str(tmp_path / "i.db"))
    d.audit("a", "x", "y")
    assert d.query_one("PRAGMA integrity_check")[0] == "ok"


def test_recover_interrupted_tasks(db):
    tid = db.create_task("stale", "instruction", "research", 0)
    db.update_task(tid, status="running")
    assert db.recover_interrupted() >= 1
    assert db.get_task(tid)["status"] == "interrupted"


def test_recover_interrupted_ledger(db):
    db.ledger_begin("interrupted-1", "fp", "telegram", "message.send")
    assert db.recover_interrupted_ledger() >= 1
    assert db.ledger_get("interrupted-1")["state"] == "unknown"


def test_usage_logging(db):
    db.log_usage("local", "skyla-mock-0.1", 100, 50, 0.0001, 12)
    db.log_usage("local", "skyla-mock-0.1", 100, 50, 0.0002, 20)
    s = db.usage_summary()
    assert s["calls"] == 2 and s["in_tok"] == 200 and s["out_tok"] == 100


def test_end_to_end_task_lifecycle():
    r = client.post("/api/tasks", json={"instruction": "Research quantum sensors"}, headers=AUTH)
    tid = r.json()["id"]
    t = None
    for _ in range(40):
        t = client.get(f"/api/tasks/{tid}", headers=AUTH).json()
        if t["status"] in ("completed", "failed"):
            break
    assert t["status"] == "completed"
    assert len(t["steps"]) >= 2
    assert t["verification"] is not None
