"""WAL-consistent backup and verified restore (v0.2.2 Mission 4, closes A-14).

Every test asserts on recovered DATA, not on the backup function's return value.
The A-14 defect is reproduced first, so the tests are demonstrably sensitive to it.
"""
import os
import shutil
import sqlite3
import tempfile
import threading
import time

import pytest

from skyla.auth import AuthService
from skyla.backup import (BackupError, BackupManager, RestoreError, file_sha256,
                          table_counts)
from skyla.db import Database


@pytest.fixture()
def live():
    """A disposable database with committed data. The original is never deleted."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, "app.db")
    db = Database(path)
    auth = AuthService(db)
    auth.create_user("critical_user", "Super-Secret-2026", "admin")
    db.audit("critical_user", "login", "ok")
    yield db, path
    db._conn.close()


# ------------------------------------------------------- the A-14 defect itself
def test_naive_file_copy_loses_committed_rows(live):
    """Regression proof: a plain copy of the .db file (the v0.2.1 method) loses
    data held in the WAL. If this test ever passes trivially, the defect has been
    reintroduced somewhere."""
    db, path = live
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    for i in range(300):
        con.execute("INSERT INTO audit_log (ts, actor, action, detail) VALUES (?,?,?,?)",
                    (time.time(), f"u{i}", "bulk", "x"))
    con.commit()
    con.close()

    assert os.path.getsize(path + "-wal") > 0, "WAL should hold the new rows"

    naive = os.path.join(tempfile.mkdtemp(), "naive.db")
    with open(path, "rb") as src, open(naive, "wb") as dst:
        dst.write(src.read())

    con = sqlite3.connect(naive)
    try:
        naive_rows = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    except sqlite3.DatabaseError:
        naive_rows = 0
    finally:
        con.close()

    source_rows = db.query("SELECT COUNT(*) AS c FROM audit_log")[0]["c"]
    assert naive_rows < source_rows, (
        "naive copy did not lose rows; WAL behaviour may have changed, so the "
        "online-backup requirement needs re-evaluation")


# ------------------------------------------------------------ correct method
def test_online_backup_captures_wal_rows(live):
    db, path = live
    con = sqlite3.connect(path)
    con.execute("PRAGMA wal_autocheckpoint=0")
    for i in range(300):
        con.execute("INSERT INTO audit_log (ts, actor, action, detail) VALUES (?,?,?,?)",
                    (time.time(), f"u{i}", "bulk", "x"))
    con.commit()
    con.close()

    mgr = BackupManager(path)
    rec = mgr.backup(label="wal")
    source = db.query("SELECT COUNT(*) AS c FROM audit_log")[0]["c"]

    assert rec.tables["audit_log"] == source, (
        f"backup holds {rec.tables['audit_log']} of {source} committed rows")

    # Prove it by OPENING the backup, not by trusting the record.
    con = sqlite3.connect(f"file:{rec.path}?mode=ro", uri=True)
    try:
        assert con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == source
        assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        con.close()


def test_backup_during_concurrent_writes_is_consistent(live):
    """A snapshot taken while writers are active must be internally consistent:
    it may reflect any committed point, but never a torn state."""
    db, path = live
    stop = threading.Event()

    def writer(tag):
        for i in range(300):
            if stop.is_set():
                return
            db.audit(tag, "concurrent", str(i))

    threads = [threading.Thread(target=writer, args=(f"w{i}",)) for i in range(3)]
    for t in threads:
        t.start()
    time.sleep(0.05)
    mgr = BackupManager(path)
    rec = mgr.backup(label="concurrent")
    stop.set()
    for t in threads:
        t.join(timeout=30)

    con = sqlite3.connect(f"file:{rec.path}?mode=ro", uri=True)
    try:
        assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        rows = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        con.close()
    assert rows >= 1, "concurrent backup captured no data at all"


def test_backup_never_captures_a_torn_transaction(live):
    """A snapshot must not contain half of a committed transaction.

    Each transaction writes TWO marker rows (detail ends 'a' and 'b'). Any
    correct snapshot therefore holds equally many 'a' and 'b' markers: a
    transaction is present entirely or not at all. An imbalance means a partial
    transaction was captured.

    This is deterministic, not timing-dependent: the markers are compared inside
    one snapshot, so no clock or scheduler coincidence can hide a tear.

    Sensitivity is demonstrated by mutation (documented in
    WAL_BACKUP_RECOVERY_REPORT.md §2): replacing the online backup API with a
    copy of the main DB file makes this test fail, because the WAL-resident
    markers are then absent entirely.
    """
    db, path = live
    stop = threading.Event()

    def writer(tag):
        # Own connection, explicit transactions: two statements, one commit.
        con = sqlite3.connect(path, timeout=30)
        try:
            for i in range(150):
                if stop.is_set():
                    return
                con.execute("BEGIN IMMEDIATE")
                con.execute("INSERT INTO audit_log (ts,actor,action,detail)"
                            " VALUES (?,?,?,?)", (time.time(), tag, "pair", f"{i}a"))
                con.execute("INSERT INTO audit_log (ts,actor,action,detail)"
                            " VALUES (?,?,?,?)", (time.time(), tag, "pair", f"{i}b"))
                con.commit()
        finally:
            con.close()

    threads = [threading.Thread(target=writer, args=(f"t{i}",)) for i in range(3)]
    for t in threads:
        t.start()

    recs = []
    mgr = BackupManager(path)
    for _ in range(5):
        time.sleep(0.02)
        recs.append(mgr.backup(label="torn"))
    stop.set()
    for t in threads:
        t.join(timeout=60)

    for rec in recs:
        con = sqlite3.connect(f"file:{rec.path}?mode=ro", uri=True)
        try:
            assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            halves = con.execute(
                "SELECT COUNT(*) FROM audit_log WHERE action='pair'"
                "   AND (detail LIKE '%a' OR detail LIKE '%b')").fetchone()[0]
            a = con.execute("SELECT COUNT(*) FROM audit_log WHERE action='pair'"
                            "   AND detail LIKE '%a'").fetchone()[0]
            b = con.execute("SELECT COUNT(*) FROM audit_log WHERE action='pair'"
                            "   AND detail LIKE '%b'").fetchone()[0]
        finally:
            con.close()
        assert a == b, (
            f"snapshot {rec.path} holds {a} 'a' and {b} 'b' markers "
            f"({halves} total) — unequal marker counts mean a half-committed "
            "transaction was captured (torn snapshot)")

    # The snapshots must also have captured something: an all-empty backup is
    # balanced but useless, and would pass the check above vacuously.
    con = sqlite3.connect(f"file:{recs[-1].path}?mode=ro", uri=True)
    try:
        total = con.execute("SELECT COUNT(*) FROM audit_log WHERE action='pair'"
                            ).fetchone()[0]
    finally:
        con.close()
    assert total > 0, "no committed marker rows reached any snapshot"


def test_backup_is_checksummed_and_manifested(live):
    db, path = live
    mgr = BackupManager(path)
    rec = mgr.backup()
    assert rec.sha256 == file_sha256(rec.path)
    entries = mgr.manifest()
    assert entries and entries[-1]["sha256"] == rec.sha256
    assert entries[-1]["method"] == "sqlite3-online-backup-api"
    assert os.stat(rec.path).st_mode & 0o077 == 0, "backup must not be group/world readable"


def test_backup_preserves_schema_version(live):
    db, path = live
    mgr = BackupManager(path)
    rec = mgr.backup()
    assert rec.schema_version == db.schema_version()


# ------------------------------------------------------- interrupted backup
def test_interrupted_backup_leaves_no_partial_file(live, monkeypatch):
    """Simulate a crash mid-backup: the destination must not be published, so a
    truncated file can never be restored over good data."""
    db, path = live
    mgr = BackupManager(path)

    def explode(src, dest):
        raise sqlite3.OperationalError("disk I/O error (simulated interruption)")

    # Connection.backup is read-only, so the fault is injected at the snapshot
    # call site instead of by rebinding the method.
    monkeypatch.setattr("skyla.backup._online_backup", explode)
    with pytest.raises(BackupError):
        mgr.backup(label="interrupted")
    monkeypatch.undo()

    published = [p for p in os.listdir(mgr.backup_dir) if p.endswith(".bak")]
    assert published == [], f"an interrupted backup published a file: {published}"


def test_interrupted_backup_does_not_alter_the_source(live, monkeypatch):
    db, path = live
    before = file_sha256(path)
    before_rows = db.query("SELECT COUNT(*) AS c FROM audit_log")[0]["c"]
    mgr = BackupManager(path)

    def failing_backup(src, dest):
        raise sqlite3.OperationalError("simulated")

    monkeypatch.setattr("skyla.backup._online_backup", failing_backup)
    with pytest.raises(BackupError):
        mgr.backup()
    monkeypatch.undo()

    assert file_sha256(path) == before, "the source database was modified"
    assert db.query("SELECT COUNT(*) AS c FROM audit_log")[0]["c"] == before_rows


# ---------------------------------------------------------------- restore
def test_restore_reproduces_counts_and_critical_records(live):
    db, path = live
    mgr = BackupManager(path)
    rec = mgr.backup(label="drill")

    target = os.path.join(tempfile.mkdtemp(), "restored.db")
    result = mgr.restore(rec.path, target)
    assert result["verified"]
    assert result["integrity"] == "ok"

    con = sqlite3.connect(f"file:{target}?mode=ro", uri=True)
    try:
        assert con.execute("SELECT username FROM users WHERE username=?",
                           ("critical_user",)).fetchone() is not None, \
            "the critical user record did not survive restoration"
        assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        restored_counts = table_counts(con)
    finally:
        con.close()
    assert restored_counts == rec.tables


def test_restore_refuses_to_overwrite_the_live_database(live):
    """Destructive-test discipline: restoring over the live DB requires an
    explicit flag."""
    db, path = live
    mgr = BackupManager(path)
    rec = mgr.backup()
    with pytest.raises(RestoreError):
        mgr.restore(rec.path, path)
    # and the live file is untouched
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        assert con.execute("SELECT COUNT(*) FROM users").fetchone()[0] >= 1
    finally:
        con.close()


def test_restore_rejects_a_corrupt_backup(live):
    db, path = live
    mgr = BackupManager(path)
    rec = mgr.backup()
    bad = os.path.join(tempfile.mkdtemp(), "bad.bak")
    with open(bad, "wb") as fh:
        fh.write(b"\x00" * 8192)
    with pytest.raises(RestoreError):
        mgr.restore(bad, os.path.join(tempfile.mkdtemp(), "out.db"))


def test_drill_reports_counts_and_critical_records(live):
    db, path = live
    drill = BackupManager(path).drill(critical={"users.username": "critical_user"})
    assert drill["counts_match"] is True
    assert drill["critical_ok"] is True
    assert drill["restored"]["schema_version"] == db.schema_version()


# -------------------------------------------------- migration compatibility
def test_backup_restores_into_a_current_build(live):
    """A backup taken now must open cleanly with the current schema and pass the
    DB guard used at startup."""
    db, path = live
    from skyla.dbguard import DBState, validate_database
    from skyla.db import MIGRATIONS

    rec = BackupManager(path).backup()
    target = os.path.join(tempfile.mkdtemp(), "restored.db")
    BackupManager(path).restore(rec.path, target)

    report = validate_database(target, max_schema_version=max(v for v, _ in MIGRATIONS))
    assert report.state is DBState.HEALTHY, f"restored DB not HEALTHY: {report.state}"


def test_backup_of_a_database_with_an_interrupted_wal_is_valid(live):
    """A -wal left behind (e.g. after a crash) must be absorbed by the backup."""
    db, path = live
    con = sqlite3.connect(path)
    con.execute("PRAGMA wal_autocheckpoint=0")
    for i in range(50):
        con.execute("INSERT INTO audit_log (ts, actor, action, detail) VALUES (?,?,?,?)",
                    (time.time(), f"crash{i}", "pre-crash", "x"))
    con.commit()
    # Do NOT close: simulate a process that died holding the WAL.
    mgr = BackupManager(path)
    rec = mgr.backup(label="after-crash")
    con.close()
    assert rec.tables["audit_log"] >= 50
    assert rec.integrity == "ok"


def test_torn_db_wal_pair_loses_rows_silently_but_online_backup_does_not(live):
    """A -wal copied at a DIFFERENT instant from its -db is silently wrong.

    This is the second half of A-14 and it is worse than the empty-copy case,
    because nothing reports an error: `integrity_check` says `ok` and the file
    opens normally, it simply holds fewer committed rows than the source.

    Deterministic: the checkpoint below is explicit, so the row counts are fixed.
    """
    db, path = live

    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("CREATE TABLE IF NOT EXISTS t(id INTEGER PRIMARY KEY, v TEXT)")
    for i in range(4):                       # transaction 1
        con.execute("INSERT INTO t(v) VALUES(?)", (f"a{i}",))
    con.commit()

    stale_wal = os.path.join(tempfile.mkdtemp(), "stale.wal")
    shutil.copyfile(path + "-wal", stale_wal)   # snapshot of the WAL, now stale

    for i in range(2):                       # transaction 2
        con.execute("INSERT INTO t(v) VALUES(?)", (f"b{i}",))
    con.commit()
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")   # all 6 rows now in the main file
    committed = con.execute("SELECT COUNT(*) FROM t").fetchone()[0]
    assert committed == 6
    con.close()

    # The naive method: main file from AFTER the checkpoint, WAL from BEFORE it.
    torn = os.path.join(tempfile.mkdtemp(), "torn.db")
    shutil.copyfile(path, torn)
    shutil.copyfile(stale_wal, torn + "-wal")
    con = sqlite3.connect(torn)
    try:
        torn_integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
        torn_rows = con.execute("SELECT COUNT(*) FROM t").fetchone()[0]
    except sqlite3.DatabaseError as exc:      # also an acceptable outcome
        torn_integrity, torn_rows = f"error: {exc}", 0
    finally:
        con.close()

    assert torn_integrity == "ok", "if SQLite detects the tear, that is even better"
    assert torn_rows < committed, (
        f"expected the torn pair to lose rows silently, got {torn_rows}/{committed}")

    # The online backup of the same live database loses nothing.
    rec = BackupManager(path).backup(label="torn-control")
    con = sqlite3.connect(f"file:{rec.path}?mode=ro", uri=True)
    try:
        backs = con.execute("SELECT COUNT(*) FROM t").fetchone()[0]
        assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        con.close()
    assert backs == committed, f"online backup lost rows: {backs}/{committed}"


def test_online_backup_captures_uncheckpointed_wal_only_with_the_api(live):
    """Contrast, in one place: same WAL state, two methods, different answers.

    Main file alone -> schema/data missing. Online backup API -> complete.
    This is the A-14 defect and its fix, side by side, from the same source.
    """
    db, path = live
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("CREATE TABLE IF NOT EXISTS walonly(id INTEGER PRIMARY KEY, v TEXT)")
    for i in range(25):
        con.execute("INSERT INTO walonly(v) VALUES(?)", (f"r{i}",))
    con.commit()
    payload = con.execute("SELECT COUNT(*) FROM walonly").fetchone()[0]
    assert payload == 25
    assert os.path.getsize(path + "-wal") > 0, "precondition: rows are still in the WAL"
    # leave the connection open: the data is genuinely only in the WAL

    main_only = os.path.join(tempfile.mkdtemp(), "mainonly.db")
    shutil.copyfile(path, main_only)
    con2 = sqlite3.connect(main_only)
    try:
        try:
            main_rows = con2.execute("SELECT COUNT(*) FROM walonly").fetchone()[0]
        except sqlite3.DatabaseError:
            main_rows = 0
    finally:
        con2.close()

    rec = BackupManager(path).backup(label="walonly")
    con3 = sqlite3.connect(f"file:{rec.path}?mode=ro", uri=True)
    try:
        backed_rows = con3.execute("SELECT COUNT(*) FROM walonly").fetchone()[0]
    finally:
        con3.close()
    con.close()

    assert main_rows == 0, f"main-file copy unexpectedly kept {main_rows} rows"
    assert backed_rows == payload, f"online backup kept {backed_rows}/{payload}"
