"""Database integrity & fail-closed recovery (A-07, A-14, A-15, A-16).

Mutation targets: making `enforce()` auto-create on an empty/corrupt file, or
letting startup proceed on an unsupported schema, makes these FAIL.
"""
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from skyla.db import MIGRATIONS, Database
from skyla.dbguard import (DBState, DatabaseIntegrityError, enforce,
                           file_checksum, validate_database)

MAXV = max(v for v, _ in MIGRATIONS)


@pytest.fixture()
def tmpdir():
    return Path(tempfile.mkdtemp())


def make(path: Path, *, sql=True, rows=1, mode=0o600):
    if sql:
        db = Database(str(path))
        for i in range(rows):
            db.audit("t", "a", f"{i}")
        db._conn.close()
    try:
        os.chmod(path, mode)
    except OSError:
        pass
    return path


# ------------------------------------------------------------ classification
def test_absent_file_is_NEW(tmpdir):
    r = validate_database(str(tmpdir / "absent.db"), max_schema_version=MAXV)
    assert r.state is DBState.NEW


def test_empty_existing_file_is_not_new(tmpdir):
    """A-07: the original bug treated a 0-byte file as a fresh install and
    silently created a new admin. It must be EMPTY_EXISTING instead."""
    p = tmpdir / "empty.db"
    p.write_bytes(b"")
    os.chmod(p, 0o600)
    r = validate_database(str(p), max_schema_version=MAXV)
    assert r.state is DBState.EMPTY_EXISTING
    assert r.state is not DBState.NEW


def test_garbage_is_CORRUPT(tmpdir):
    p = tmpdir / "junk.db"
    p.write_bytes(b"\x00" * 8192)
    os.chmod(p, 0o600)
    assert validate_database(str(p), max_schema_version=MAXV).state is DBState.CORRUPT


def test_healthy_database(tmpdir):
    r = validate_database(str(make(tmpdir / "good.db")), max_schema_version=MAXV)
    assert r.state is DBState.HEALTHY
    assert r.schema_version == MAXV


def test_schema_too_new(tmpdir):
    p = make(tmpdir / "future.db")
    con = sqlite3.connect(p)
    con.execute("INSERT INTO schema_version (version, applied_at) VALUES (?, 0)", (MAXV + 50,))
    con.commit()
    con.close()
    assert validate_database(str(p), max_schema_version=MAXV).state is DBState.SCHEMA_TOO_NEW


def test_missing_schema(tmpdir):
    p = tmpdir / "noschema.db"
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE junk(x)")
    con.commit()
    con.close()
    os.chmod(p, 0o600)
    r = validate_database(str(p), max_schema_version=MAXV)
    assert r.state in (DBState.EMPTY_EXISTING, DBState.CORRUPT)


def test_loose_permissions_detected(tmpdir):
    r = validate_database(str(make(tmpdir / "loose.db", mode=0o644)), max_schema_version=MAXV)
    assert r.state is DBState.PERMISSIONS


def test_permissions_never_mask_real_state(tmpdir):
    """Regression: an earlier build short-circuited on permissions and reported
    PERMISSIONS for a corrupt database. Integrity must always be computed."""
    p = tmpdir / "corrupt_loose.db"
    p.write_bytes(b"\x00" * 8192)
    os.chmod(p, 0o666)
    r = validate_database(str(p), max_schema_version=MAXV)
    assert r.state is DBState.CORRUPT, "permission finding masked corruption"
    assert r.warning, "the permission issue should still be reported"


# --------------------------------------------------------------- enforcement
def test_enforce_refuses_empty_existing_and_preserves_bytes(tmpdir):
    p = tmpdir / "empty.db"
    p.write_bytes(b"")
    os.chmod(p, 0o600)
    before = p.read_bytes()
    with pytest.raises(DatabaseIntegrityError):
        enforce(str(p), max_schema_version=MAXV)
    assert p.read_bytes() == before, "original data must be preserved"


def test_enforce_refuses_corrupt_and_preserves_bytes(tmpdir):
    p = tmpdir / "junk.db"
    p.write_bytes(b"NOT A DATABASE" * 100)
    os.chmod(p, 0o600)
    before = p.read_bytes()
    with pytest.raises(DatabaseIntegrityError):
        enforce(str(p), max_schema_version=MAXV)
    assert p.read_bytes() == before
    assert p.stat().st_size == len(before)


def test_enforce_refuses_unsupported_schema(tmpdir):
    p = make(tmpdir / "future.db")
    con = sqlite3.connect(p)
    con.execute("INSERT INTO schema_version (version, applied_at) VALUES (?, 0)", (MAXV + 1,))
    con.commit()
    con.close()
    with pytest.raises(DatabaseIntegrityError):
        enforce(str(p), max_schema_version=MAXV)


def test_enforce_allows_healthy(tmpdir):
    p = make(tmpdir / "good.db")
    r = enforce(str(p), max_schema_version=MAXV)
    assert r.state is DBState.HEALTHY


def test_enforce_allows_explicit_new_deployment(tmpdir):
    r = enforce(str(tmpdir / "brand_new.db"), max_schema_version=MAXV, allow_init=True)
    assert r.state is DBState.NEW


def test_enforce_blocks_init_when_disabled(tmpdir):
    """Bootstrap must be an explicit operator action, never a side effect."""
    with pytest.raises(DatabaseIntegrityError):
        enforce(str(tmpdir / "brand_new.db"), max_schema_version=MAXV, allow_init=False)


def test_integrity_check_detects_page_corruption(tmpdir):
    """A file with a valid header whose pages are damaged must not read HEALTHY."""
    p = make(tmpdir / "pages.db", rows=200)
    data = bytearray(p.read_bytes())
    # Corrupt a large span in the middle, leaving the header intact.
    start = len(data) // 2
    for i in range(start, min(start + 4096, len(data))):
        data[i] = 0xFF
    p.write_bytes(bytes(data))
    os.chmod(p, 0o600)
    r = validate_database(str(p), max_schema_version=MAXV)
    assert r.state is not DBState.HEALTHY, "page corruption not detected"


# ------------------------------------------------------------------ checksums
def test_checksum_is_stable_and_changes_on_write(tmpdir):
    p = make(tmpdir / "c.db")
    a = file_checksum(str(p))
    assert a == file_checksum(str(p))
    db = Database(str(p))
    db.audit("t2", "b", "new")
    db._conn.close()
    assert file_checksum(str(p)) != a


def test_database_file_is_created_0600():
    """Holds password hashes and TOTP secrets: never group/world readable."""
    d = Path(tempfile.mkdtemp())
    p = d / "perm.db"
    db = Database(str(p))
    db._conn.close()
    assert oct(p.stat().st_mode)[-3:] == "600"
    assert oct(d.stat().st_mode)[-3:] == "700"
