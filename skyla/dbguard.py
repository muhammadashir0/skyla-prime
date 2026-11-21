"""Fail-closed database initialization and integrity validation (v0.3.0, A-07).

v0.2.0 could not distinguish "brand new deployment" from "existing database that
was truncated to zero bytes". Both produced a clean schema and a fresh admin
account, so total data loss was reported as a healthy system.

This module classifies the database file before anything is written, and refuses
to start on any ambiguous or damaged state.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class DBState(str, Enum):
    NEW = "new"                          # absent file: genuine first run
    HEALTHY = "healthy"                  # opens, integrity ok, schema present
    EMPTY_EXISTING = "empty_existing"    # exists but has no schema -> REFUSE
    CORRUPT = "corrupt"                  # sqlite cannot read it -> REFUSE
    SCHEMA_TOO_NEW = "schema_too_new"    # newer than this build -> REFUSE
    SCHEMA_MISSING = "schema_missing"    # tables absent but version row present
    PERMISSIONS = "permissions"          # world/group readable -> REFUSE


class DatabaseIntegrityError(RuntimeError):
    """Startup must stop. The original file is never modified."""


@dataclass
class DBReport:
    state: DBState
    path: str
    detail: str
    schema_version: int = 0
    size_bytes: int = 0
    checksum: str = ""
    # A non-fatal observation. Crucially this is NOT a state: an integrity
    # finding always wins over a permission finding (regression: an earlier
    # build reported PERMISSIONS for a corrupt database and hid the corruption).
    warning: str = ""

    @property
    def ok(self) -> bool:
        return self.state in (DBState.NEW, DBState.HEALTHY)

    def as_dict(self) -> dict:
        return {"state": self.state.value, "path": self.path, "detail": self.detail,
                "schema_version": self.schema_version, "size_bytes": self.size_bytes,
                "checksum": self.checksum, "warning": self.warning, "ok": self.ok}


def file_checksum(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:32]


def _check_permissions(path: str) -> str:
    """The DB holds password hashes and MFA secrets: it must not be world-readable."""
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        return f"insecure permissions {oct(mode)} (group/other have access)"
    return ""


def validate_database(path: str, *, max_schema_version: int,
                      allow_loopback_owner_root: bool = True) -> DBReport:
    """Classify a database file without modifying it."""
    p = Path(path)
    if not p.exists():
        return DBReport(DBState.NEW, path, "file does not exist (genuine first run)")

    size = p.stat().st_size
    if size == 0:
        # THE A-07 CASE. An existing, empty file is NOT a new deployment.
        return DBReport(
            DBState.EMPTY_EXISTING, path,
            "file exists but is 0 bytes — this is not a new deployment. "
            "Restore from backup, or delete the file to initialize deliberately.",
            size_bytes=0)

    perm = _check_permissions(path)

    report = _classify(path, max_schema_version=max_schema_version, size=size)
    if report.state is DBState.HEALTHY and perm:
        # Integrity is fine, but the file is group/world readable. This is still
        # a refusal -- just one that does not pretend the file is damaged.
        return DBReport(DBState.PERMISSIONS, path, perm,
                        schema_version=report.schema_version, size_bytes=size,
                        checksum=report.checksum)
    if perm:
        report.warning = perm
    return report


def _classify(path: str, *, max_schema_version: int, size: int) -> DBReport:
    """Pure integrity/schema classification. Never looks at file permissions."""
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return DBReport(DBState.CORRUPT, path, f"cannot open: {exc}", size_bytes=size)

    try:
        con.row_factory = sqlite3.Row
        check = con.execute("PRAGMA integrity_check").fetchone()
        integrity = check[0] if check else "no result"
        if integrity != "ok":
            return DBReport(DBState.CORRUPT, path,
                            f"integrity_check failed: {integrity}", size_bytes=size)

        tables = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "schema_version" not in tables:
            return DBReport(DBState.EMPTY_EXISTING, path,
                            "no schema_version table — existing file without our "
                            "schema; refusing to initialize over it", size_bytes=size)

        row = con.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
        version = int(row["v"]) if row and row["v"] is not None else 0
        if version == 0:
            return DBReport(DBState.SCHEMA_MISSING, path,
                            "schema_version table is empty", size_bytes=size)
        if version > max_schema_version:
            return DBReport(DBState.SCHEMA_TOO_NEW, path,
                            f"database schema v{version} is newer than this build "
                            f"(v{max_schema_version}); refusing to downgrade",
                            schema_version=version, size_bytes=size)

        # A schema-version row with no user table would mean a half-applied state.
        if "users" not in tables:
            return DBReport(DBState.SCHEMA_MISSING, path,
                            "schema_version present but users table missing",
                            schema_version=version, size_bytes=size)

        return DBReport(DBState.HEALTHY, path, "integrity ok",
                        schema_version=version, size_bytes=size,
                        checksum=file_checksum(path))
    except sqlite3.DatabaseError as exc:
        return DBReport(DBState.CORRUPT, path, f"sqlite error: {exc}", size_bytes=size)
    finally:
        con.close()


def enforce(path: str, *, max_schema_version: int,
            allow_init: bool | None = None) -> DBReport:
    """Validate and RAISE unless the state is safe to proceed with.

    REFUSES to bootstrap an existing empty database: that is the silent-data-loss
    path. Initialization must be explicit.
    """
    report = validate_database(path, max_schema_version=max_schema_version)

    # Initialization is checked FIRST: NEW is "ok" for a fresh file, but only an
    # explicit operator decision may create one.
    if report.state is DBState.NEW:
        if allow_init is not True:
            raise DatabaseIntegrityError(
                "database does not exist and initialization was not explicitly "
                "authorized (set SKYLA_INIT_DB=1 for a genuine first run)")
        return report

    if report.ok:
        return report

    # Everything else is fatal. The file is left untouched for forensic recovery.
    raise DatabaseIntegrityError(
        f"refusing to start: database state is '{report.state.value}' — {report.detail}. "
        "The existing file has NOT been modified. Restore from backup or inspect it "
        "before retrying.")
