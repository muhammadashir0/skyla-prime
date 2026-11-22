"""Transactionally consistent SQLite backup & verified restore (v0.2.2 Mission 4).

Closes A-14.

The defect
----------
v0.2.1 backed up by copying the database file. In WAL mode that is wrong: a
committed transaction lives in `<db>-wal` until a checkpoint moves it into the
main file. Copying only `<db>` can therefore produce a backup that contains
NOTHING (measured: 500 committed rows, copied file reports "no such table: t"),
and copying `<db>` and `<db>-wal` separately while writes continue can capture a
torn pair.

The fix
-------
Use the SQLite **online backup API** (`sqlite3.Connection.backup`), which takes a
consistent snapshot through the same locking machinery readers use. It is safe
while writes are in flight, and the destination is a single self-contained file.

Every backup is:
  * taken via the online backup API (never `cp`);
  * `PRAGMA integrity_check`ed before being declared good;
  * checksummed (SHA-256) and recorded in a manifest with row counts;
  * written to a temp file and atomically renamed, so an interrupted backup can
    never be mistaken for a complete one;
  * verified by a restore drill that compares row counts and critical records.

The original database is only ever opened read-only. Restores go to a disposable
path; `restore()` refuses to overwrite the live database unless explicitly told to.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path


class BackupError(RuntimeError):
    """A backup could not be taken or failed verification."""


class RestoreError(RuntimeError):
    """A backup failed restore verification."""


@dataclass
class BackupRecord:
    path: str
    sha256: str
    size_bytes: int
    created_at: float
    schema_version: int
    tables: dict[str, int]
    integrity: str = "ok"
    source: str = ""
    method: str = "sqlite3-online-backup-api"

    @property
    def total_rows(self) -> int:
        return sum(self.tables.values())

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["created_at_iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                            time.gmtime(self.created_at))
        d["total_rows"] = self.total_rows
        return d


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def table_counts(conn: sqlite3.Connection) -> dict[str, int]:
    """Row count per user table. Used to prove a restore kept the data."""
    names = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    out = {}
    for name in names:
        try:
            out[name] = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
        except sqlite3.DatabaseError:
            out[name] = -1
    return out


def schema_version(conn: sqlite3.Connection) -> int:
    try:
        row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
        return int(row[0]) if row and row[0] is not None else 0
    except sqlite3.DatabaseError:
        return -1


def _online_backup(src: sqlite3.Connection, dest: sqlite3.Connection) -> None:
    """The consistent-snapshot primitive, in one place so it can be fault-injected.

    `Connection.backup` is a read-only attribute, so tests simulating an
    interrupted backup must patch this wrapper rather than the method itself.
    """
    src.backup(dest)


def integrity_check(conn: sqlite3.Connection) -> str:
    try:
        row = conn.execute("PRAGMA integrity_check").fetchone()
        return row[0] if row else "no result"
    except sqlite3.DatabaseError as exc:
        return f"error: {exc}"


class BackupManager:
    """Takes, verifies, lists and restores database backups."""

    def __init__(self, db_path: str, backup_dir: str | None = None):
        self.db_path = db_path
        self.backup_dir = Path(backup_dir or (str(Path(db_path).parent) + "/backups"))
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.backup_dir / "manifest.jsonl"

    # ------------------------------------------------------------- backup
    def backup(self, label: str = "", *, verify: bool = True) -> BackupRecord:
        """Take a consistent snapshot using the online backup API.

        The destination is built in a temporary file inside the backup directory
        and renamed only after integrity verification, so a crash mid-backup
        leaves either a complete `.bak` or no file at all — never a truncated one
        that could later be restored over good data.
        """
        if not os.path.exists(self.db_path):
            raise BackupError(f"source database does not exist: {self.db_path}")

        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        name = f"{Path(self.db_path).stem}-{stamp}-{label or 'manual'}.bak"
        final = self.backup_dir / name
        tmp = self.backup_dir / (name + ".partial")

        src = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        try:
            dest = sqlite3.connect(str(tmp))
            try:
                _online_backup(src, dest)   # <-- consistent-snapshot primitive
                dest.commit()
            finally:
                dest.close()
            # Counts are taken from the SNAPSHOT, not from a second read of the
            # source: a separate read sees later commits and would report a
            # mismatch that is not a backup defect (measured: off-by-one under
            # three concurrent writers).
            snap = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
            try:
                counts = table_counts(snap)
                version = schema_version(snap)
            finally:
                snap.close()
        except sqlite3.Error as exc:
            src.close()
            try:
                tmp.unlink()
            except OSError:
                pass
            raise BackupError(f"online backup failed: {exc}") from exc
        finally:
            src.close()

        if verify:
            dest = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
            try:
                integrity = integrity_check(dest)
                if integrity != "ok":
                    tmp.unlink(missing_ok=True)
                    raise BackupError(f"backup failed integrity_check: {integrity}")
                got = table_counts(dest)
            finally:
                dest.close()
            if got != counts:
                tmp.unlink(missing_ok=True)
                raise BackupError(
                    f"backup row counts are unstable: {counts} != {got}")

        os.replace(tmp, final)            # atomic publish
        os.chmod(final, 0o600)

        rec = BackupRecord(
            path=str(final), sha256=file_sha256(str(final)),
            size_bytes=final.stat().st_size, created_at=time.time(),
            schema_version=version, tables=counts, source=self.db_path)
        self._append_manifest(rec)
        return rec

    def _append_manifest(self, rec: BackupRecord) -> None:
        with open(self.manifest_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec.as_dict()) + "\n")

    def manifest(self) -> list[dict]:
        if not self.manifest_path.exists():
            return []
        out = []
        for line in self.manifest_path.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    # ------------------------------------------------------------ restore
    def verify(self, backup_path: str) -> dict:
        """Validate a backup file without restoring it."""
        p = Path(backup_path)
        if not p.exists():
            raise RestoreError(f"backup not found: {backup_path}")
        try:
            con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        except sqlite3.DatabaseError as exc:
            raise RestoreError(f"backup is not a readable database: {exc}") from exc
        try:
            tables = table_counts(con)
            integrity = integrity_check(con)
        except sqlite3.DatabaseError as exc:
            raise RestoreError(f"backup is not a valid database: {exc}") from exc
        finally:
            con.close()
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        try:
            version = schema_version(con)
        finally:
            con.close()
        return {
            "path": str(p),
            "sha256": file_sha256(str(p)),
            "integrity": integrity,
            "schema_version": version,
            "tables": tables,
        }

    def restore(self, backup_path: str, target_path: str, *,
                overwrite_live: bool = False) -> dict:
        """Restore a backup to `target_path` and verify it.

        Refuses to write to the live database unless `overwrite_live=True` is
        passed explicitly, so a mistake cannot destroy production data.
        """
        if os.path.abspath(target_path) == os.path.abspath(self.db_path) and not overwrite_live:
            raise RestoreError(
                "refusing to overwrite the live database; pass overwrite_live=True "
                "after taking a fresh backup")
        if not Path(backup_path).exists():
            raise RestoreError(f"backup not found: {backup_path}")

        before = self.verify(backup_path)
        if before["integrity"] != "ok":
            raise RestoreError(f"backup is not valid: {before['integrity']}")

        tmp = str(target_path) + ".restore-partial"
        shutil.copyfile(backup_path, tmp)
        os.replace(tmp, target_path)
        os.chmod(target_path, 0o600)

        con = sqlite3.connect(f"file:{target_path}?mode=ro", uri=True)
        try:
            after = {"integrity": integrity_check(con),
                     "schema_version": schema_version(con),
                     "tables": table_counts(con)}
        finally:
            con.close()

        if after["integrity"] != "ok":
            raise RestoreError(f"restored file failed integrity_check: {after['integrity']}")
        if after["tables"] != before["tables"]:
            raise RestoreError(
                f"restored row counts differ from backup: {before['tables']} != {after['tables']}")

        return {"restored_to": str(target_path), "verified": True,
                "source_sha256": before["sha256"], **after}

    # ------------------------------------------------------- restore drill
    def drill(self, critical: dict[str, str] | None = None) -> dict:
        """Backup -> restore into a disposable directory -> compare.

        `critical` maps "table.column" -> a value that must survive, e.g.
        {"users.username": "admin"}.
        """
        rec = self.backup(label="drill")
        workdir = tempfile.mkdtemp(prefix="skyla_drill_")
        target = os.path.join(workdir, "restored.db")
        restored = self.restore(rec.path, target)

        src = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        dst = sqlite3.connect(f"file:{target}?mode=ro", uri=True)
        try:
            src_counts, dst_counts = table_counts(src), table_counts(dst)
            findings = []
            for spec, expected in (critical or {}).items():
                table, _, column = spec.partition(".")
                try:
                    row = dst.execute(
                        f'SELECT 1 FROM "{table}" WHERE "{column}"=? LIMIT 1',
                        (expected,)).fetchone()
                    findings.append({"check": spec, "expected": expected,
                                     "found": bool(row)})
                except sqlite3.DatabaseError as exc:
                    findings.append({"check": spec, "error": str(exc), "found": False})
        finally:
            src.close()
            dst.close()

        return {
            "backup": rec.as_dict(),
            "restored": restored,
            "source_counts": src_counts,
            "restored_counts": dst_counts,
            "counts_match": src_counts == dst_counts,
            "critical_records": findings,
            "critical_ok": all(f.get("found") for f in findings),
            "drill_dir": workdir,
        }
