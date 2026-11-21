# PRIME CONTAINMENT — Database Integrity & Recovery Design

**Scope:** Mission 5, audit findings **A-07** (0-byte DB silently re-initialised), A-14 (naive WAL copy), A-15 (no integrity check), A-16 (no downgrade guard).
**Status:** **PASS** for fail-closed classification, refusal semantics and original-data preservation. Scheduled backup/restore drills **NOT VERIFIED** at v0.3.0 (see §8).

---

## 1. The finding that mattered most

v0.2.0 could not tell these apart:

1. a brand-new deployment (create schema, create admin), and
2. an existing database that had been truncated to 0 bytes (create schema, create admin).

Both produced a clean schema and a fresh admin account. Total data loss was indistinguishable from a healthy first run — the system would report success while the previous database was gone. In the audit, a 0-byte file was replaced with a new database and a new bootstrap admin without a single error.

---

## 2. Fail-closed classification

`skyla/dbguard.py` inspects the file **before anything writes to it**:

| State | Meaning | Decision |
|---|---|---|
| `NEW` | file does not exist | create **only** if initialization is explicit |
| `HEALTHY` | opens read-only, `PRAGMA integrity_check` = ok, schema current | proceed |
| `EMPTY_EXISTING` | file exists, 0 bytes | **REFUSE** |
| `CORRUPT` | SQLite cannot read it, or integrity_check fails | **REFUSE** |
| `SCHEMA_MISSING` | `schema_version` present but tables absent (interrupted migration) | **REFUSE** |
| `SCHEMA_TOO_NEW` | `MAX(version)` > this build's maximum | **REFUSE** (no downgrade) |
| `PERMISSIONS` | group/other have access | **REFUSE** |

`REFUSE` means `DatabaseIntegrityError`, which `skyla/api/app.py` converts into a startup failure:

```
SKYLA PRIME refused to start: refusing to start: database state is 'empty_existing' —
file exists but is 0 bytes — this is not a new deployment. Restore from backup, or
delete the file to initialize deliberately. The existing file has NOT been modified.
```

The process does not serve traffic. There is no degraded mode.

### Original data is preserved

Every check opens the file with `mode=ro` (`file:...?mode=ro`, `uri=True`). Nothing in the validation path writes. Tests assert byte equality before and after a refusal:

```python
before = p.read_bytes()
with pytest.raises(DatabaseIntegrityError):
    enforce(str(p), max_schema_version=MAXV, allow_init=True)
assert p.read_bytes() == before
```

(`test_enforce_refuses_empty_existing_and_preserves_bytes`, `..._corrupt_and_preserves_bytes`)

This is the explicit "stop startup and preserve original data; never silently replace with an empty DB" requirement. A silent empty-DB replacement is now not reachable from any input.

---

## 3. Integrity checks (A-15)

```sql
PRAGMA integrity_check      -- full b-tree + page verification, not just readability
```

A database whose header is intact but whose pages are damaged must not report `HEALTHY`. `test_integrity_check_detects_page_corruption` takes a healthy 200-row database, overwrites a 4 KB span in the middle with `0xFF`, and asserts the result is not `HEALTHY`. A checksum of the database file is also recorded (`file_checksum`, SHA-256, truncated to 32 hex chars) so an operator can compare a restored copy against the expected digest.

---

## 4. Schema and migration consistency (A-16)

* `MAX(version)` is compared against `max(v for v, _ in MIGRATIONS)`. A newer file is refused — a downgrade attempt would silently corrupt a schema the old code does not understand.
* `SCHEMA_MISSING` catches the half-applied case: a `schema_version` row exists but `users` does not. This is the "interrupted migration" state.
* Migrations are applied idempotently and recorded in `schema_version`; v0.3.0 adds v5 (`memories.owner_id`) and v6 (`users.mfa_last_step`).

---

## 5. The bug this design caught in its own implementation

The first version of `validate_database()` checked *permissions first* and returned `PERMISSIONS` immediately. Because files created in a test directory inherit `umask 022` → `0644`, **every** pre-existing database was classified `PERMISSIONS` and the integrity/schema logic never ran. Expected `CORRUPT` was reported as `PERMISSIONS`.

Two fixes:

1. Integrity is computed **first**; a permission finding can only downgrade a `HEALTHY` result, and when integrity has already failed the permission problem is attached as a non-terminal `warning` field rather than becoming the state. `test_permissions_never_mask_real_state` asserts a corrupt 0666 file reports `CORRUPT` with a warning.
2. `Database` now creates the file `0600` inside a `0700` directory, so the permission state is not reached in ordinary operation.

Additionally, `enforce()` originally returned early for `NEW` because `NEW` counted as `ok`, so `allow_init` was never consulted. The check was moved **before** the `ok` shortcut, and the default became `allow_init is not True` (deny). `test_enforce_blocks_init_when_disabled` covers it.

These were found by writing the tests adversarially rather than by trusting the implementation.

---

## 6. Explicit bootstrap (the A-07 core requirement)

**Never auto-create an admin when an existing DB is empty or corrupt.** Both of those states refuse before any bootstrap code is reachable.

For a genuine new deployment:

```bash
SKYLA_INIT_DB=1 skyla serve          # explicit operator action
```

Without it, an absent database is also refused (`initialization was not explicitly authorized`). The bootstrap credential is written once to `data/bootstrap_admin_credential.txt` (gitignored) and must be deleted after first login; the file is not recreated.

---

## 7. File permissions

| Object | Mode | Rationale |
|---|---|---|
| DB directory | `0700` | contains credentials-adjacent data |
| `*.db` | `0600` | password hashes, TOTP secrets, memory content |
| `*.db-wal`, `*.db-shm` | `0600` | WAL frames contain the same data |
| bootstrap credential | `0600` | single-use secret |

`test_database_file_is_created_0600` asserts both modes.

---

## 8. Backup and recovery — status

The mission requires atomic backups, checksums, recovery verification, scheduled backups and restore drills.

* **Checksums:** implemented (`file_checksum`), used in `DBReport`.
* **Recovery verification:** implemented as validation — a restored file must classify `HEALTHY` before the service will serve it.
* **Atomic backup of a live WAL database (A-14):** **NOT VERIFIED** in v0.3.0. The v0.2.1 audit showed a naive `cp` of `-wal`/`-shm` can produce an inconsistent snapshot. The correct mechanism is `sqlite3 .backup` / the online backup API, which takes a consistent read lock. That is not wired into a scheduler here, so no claim is made.
* **Scheduled backups:** **NOT VERIFIED** — no scheduler is deployed.
* **Restore drill:** **NOT VERIFIED** — a drill requires a real deployment to restore into; fabricating a result would violate the "do not claim improvements that cannot be independently reproduced" rule.

A-14 therefore remains **OPEN at P1**, recorded in `PRIME_CONTAINMENT_ACCEPTANCE_REPORT.md`.

---

## 9. Reproducing

```bash
python -m pytest tests/security/test_db_integrity.py -q   # 17 tests
```
