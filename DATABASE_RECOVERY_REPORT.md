# DATABASE RECOVERY REPORT — SKYLA PRIME v0.2.1

**Target:** `skyla/db.py` (SQLite, WAL), migrations 1–4
**Method:** source review + destructive testing on disposable databases
**Date:** 2026-11-21
**Result: 5 PASS · 4 FAIL · 1 NOT VERIFIED**

> Sandbox note: the live server was killed (OOM, §T-04 of the threat model) partway through the
> assessment. The DB files written by the **running server** were backed up to `/tmp/db-backup-audit`
> before any destructive test, and all corruption/restore tests below used **disposable copies in
> `/tmp`**, never the live file.

---

## 1. Results

| # | Property | Result | Evidence |
|---|---|---|---|
| 1 | Migration 1 (baseline) | **PASS** | applies cleanly to an empty file |
| 2 | Migration 2 (identity/ledger/usage) | **PASS** | 5 tables created |
| 3 | Migration 3 (`owner_id` columns) | **PASS** | additive ALTER, backfilled to `admin` |
| 4 | Migration 4 (`grants`) | **PASS** | additive ALTER, `DEFAULT '[]'` |
| 5 | Idempotent re-application | **PASS** | restart does not re-apply; `schema_version` stays 4; column survives |
| 6 | Partial-rollback tolerance | **PASS** | deleting the v4 version row → restart re-applies v4 only |
| 7 | **Migration rollback (downgrade)** | **FAIL (Medium)** | **no downgrade path exists** — no `downgrade()`/`rollback()` in the codebase |
| 8 | Backup via online-backup API | **PASS** | users=1, audit=1, `integrity_check ok` |
| 9 | **Backup via naive `cp` (operator default)** | **FAIL (Medium)** | copy is **torn**: `no such table: users` — a backup file that exists but is useless |
| 10 | **Automated backup** | **FAIL (High)** | none in the codebase; only a hand-run documented shell command |
| 11 | **Startup integrity verification** | **FAIL (High)** | `PRAGMA integrity_check` is **never run at startup** (tests only) |
| 12 | Corruption detection (garbage/NUL header) | **PASS** | refuses to start: `DatabaseError file is not a database` |
| 13 | **Corruption detection (0-byte file)** | **FAIL (High)** | starts cleanly, reports `schema_version: 4`, **0 users**, silently re-bootstraps admin — **silent total data loss reported as healthy** |
| 14 | Concurrent writes | **PASS** | 8 threads × 30 writes = 240 rows, 0 errors (in-process lock + WAL) |
| 15 | Transaction rollback | **PASS** | every write is a single autocommitted statement; `execute()` commits under a lock, so no partial multi-statement state |
| 16 | `PRAGMA integrity_check` after load | **PASS** | `ok` |
| 17 | Idempotency ledger persistence | **PASS** | keys survive restart; duplicate detection works post-restart |
| 18 | Interrupted task recovery | **FAIL (Medium)** | tasks are parked as `interrupted`; **nothing resumes them**, and the docstring's "resumable" is aspirational |
| 19 | PostgreSQL compatibility | **NOT VERIFIED** | no PostgreSQL server, no driver installed, no data migrated. `?` placeholders, `REAL` timestamps, `INTEGER` booleans and `PRAGMA` calls are all SQLite-specific and would need the documented adaptation. |
| 20 | Multi-process / network FS safety | **FAIL (Low)** | single-writer SQLite; documented, not tested for NFS (correctly warned against) |

## 2. Detailed findings

### 2.1 A 0-byte database is treated as a fresh install — **HIGH**

Reproduction on a disposable DB:

```
db = Database(p)
db.execute("INSERT INTO users … 'realuser'")
db._conn.close()
open(p,"wb").close()                  # truncate to 0 bytes  (crash during create, or rm+recreate, or a
                                      # failed volume attach)
db2 = Database(p)
→ STARTUP OK, schema=4, users=0        *** SILENT DATA LOSS, reported healthy ***
```

Compare with an 8 KB NUL-filled file, which is correctly rejected (`file is not a database`). The
difference is that `_apply_migrations()` uses `CREATE TABLE IF NOT EXISTS`, so against an empty file
it happily constructs a brand-new schema, and `bootstrap_admin()` then creates a fresh `admin` user
because `SELECT id FROM users LIMIT 1` returns nothing.

**Impact.** The platform comes up green (`/api/health` → `status: ok`, `schema_version: 4`) with no
users, no tasks, no audit history, and a newly generated admin credential. An operator sees a healthy
system and a login that "stopped working"; every record is gone. There is no alarm anywhere.

**Remediation.**
1. Record a *sentinel* on first initialisation (e.g. a row in a dedicated table, or the audit log).
2. On startup, if the file **already existed** but `schema_version` is empty / the sentinel is
   missing → refuse to start with a loud error and instructions, do **not** bootstrap.
3. Run `PRAGMA integrity_check` at startup and fail closed on anything other than `ok`.
4. Require an explicit `SKYLA_INIT_DB=1` (or `skyla init`) for genuine first-run creation.

### 2.2 The documented backup command is the only one that works, and nothing runs it — **HIGH**

```
live DB (WAL) → shutil.copy2(live, naive.db) → sqlite3.connect(naive).execute("SELECT … users")
   OperationalError: no such table: users        # torn copy: the schema lives in the -wal
```

`DATABASE_MIGRATION_PLAN.md` does document `sqlite3 … ".backup"` (correct) — but that is a human step.
No scheduler, no retention, no restore verification, and no alert on stale backups. Meanwhile the
obvious `cp` produces a file that *looks* like a backup and is worthless.

Note also that `skyla.db-wal` is where the recent writes live (`683 952 bytes` at one point), so
copying only `skyla.db` loses nearly everything.

**Remediation.** Ship a `skyla-backup` command/job that uses `Connection.backup()`, writes a
timestamped file, immediately re-opens it (`integrity_check` + row counts + `schema_version`), records
the result in the audit log, prunes old copies, and exposes "last successful backup age" on
`/api/metrics` with an alarm threshold.

### 2.3 No downgrade path — **MEDIUM**

`MIGRATIONS` is a forward-only list of `(version, description)`. There is no `downgrade()` and no
per-revision `down` logic, despite `DATABASE_MIGRATION_PLAN.md` describing reversible revisions.
Migrations 3 and 4 are additive, so a rolling back by deleting the version row is *tolerable* (§1 row
6) — but there is no supported automation, and any future destructive revision (a column rename, a
type change) would be irreversible.

**Remediation.** Adopt Alembic (already the documented plan) or add explicit `down` callables and a
`Database.migrate(target_version)` that refuses to cross a destructive boundary without
`--allow-destructive`.

### 2.4 Interrupted tasks are parked, not recovered — **MEDIUM**

```
recover_interrupted() → status 'interrupted'
steps preserved: 0        (for a task that never started stepping)
resume API endpoint exists: False
```

The docstring says *"interrupted (resumable)"*. Nothing resumes: no endpoint, no scheduler, no
orchestrator path. A task interrupted by a restart stays `interrupted` forever. This is safe (no
double execution) but it is a durability claim that is only half true.

**Remediation.** Either implement `POST /api/tasks/{id}/resume` that re-fits context from stored step
outputs and continues from the first non-completed step, or change the status to `abandoned` and
document that restarts do not resume work.

## 3. What is genuinely solid (independently confirmed)

- **All four migrations apply cleanly and are truly idempotent** — re-opening does not re-apply,
  duplicate rows are not created, and the `grants` column survives. The `PRAGMA table_info` guard for
  ALTERs is the correct pattern.
- **Concurrency works in-process**: 8 threads × 30 writes, zero errors, `integrity_check ok`.
- **`UNIQUE` constraints are the arbiter of the ledger**, not application logic — the right choice.
- **`FOREIGN KEY` enforcement is enabled** (`PRAGMA foreign_keys=ON`), and sessions/tokens reference
  users.
- **The online-backup API produces a correct, verifiable backup**, so recovery *is* achievable.
- **Header/NUL corruption is detected and refused** — the failure is specifically the empty-file case.

## 4. PostgreSQL readiness (inspection only)

Not tested — no server, no driver, no data migration (and none is authorised). Blocking differences
observed in source: `?` placeholders throughout, `REAL` epoch timestamps (loses `TIMESTAMPTZ`
semantics), `INTEGER` booleans, `PRAGMA journal_mode/foreign_keys/table_info/integrity_check`,
`AUTOINCREMENT`, and `sqlite3.Row` access patterns. SQLite's `Database` class is the only SQL-touching
layer, so the migration remains contained, but it is genuinely unimplemented.

## 5. Verdict

**Database migration correctness: PASS.** Idempotent, versioned, additive, and the ledger constraints
are in the database where they belong.

**Database recovery: FAIL.** The recovery properties claimed in v0.2.0 are not operational:
- no startup integrity check,
- a truncated database silently reports a healthy empty system (**High**),
- no automated backup, and the obvious manual method is silently wrong (**High**),
- no downgrade path and no task resume.

A platform that silently loses all data and reports `status: ok` fails the "database recovery is
demonstrated" acceptance criterion, regardless of what the test suite asserts.
