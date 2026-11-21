# DATABASE MIGRATION PLAN — SKYLA PRIME v0.2.0

**Status:** versioned migrations implemented and tested. PostgreSQL migration is a **plan**, not
implemented code. Database recovery is demonstrated by test.
**Scope:** Workstream 5.

---

## 1. Current state (implemented)

- Engine: **SQLite 3** (stdlib `sqlite3`), file at `SKYLA_DB_PATH` (default `data/skyla.db`).
- Journal: **WAL** (`journal_mode=WAL`), `foreign_keys=ON`.
- Configuration: `SKYLA_DB_PATH` environment variable — added in v0.2.0 so tests and deployments can
  isolate databases (previously hard-coded, which made clean-environment testing impossible).
- One connection per process behind a `threading.Lock`; writes are serialised in-process.

### 1.1 Formal versioning

`schema_version(version INTEGER PRIMARY KEY, applied_at REAL)`. `MIGRATIONS` is an ordered list:

| Version | Change |
|---|---|
| 1 | baseline v0.1.0 schema (tasks, task_steps, documents, memories, audit_log, connector_state) |
| 2 | v0.2.0 identity + ledger + usage: `users`, `sessions`, `api_tokens`, `action_ledger`, `provider_usage`, `schema_version` |
| 3 | `owner_id` columns on `tasks`, `documents`, `memories` (cross-user isolation), backfilled to `admin` |
| 4 | `grants` column on `users` (per-agent / per-connector permissions, explicit denies) |

`_apply_migrations()` is idempotent: each version is applied only if absent, guarded with
`IF NOT EXISTS` (creates) or a `PRAGMA table_info` check (ALTERs). Re-opening a database never
re-applies (`test_migrations_idempotent`, `test_schema_version_tracked`). The live server reports
`schema_version: 4` on `/api/health`.

### 1.2 Transaction integrity

- Every write goes through `execute()` which commits under the lock; no partial multi-statement
  writes are issued outside a single statement.
- The idempotency ledger depends on `idempotency_key UNIQUE` — the database is the arbiter of
  duplicate claims, not application logic.

### 1.3 Concurrency — measured, with the honest caveat

`test_concurrent_writes`: 8 threads × 30 inserts = 240 rows, zero errors.
The v0.1.0 audit measured 8 × 50 = 400 rows, zero errors.

**What this proves and does not prove:**
- Proves: the in-process lock + WAL handles concurrent access from threads of one process.
- Does **not** prove: correctness with multiple *processes* on NFS/SMB, or under heavy write
  contention. SQLite's WAL still serialises writers; a single `database is locked` at high
  contention is possible with default `busy_timeout`. This is exactly why single-instance SQLite is
  a development posture only.

### 1.4 Backup and recovery — demonstrated

`test_backup_and_recovery` performs a real recovery drill:

1. Write a critical record.
2. `sqlite3.Connection.backup()` to a second file (SQLite online backup API — safe while live).
3. Close the database and **overwrite the live file with junk** (simulated total loss).
4. Open the backup: the record is present and `schema_version` matches.

`test_integrity_check_after_concurrency` asserts `PRAGMA integrity_check = ok`.

Operational procedure (documented, to be automated in v0.3.0):

```bash
# backup (online, no downtime)
sqlite3 data/skyla.db ".backup 'backups/skyla-$(date +%F-%H%M).db'"
# verify
sqlite3 backups/skyla-YYYY-MM-DD-HHMM.db "PRAGMA integrity_check; SELECT MAX(version) FROM schema_version;"
# restore
cp backups/skyla-YYYY-MM-DD-HHMM.db data/skyla.db
```

### 1.5 Data consistency validation

- `PRAGMA foreign_keys=ON` (sessions/api_tokens reference `users(id)`).
- `UNIQUE` constraints: `users.username`, `sessions.token_hash`, `api_tokens.token_hash`,
  `action_ledger.idempotency_key`.
- `PRAGMA integrity_check` asserted in tests.
- `recover_interrupted()` / `recover_interrupted_ledger()` reconcile state left behind by a crash.

## 2. SQLite limitations — stated plainly

| Limitation | Impact |
|---|---|
| Single writer at a time | Write throughput bound to one process; contention under load |
| Single host / single instance | No horizontal scaling, no read replicas |
| Whole-file locking on network filesystems | **Do not** place the DB on NFS/SMB |
| No role-based DB-level access control | Application-level authz only |
| Backup = file copy | Requires the online backup API or a stopped writer for consistency |
| No online DDL for complex changes | Table rewrites need a shadow table or downtime |

These are acceptable for a single-operator development/demo deployment and **not** acceptable for a
multi-tenant production service.

## 3. PostgreSQL migration — plan (NOT implemented)

Nothing here has been executed. No production data migration has been performed or is authorised.

### 3.1 Target design

| Concern | SQLite (today) | PostgreSQL (target) |
|---|---|---|
| Connection | one connection + `threading.Lock` | connection pool (e.g. `asyncpg` pool, `min=5 max=20`), per-request checkout |
| Timestamps | `REAL` epoch seconds | `TIMESTAMPTZ` (keeps sub-second precision, timezone-safe) |
| Ids | `TEXT` (`task_ab12…`) | `TEXT` unchanged, or `UUID` — kept `TEXT` to avoid a data transform |
| Booleans | `INTEGER 0/1` | `BOOLEAN` |
| JSON | `TEXT` + `json` module | `JSONB` (indexable, validated) |
| Auto-increment | `INTEGER PRIMARY KEY AUTOINCREMENT` | `GENERATED ALWAYS AS IDENTITY` |
| Uniqueness | `UNIQUE` | `UNIQUE` (unchanged) |
| Concurrency | serialised writers | MVCC, real concurrent writers |
| Isolation | `READ COMMITTED`-ish via lock | `READ COMMITTED` default; `SERIALIZABLE` for ledger claims |

### 3.2 Migration framework

`alembic` (SQLAlchemy's migration tool) is the recommended framework; it supplies ordered revisions,
`upgrade`/`downgrade` pairs, and a version table. The existing `MIGRATIONS` list maps 1:1 onto
Alembic revisions `0001`–`0004`.

**Dependency decision:** Alembic is **not** added in v0.2.0. Adding SQLAlchemy + Alembic + `psycopg`
is a significant dependency footprint and the target infrastructure is not provisioned
(no PostgreSQL server, no authorised spend). The current versioned, idempotent migration list is the
interim mechanism and already provides ordering and idempotency.

### 3.3 Reversible migrations (where feasible)

| Revision | Up | Down |
|---|---|---|
| 0001 baseline | create base tables | drop them (**destructive**, dev only) |
| 0002 identity/ledger/usage | create 5 tables | drop them (**destructive**) |
| 0003 `owner_id` | `ADD COLUMN owner_id TEXT DEFAULT 'admin'` | `DROP COLUMN owner_id` (safe: additive) |
| 0004 `grants` | `ADD COLUMN grants JSONB DEFAULT '[]'` | `DROP COLUMN grants` (safe: additive) |

Rule: additive revisions are reversible; table-creating revisions have destructive downgrades and are
therefore forward-only in any environment that holds real data.

### 3.4 Execution plan (when authorised)

1. **Freeze writes** or enable dual-write; announce a maintenance window.
2. **Provision** PostgreSQL (not done; no infrastructure authorised).
3. **Backup** SQLite with the online backup API; verify `integrity_check` and `schema_version`.
4. **Schema**: run Alembic `upgrade head` against the empty target.
5. **Copy** data table-by-table in FK order (`users` → `sessions`/`api_tokens` → `tasks` →
   `task_steps` → `documents`/`memories` → `action_ledger` → `provider_usage` → `audit_log`),
   converting `REAL`→`TIMESTAMPTZ`, `0/1`→`BOOLEAN`, JSON text→`JSONB`.
6. **Validate**: row counts per table, `MAX(schema_version)`, spot-check hashes, and re-run
   `PRAGMA integrity_check` on the source.
7. **Cut over**: point `SKYLA_DB_URL` at PostgreSQL; keep the SQLite file read-only for one release
   as a rollback target.
8. **Rollback**: restore the SQLite file and restart — no downgrade script needed because the source
   was never mutated.

**Reconciliation invariant:** `action_ledger` must be copied *before* traffic resumes, otherwise a
retry could duplicate an external write that the ledger was there to prevent.

### 3.5 Code changes required

`Database` is the only SQL-touching layer, so the migration is contained:

- replace `sqlite3.connect` with a pool checkout;
- replace `?` placeholders with `%s` (or use a thin adapter to keep `?`);
- replace `PRAGMA` calls with PostgreSQL equivalents;
- make `execute`/`query` `async` (or keep the sync shim and call it in a threadpool);
- keep the same public method names so no caller changes.

## 4. Tests (this release)

| Test | Proves |
|---|---|
| `test_schema_version_tracked` | version table matches the migration list |
| `test_migrations_idempotent` | re-opening does not re-apply or corrupt |
| `test_expected_tables_exist` | all v0.2.0 tables present |
| `test_concurrent_writes` | 8 threads × 30 writes, no errors |
| `test_backup_and_recovery` | backup → simulated loss → restore preserves data |
| `test_integrity_check_after_concurrency` | `PRAGMA integrity_check = ok` |
| `test_recover_interrupted_tasks` / `_ledger` | crash-left state is reconciled safely |
| `test_usage_logging` | usage aggregation for cost reporting |

## 5. Decision record

- **ADR-5.1** Keep SQLite for development; it is honest, embedded and needs no provisioning. Its
  limitations are documented rather than papered over.
- **ADR-5.2** Versioned migration list now, Alembic at PostgreSQL cut-over — avoids a large
  dependency for a target that does not exist yet.
- **ADR-5.3** Additive `ALTER TABLE` only for existing tables — keeps downgrades feasible.
- **ADR-5.4** PostgreSQL migration requires explicit authorisation; no data has been migrated.
