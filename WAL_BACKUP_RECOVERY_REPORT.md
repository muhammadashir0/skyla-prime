# WAL BACKUP & RECOVERY REPORT — v0.2.2 PRIME QUALIFICATION

**Mission 4.** Close A-14: transactionally consistent SQLite backup, active-write
safety, interrupted-backup behaviour, integrity checksums, verified restore.

## Verdict

> **PASS** for backup correctness and restore verification, measured against a
> disposable database with the original preserved throughout.
> **NOT VERIFIED** for scheduled operation: no scheduler or cron is deployed, so
> "backups happen automatically" has not been demonstrated.

---

## 1. A-14 reproduced before it was fixed

The defect was not taken on trust. A WAL database with 500 committed rows was copied
with `cp`-equivalent file copy — the v0.2.1 method — and the copy was opened:

```
committed rows in source : 500
app.db       4096 bytes   (header + empty pages)
app.db-wal  24752 bytes   (every committed row lives here)
app.db-shm  32768 bytes

NAIVE copy of app.db alone -> "no such table: t"   (0 rows)
NAIVE copy of app.db + app.db-wal while writes continued -> 500 rows, sometimes torn
```

The first case loses **all** committed data. The second can capture a mismatched
pair, because the two files are copied at different instants. Both were reachable
through the v0.2.1 backup path, and neither produced an error.

This reproduction is preserved as a regression test
(`test_naive_file_copy_loses_committed_rows`), so if WAL behaviour ever changes the
suite says so instead of silently passing.

## 2. The fix: SQLite online backup API

```python
src  = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
dest = sqlite3.connect(str(tmp_path))
src.backup(dest)          # consistent snapshot via SQLite's own locking
```

Properties, each tested:

| Property | Mechanism | Test |
|---|---|---|
| Consistent under concurrent writes | online backup API shares the locking machinery readers use | `test_backup_during_concurrent_writes_is_consistent` |
| Captures WAL-resident rows | snapshot includes uncheckpointed frames | `test_online_backup_captures_wal_rows` |
| Source never modified | opened with `mode=ro` | `test_interrupted_backup_does_not_alter_the_source` |
| Verified before publish | `PRAGMA integrity_check` on the copy | `test_backup_is_checksummed_and_manifested` |
| Checksummed | SHA-256 recorded in the manifest | same |
| Atomic | written to `.partial`, `os.replace()` on success | `test_interrupted_backup_leaves_no_partial_file` |
| Counts are trustworthy | taken **from the snapshot**, not a second read | see §3 |

### Bug found: counts from the wrong transaction

The first implementation counted rows in a separate read of the source. Under three
concurrent writers the backup then failed verification with an off-by-one
(`audit_log 102 != 103`) although the backup was perfectly consistent — a false
positive that would have caused production backup failures under load. Counts are
now taken from the snapshot itself. This is recorded because it is the kind of bug
that "passes" in quiet testing and fails in the field.

## 3. Required scenarios

| # | Scenario | Method | Result |
|---|---|---|---|
| 1 | Backup during normal activity | `backup(label="normal")` | PASS — count and checksum recorded |
| 2 | Backup during concurrent writes | 3 threads writing while backup runs | PASS — `integrity_check: ok`, rows captured |
| 3 | Simulated interrupted backup | fault injected into the snapshot call | PASS — no `.bak` published, source byte-identical |
| 4 | Restore to a disposable environment | restore to a fresh temp path | PASS — verified, `0600` |
| 5 | Database integrity validation | `PRAGMA integrity_check` after restore | PASS — `ok` |
| 6 | Data count comparison | all table counts before vs after | PASS — equal |
| 7 | Critical-record comparison | named records must survive | PASS — user + schema version found |
| 8 | Migration compatibility | restored file through `dbguard.validate_database` | PASS — `HEALTHY`, schema v6 |

### Evidence that committed records survive restoration

```
backup -> restore -> compare
  counts_match : True
  critical_ok  : True
  {'check': 'users.username',      'expected': 'critical_user', 'found': True}
  {'check': 'schema_version.version','expected': '6',            'found': True}
  users: 1   audit_log: 1   schema_version kept: 6
```

The drill also validates the restored file with the same startup guard the API uses
(`validate_database(...) -> DBState.HEALTHY`), so a backup that restores to a file
the application would refuse to open is treated as a failed backup.

## 4. Safety properties

* **The original is never deleted or replaced.** Validation opens read-only; the
  drill restores to a new temp directory; `restore()` refuses to target the live
  database unless `overwrite_live=True` is passed explicitly
  (`test_restore_refuses_to_overwrite_the_live_database`).
* **A corrupt backup cannot be restored.** `verify()` raises `RestoreError` for a
  file that is not a readable database, and the restore path re-checks integrity
  after copying (`test_restore_rejects_a_corrupt_backup`). This was a real bug:
  `verify()` originally crashed with an uncaught `sqlite3.DatabaseError` instead of
  reporting a clean failure.
* **Permissions.** Backups are `0600`; a group/world-readable copy of a database
  containing password hashes and TOTP secrets would reintroduce the permission
  finding closed in v0.3.0.
* **Interrupted backup cannot be mistaken for a complete one**, because publication
  is a single atomic rename of a fully verified file.

## 5. Not verified

* **No scheduled backups.** No cron/systemd timer is deployed. `BackupManager.backup()`
  works when called; nothing calls it on a schedule. **NOT VERIFIED.**
* **No restore drill against a real deployment.** Drills ran against disposable
  databases. Restoring a production-sized database (and the downtime it implies) has
  not been exercised. **NOT VERIFIED.**
* **WAL checkpoint behaviour under sustained load** beyond ~900 concurrent writes was
  not measured; `wal_autocheckpoint` is left at SQLite's default.
* **No off-site/encrypted storage.** Backups are written to the database directory;
  no encryption at rest and no replication.

## 6. Reproduction

```bash
python -m pytest tests/security/test_backup.py -q     # 13 passed
```

## 7. Residual risk

| Risk | Severity | Note |
|---|---|---|
| No scheduled backups | High | a working mechanism that nobody runs is not a backup strategy |
| No off-site copy | High | single-disk failure loses both live DB and backups |
| No encryption at rest | Medium | backups inherit the DB directory permissions only |
| Restore time untested at scale | Medium | staging-sized data only |
