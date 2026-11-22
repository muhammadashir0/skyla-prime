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

The defect was not taken on trust. A WAL database with 300 committed rows
(`wal_autocheckpoint=0`) was copied with a plain file copy — the v0.2.1 method — and
the copy was opened:

```
committed rows: 300
app.db      4096 bytes    (header + empty pages)
app.db-wal 12392 bytes    (every committed row lives here)
app.db-shm 32768 bytes

plain copy of app.db alone -> sqlite3.OperationalError: no such table: t
```

The copy loses **all** committed data, and it does so silently: the file opens, and
the schema is simply absent. This is the shape of failure that matters — not a
corruption error, but an apparently empty database that the application would
re-initialise (see A-07). A copy of `app.db` **together with** `-wal` can also capture
a mismatched pair, because the two files are copied at different instants. Both were
reachable through the v0.2.1 backup path, and neither produced an error.

This reproduction is preserved as two tests, so the defect cannot quietly return:

| Test | What it pins |
|---|---|
| `test_naive_file_copy_loses_committed_rows` | main-file copy raises `no such table: t` while committed rows exist |
| `test_online_backup_captures_uncheckpointed_wal_only_with_the_api` | same source, two methods, side by side: na&iuml;ve copy → **0 rows**, online backup → **25 rows** |
| `test_torn_db_wal_pair_loses_rows_silently_but_online_backup_does_not` | a `-db`/`-wal` pair copied at different instants reports `integrity ok` yet holds **4 of 6** committed rows; the online backup of the same database holds all 6 |

### Sensitivity is measured, not asserted

The second test was verified to be load-bearing by mutation: `_online_backup()` was
replaced with a copy of the main database file only. The test then fails with
`sqlite3.OperationalError: no such table: walonly`; with the real implementation it
passes. A test that cannot fail is documentation, not evidence.

An earlier attempt at this assertion ("an odd number of paired rows means a torn
transaction") was **discarded**: a naive-copy mutant failed it by crashing at the
snapshot stage rather than by producing a torn snapshot, so the assertion itself was
never exercised. The replacements above discriminate on row counts that are fixed by
an explicit `wal_checkpoint(TRUNCATE)`, not on timing.

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

The first implementation counted rows with a **separate read of the source**, after the
snapshot was taken. Under three concurrent writers the backup then failed verification
with an off-by-few (`audit_log 102 != 103`) although the backup itself was perfectly
consistent — a false positive that would have made backups fail *under load*, which is
exactly when they are needed. Counts are now read from the snapshot itself, so the
comparison is between a file and its own metadata. This is recorded because it is the
kind of bug that passes in quiet testing and fails in the field.

## 3. Required scenarios

| # | Scenario | Method | Result |
|---|---|---|---|
| 1 | Backup during normal activity | `backup(label="normal")` | PASS — count and checksum recorded |
| 2 | Backup during concurrent writes | 3 threads writing while 5 backups are taken | PASS — every snapshot `integrity ok` and holds equal `a`/`b` marker counts (no half-committed transaction); `test_backup_during_concurrent_writes_is_consistent`, `test_backup_never_captures_a_torn_transaction` |
| 3 | Simulated interrupted backup | fault injected into the snapshot call | PASS — no `.bak` published, source byte-identical |
| 4 | Restore to a disposable environment | restore to a fresh temp path | PASS — verified, `0600` |
| 5 | Database integrity validation | `PRAGMA integrity_check` after restore | PASS — `ok` |
| 6 | Data count comparison | all table counts before vs after | PASS — equal |
| 7 | Critical-record comparison | named records must survive | PASS — user + schema version found |
| 8 | Migration compatibility | restored file through `dbguard.validate_database` | PASS — `HEALTHY`, schema v6 |

### Evidence that committed records survive restoration

Reproduced with `BackupManager(path).drill(critical={"users.username": "critical_user"})`
on a disposable database:

```
backup.method        sqlite3-online-backup-api
backup.integrity     ok
backup.total_rows    11
backup.tables        users:1  audit_log:1  schema_version:6  action_ledger:0  tasks:0 ...

restored.restored_to /tmp/skyla_drill_0srhctoi/restored.db
restored.verified    true          (source_sha256 == restored sha256)
restored.integrity   ok
restored.tables      identical to backup.tables, key for key

counts_match   True
critical_ok    True
critical_records  [{"check":"users.username","expected":"critical_user","found":true}]
```

`critical_records` covers the one named record supplied; `schema_version` is compared
separately (`restored.schema_version == db.schema_version() == 6`) by
`test_drill_reports_counts_and_critical_records`. Note that the table list includes
the FTS shadow tables (`documents_fts_data: 2`, `documents_fts_config: 1`) — those are
compared too, so a restore that silently drops the search index would fail the drill.

The drill also validates the restored file with the same startup guard the API uses
(`validate_database(...) -> DBState.HEALTHY`), so a backup that restores to a file
the application would refuse to open is treated as a failed backup.

## 4. Safety properties

* **The original is never deleted or replaced.** Validation opens read-only; the
  drill restores to a new temp directory; `restore()` refuses to target the live
  database unless `overwrite_live=True` is passed explicitly
  (`test_restore_refuses_to_overwrite_the_live_database`).
* **A corrupt backup cannot be restored.** `verify()` wraps both the connect and the
  count/integrity reads so that a non-database file surfaces as `RestoreError`, and
  `restore()` re-checks integrity *and* re-compares all row counts after copying
  (`test_restore_rejects_a_corrupt_backup` writes 8 KiB of NUL bytes and asserts a
  clean `RestoreError`). A restore whose counts differ from the backup is also
  rejected, so a truncated-but-openable file cannot be silently accepted.
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
python -m pytest tests/security/test_backup.py -q     # 16 passed
```

## 7. Residual risk

| Risk | Severity | Note |
|---|---|---|
| No scheduled backups | High | a working mechanism that nobody runs is not a backup strategy |
| No off-site copy | High | single-disk failure loses both live DB and backups |
| No encryption at rest | Medium | backups inherit the DB directory permissions only |
| Restore time untested at scale | Medium | staging-sized data only |
