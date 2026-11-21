# SKYLA PRIME — Disaster Recovery

## Data protection

- SQLite database (`data/skyla.db`) is the single source of truth for
  tasks/audit/knowledge. Back it up with file copy (WAL-safe: checkpoint
  first or copy both `.db` and `-wal` files).
- Recommended: daily automated backup to S3-compatible storage with
  30-day retention (Phase-1.5 hardening).

## Recovery procedures

1. **Process crash:** restart the app. Tasks left `running` are marked
   `interrupted` on boot and can be re-run; completed steps are preserved.
2. **Provider outage:** router falls back to the next candidate; mock is
   the last resort. No task data is lost.
3. **Database corruption:** restore from backup; audit log gaps are
   detected by sequence inspection.
4. **Credential compromise:** rotate the affected key, revoke OAuth
   grants, review `/api/audit` for unauthorized actions.

## RPO/RTO targets (proposed)

RPO ≤ 24h (daily backup), RTO ≤ 1h (container restart + restore).
