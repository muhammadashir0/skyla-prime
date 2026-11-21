# SKYLA PRIME — Data Governance

## Record provenance (implemented)

Every document in PRIME KNOWLEDGE stores: `source`, `license`, SHA-256
`hash`, `kind`, `created_at`. Web-fetched records store the source URL and
are marked `see-source-terms`. User uploads default to `user-provided`.

## Rules

1. **No indiscriminate scraping.** Only explicit URLs via the research
   fetcher; search-engine scraping is not implemented (ToS/legality).
2. **Retrieval ≠ training.** Knowledge-store content is for retrieval only.
   Training pipelines (Phase 7) require separate, rights-cleared datasets.
3. **Untrusted content.** Fetched/uploaded text is injection-scanned
   (`skyla/security.py::scan_untrusted`); flags are recorded on tasks.
4. **Deduplication:** content hash prevents exact-duplicate ingestion
   (semantic dedup is a Phase-4 item).
5. **Deletion:** documents/memories are deletable via DB (admin operation);
   removal history is audit-logged.

## Privacy classification

Tasks marked `private` route to local/open-weight models only. Memory
reliability scores gate promotion: model-generated statements are stored at
low reliability and never treated as facts without user/source confirmation.
