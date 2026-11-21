# SKYLA PRIME — Security Architecture

## Implemented (MVP)

- **Authentication:** Bearer token (`SKYLA_API_TOKEN`) on all `/api/*`
  endpoints; open only in local dev when unset. Constant-time comparison.
- **Autonomy levels:** 0 Observe · 1 Prepare · 2 Routine execution ·
  3 Standing delegation · 4 Consequential. Enforced server-side against
  `SKYLA_MAX_AUTONOMY` (default 2). Sandbox execution requires L2+.
- **Audit trail:** every task creation, workflow run, ingestion and
  execution is recorded (`audit_log`) with actor, action, detail, level.
- **Prompt-injection defense:** untrusted content (instructions, fetched
  pages) is scanned for injection patterns; flags are stored on tasks.
- **Secrets hygiene:** keys come only from environment variables; never
  logged, never placed in model-visible context (gateway sends only
  system/user prompts).
- **Sandbox:** subprocess Python with timeout, CPU/memory rlimits,
  minimal environment, no network. Defense-in-depth for dev; production
  requires container isolation (Phase 5).
- **Durable state:** tasks/steps persisted; interrupted tasks recovered
  on boot — no silent loss of completed work.

## Roadmap

MFA, RBAC per-user roles, OAuth credential vault (Vault/KMS), network
segmentation, dependency scanning (pip-audit), red-team suite, rate
limiting, encrypted backups, incident-response runbook
(docs/DISASTER_RECOVERY.md).
