# SKYLA PRIME — API Reference

Base: `http://localhost:8000`

## Authentication (v0.2.0)

Every endpoint except `GET /api/health` and `POST /api/auth/login` requires
`Authorization: Bearer <token>`. Two credential kinds are accepted:

- **Session token** (`sess_…`), from `POST /api/auth/login`, 8 h lifetime, revoked on logout.
- **Scoped API token** (`skt_…`), from `POST /api/auth/tokens`, limited to its scope list.
- The legacy `SKYLA_API_TOKEN` is still accepted and maps to a named `legacy-admin`
  principal. Production deployments should unset it and use real users.

Authorization is capability-based (`tasks:create`, `execute`, `workflows:run`,
`agent:<name>:run`, `connector:<name>:write`, …). Denied requests return **401**
(no/invalid credential) or **403** (credential lacks the capability), and denials are
audited. Records belonging to another user return **404**, not 403, to avoid leaking
existence. See `AUTHORIZATION_ARCHITECTURE.md`.

## Identity

- `POST /api/auth/login` — `{username, password, mfa_code?}` → `{token, user}`.
- `POST /api/auth/logout` — revokes the calling session.
- `POST /api/auth/users` — create user `{username, password, role}` (admin).
- `POST /api/auth/users/{id}/mfa` — enable MFA, returns the TOTP secret (admin/self).
- `POST /api/auth/tokens` — mint a scoped API token `{scopes, ttl_days?}`.
- `POST /api/auth/tokens/revoke` — revoke the calling token.

## Observability

- `GET /api/metrics` — counters, task latency, provider/HTTP latency series, usage totals.
- `GET /api/providers/health` — per-provider LIVE / MOCK / NOT CONFIGURED health.
- Every response carries `X-Trace-Id` for log correlation.

## Tasks

- `POST /api/tasks` — `{instruction, autonomy_level?, title?, idempotency_key?}` →
  `{id, status, injection_flags}`. Task runs in background; poll `GET /api/tasks/{id}`.
  Requires `tasks:create` **and** `agent:<name>:run` for every agent in the plan.
  With `idempotency_key`, a repeat returns `status: duplicate` and the original id.
- `GET /api/tasks` — list (newest first) with plan/verification/cost.
- `GET /api/tasks/{id}` — full record incl. steps.

## Models & agents

- `GET /api/models` — registry + configured providers.
- `GET /api/models/route?kind=coding` — ordered routing candidates.
- `GET /api/agents` — agent registry.

## Knowledge & memory

- `POST /api/knowledge/documents` — `{title, content, source?, license?}`.
- `GET /api/knowledge/search?q=…` — FTS search with excerpts.
- `GET /api/knowledge/documents` — list.
- `POST /api/knowledge/memory` — `{key, value, kind?, reliability?}`.
- `GET /api/knowledge/memory?q=…` — recall.

## Execution & workflows

- `POST /api/execute/python` — `{code, network?}` → `{ok, stdout, stderr, provider,
  isolated, safe_for_untrusted}` (requires `execute`). When the provider is not isolated the
  response carries `isolated: false` and a warning — never a silent claim of safety.
- `POST /api/workflows/inbox` — Workflow B (triage + drafts).
- `POST /api/workflows/meeting` — `{attendee, autonomy_level?, idempotency_key?}` (Workflow C).
  Requires `connector:google-calendar:write`.
- `POST /api/workflows/research` — `{url}` (Workflow D).
- `POST /api/workflows/telegram` — `{text, chat_id?, idempotency_key?}` (Workflow E).
  Requires `connector:telegram:write`.
- `POST /api/workflows/gmail/draft` — `{message_id, body, idempotency_key?}`. Creates a
  **draft only** (no send path exists). Requires `connector:gmail:write`.
- `GET /api/connectors` — connector registry + live/mock status.
- `GET /api/audit` — audit log. `GET /api/health` — status.
