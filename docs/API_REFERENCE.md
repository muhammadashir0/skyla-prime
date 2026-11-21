# SKYLA PRIME — API Reference

Base: `http://localhost:8000` · Auth: `Authorization: Bearer <SKYLA_API_TOKEN>`
(required only when the token is configured).

## Tasks

- `POST /api/tasks` — `{instruction, autonomy_level?, title?}` → `{id, status, injection_flags}`.
  Task runs in background; poll `GET /api/tasks/{id}`.
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

- `POST /api/execute/python` — `{code}` → `{ok, stdout, stderr}` (L2+).
- `POST /api/workflows/inbox` — Workflow B (triage + drafts).
- `POST /api/workflows/meeting` — `{attendee, autonomy_level?}` (Workflow C).
- `POST /api/workflows/research` — `{url}` (Workflow D).
- `POST /api/workflows/telegram` — `{text, chat_id?}` (Workflow E).
- `GET /api/connectors` — connector registry + live/mock status.
- `GET /api/audit` — audit log. `GET /api/health` — status.
