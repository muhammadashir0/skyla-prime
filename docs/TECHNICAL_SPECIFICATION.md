# SKYLA PRIME — Technical Specification

**Version:** 0.1.0 · **Stack:** Python 3.11, FastAPI, Pydantic v2, SQLite, vanilla-JS SPA

## Repository layout

```
skyla/
  config.py          Environment-driven settings (no secrets in code)
  db.py              SQLite persistence (tasks, steps, audit, docs, memory)
  security.py        Bearer auth, RBAC-ready, autonomy levels, injection scan
  core/              planner.py (decomposition), orchestrator.py (lifecycle)
  models/            base.py, registry.py, router.py, http_provider.py, mock.py
  agents/            base.py, registry.py (5 specialist agents)
  knowledge/         store.py (FTS5 + memory), research.py (web fetch)
  integrations/      registry.py, gmail.py, calendar.py, telegram.py
  execution/         sandbox.py (resource-limited subprocess Python — NOT a security boundary; see SECURITY_ARCHITECTURE.md)
  workflows/         operations.py (Workflows B–E)
  api/               app.py (FastAPI, dashboard serving)
apps/web/static/     Dashboard (index.html, app.js, style.css)
tests/unit/          31 tests (router, planner, security, sandbox, knowledge,
                     orchestrator, API)
```

## API reference (summary)

| Method | Endpoint | Purpose |
|---|---|---|
| GET | /api/health | Status + configured providers |
| POST | /api/tasks | Create + run task (background) |
| GET | /api/tasks, /api/tasks/{id} | List / inspect task (plan, steps, verification) |
| GET | /api/models, /api/models/route | Registry + routing preview |
| GET | /api/agents | Agent registry |
| POST/GET | /api/knowledge/documents, /search, /memory | Ingest, FTS search, memory |
| POST | /api/execute/python | Sandboxed Python (L2+) |
| GET | /api/connectors | Connector registry + live/mock status |
| POST | /api/workflows/inbox|meeting|research|telegram | Workflows B–E |
| GET | /api/audit | Audit log |

Full details: docs/API_REFERENCE.md.

## Persistence schema

`tasks`, `task_steps`, `audit_log`, `documents` (+ FTS5 virtual table),
`memories`, `connector_state`. WAL mode; interrupted tasks recovered on boot.

## PostgreSQL migration path

`Database` methods are the only SQL touchpoints. To migrate: implement the
same methods against `asyncpg`/SQLAlchemy, replace `?` placeholders with
`%s`/`$1`, and swap FTS5 for `tsvector` or OpenSearch. No caller changes.

## Testing

`python3 -m pytest tests/ -q` — 31 tests, all passing (Nov 2026).
