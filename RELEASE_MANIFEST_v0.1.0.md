# SKYLA PRIME v0.1.0 — Release Manifest

**Release:** v0.1.0 · **Date:** 2026-11-21 · **Branch:** arena/2a497c0e-skyla-prime
**Audit:** docs/AUDIT_REPORT_v0.1.0.md (independent audit, 2026-11-21)

## Contents

- `skyla/` — backend package (API, core, models, agents, knowledge,
  integrations, execution, workflows)
- `apps/web/static/` — SKYLA PRIME COMMAND dashboard
- `tests/` — 36 automated tests (unit + API + security + audit regressions)
- `docs/` — 19 documents (architecture, security, API, deployment, audit…)
- `Dockerfile`, `docker-compose.yml`, `.env.example`, `pyproject.toml`
- `SECURITY.md`, `LICENSE` (MIT)

## Verified

- Fresh-venv install via documented instructions: `pip install -e ".[dev]"`
- Test suite: **36 passed** (`python3 -m pytest tests/ -q`)
- Live server smoke test: health, task lifecycle, workflows, audit log
- No secrets in Git history; `.env` excluded; `.env.example` placeholders only

## Known limitations (must be read before production use)

1. Python execution endpoint is resource-limited, **not** a security sandbox.
2. Frontier model + connector live operations require credentials (mock mode default).
3. Single shared API token; no MFA/RBAC yet. SQLite single-instance only.
4. No light theme; partial input labeling (accessibility roadmap item).

## Install

```bash
pip install -e ".[dev]"
python3 -m uvicorn skyla.api.app:app --host 0.0.0.0 --port 8000
```

## Decision

**CONDITIONAL GO** for first GitHub release as a development milestone
(not production). See audit report for conditions.
