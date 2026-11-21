# SKYLA PRIME — Deployment Guide

## Local development

```bash
pip install -e ".[dev]"
python3 -m uvicorn skyla.api.app:app --host 0.0.0.0 --port 8000
# Dashboard: http://localhost:8000
python3 -m pytest tests/ -q
```

## Configuration (environment variables)

| Variable | Purpose |
|---|---|
| `SKYLA_API_TOKEN` | Bearer token for /api/* (empty = local dev open) |
| `SKYLA_MAX_AUTONOMY` | Autonomy ceiling 0–4 (default 2) |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_API_KEY` / `DEEPSEEK_API_KEY` / `QWEN_API_KEY` / `GLM_API_KEY` | Enable model providers |
| `SKYLA_CUSTOM_BASE_URL` + `SKYLA_CUSTOM_MODEL` | Local vLLM/SGLang endpoint |
| `GOOGLE_OAUTH_CLIENT_ID/SECRET`, `GOOGLE_REFRESH_TOKEN` | Gmail + Calendar live mode |
| `TELEGRAM_BOT_TOKEN` | Telegram live mode |

## Docker

```bash
docker compose up --build
```

## Live smoke test (after setting a provider key)

1. `POST /api/tasks` with a research instruction.
2. Poll `GET /api/tasks/{id}` until `completed`.
3. Confirm `model_used` is the real provider (not `skyla-mock-0.1`)
   and the verification verdict is recorded.
