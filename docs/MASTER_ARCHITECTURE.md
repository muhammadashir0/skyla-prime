# SKYLA PRIME — Master Architecture

**Version:** 0.1.0 (Phase 0–1 milestone) · **Date:** 2026-11-21

## System overview

SKYLA PRIME is a model-agnostic intelligence and autonomous-operations
platform. The MVP implements the full control plane with a deterministic
local model provider; frontier providers plug in via environment keys.

```
┌──────────────────────── SKYLA PRIME COMMAND (web dashboard) ────────────────────────┐
│  Dashboard · Tasks · Agents · Models · Prime Connect · Knowledge · Ops · Security    │
└───────────────────────────────────┬───────────────────────────────────────────────────┘
                                    │ REST (FastAPI)
┌───────────────────────────────────▼───────────────────────────────────────────────────┐
│  API LAYER (skyla/api/app.py) — auth, autonomy enforcement, audit logging              │
├───────────────────────────────────────────────────────────────────────────────────────┤
│  CONTROL PLANE                                                                        │
│   Orchestrator (durable task lifecycle, checkpoints, recovery)                        │
│   Planner (rule-based decomposition → dependency graph)                               │
│   Model Router (classify → score → route → fallback)                                  │
│   Agent Registry (executive · research · engineering · operations · verification)     │
├───────────────────────────────────────────────────────────────────────────────────────┤
│  MODEL INTELLIGENCE                                                                   │
│   OpenAI-compatible HTTP adapter (OpenAI/DeepSeek/Qwen/GLM/local vLLM)                │
│   Deterministic local mock (dev/test, always available, clearly labeled)              │
│   Model registry (Nov-2026 researched candidates, cost/quality/context metadata)      │
├───────────────────────────────────────────────────────────────────────────────────────┤
│  PRIME KNOWLEDGE · PRIME MEMORY · PRIME CONNECT · PRIME EXECUTION                     │
│   SQLite FTS5 documents + memory · Gmail/Calendar/Telegram connectors (mock-safe)     │
│   Sandboxed Python execution · Workflows B–E (inbox/meeting/research/telegram)        │
├───────────────────────────────────────────────────────────────────────────────────────┤
│  PERSISTENCE: SQLite (WAL) — tasks, steps, audit, documents, memory, connector state   │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

## Design decisions

1. **SQLite first, Postgres path documented.** Single-file deployment for
   the MVP; the `Database` class is the single seam for swapping backends
   (see TECHNICAL_SPECIFICATION.md).
2. **One OpenAI-compatible adapter** covers OpenAI, DeepSeek, Qwen, GLM and
   local vLLM/SGLang. Native Anthropic/Google adapters are a Phase-1.5 item.
3. **Mock provider is explicit.** Connectors and models without credentials
   run in labeled mock mode — never presented as live.
4. **Independent verification is structural:** the verification agent is a
   different agent from the executor, and its verdict is persisted.
5. **Autonomy is enforced server-side** (levels 0–4, deployment ceiling via
   `SKYLA_MAX_AUTONOMY`, default 2).

## Scaling path

- Replace SQLite with PostgreSQL (repository interface unchanged).
- Add Qdrant/OpenSearch when document volume exceeds FTS5 comfort (~100k+ docs).
- Add Temporal when workflows need long-running timers/retries beyond
  in-process background tasks.
- Add vLLM/SGLang for self-hosted open-weight inference.
