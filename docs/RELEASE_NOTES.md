# SKYLA PRIME — Release Notes

## v0.1.0 — 2026-11-21 (Phase 0–1 milestone)

**Implemented:**
- FastAPI backend + SKYLA PRIME COMMAND dashboard (8 wired tabs).
- Model gateway: OpenAI-compatible adapter (OpenAI/DeepSeek/Qwen/GLM/local
  vLLM) + deterministic local mock; dynamic router with fallback.
- Task planner + durable orchestrator (plan → steps → independent
  verification → audit).
- 5 specialist agents (executive, research, engineering, operations,
  verification).
- PRIME KNOWLEDGE: document ingestion, FTS5 search, memory, web research.
- PRIME CONNECT: Gmail, Google Calendar, Telegram (live-ready, mock-safe).
- Workflows B–E: inbox triage, meeting proposal, web research report,
  Telegram commands. Sandboxed Python execution.
- Security: Bearer auth, autonomy levels 0–4, injection scanning, audit log.
- 31 automated tests passing. Full documentation set (18 docs).

**Not yet live (pending credentials):** frontier model calls, Gmail/Calendar/
Telegram live operations. Mock mode is explicit everywhere.

**Known limitations:** sequential step execution; in-process background
tasks (no durable scheduler yet); SQLite (Postgres path documented);
no native Anthropic/Google adapters yet.
