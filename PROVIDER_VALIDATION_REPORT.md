# PROVIDER VALIDATION REPORT — SKYLA PRIME v0.2.0

**Scope:** Workstream 6 — model providers and integrations: auth, request construction, response
validation, timeouts, rate limits, retries, error normalisation, health checks, model-ID
verification, usage/cost logging, and honest LIVE / MOCK / DISABLED / NOT CONFIGURED status.
**Date:** 2026-11-21.

---

## 1. Executive summary — read this first

**No live model provider and no live integration was exercised in this environment.** No provider API
key, no Google OAuth credential and no Telegram bot token exists here, and the engineering
constraints forbid purchasing infrastructure or sending real communications without authorisation.

Therefore:

- Every live path below is marked **NOT VERIFIED** with a concrete blocker.
- What *is* verified: the full request/response/retry/error pipeline of the OpenAI-compatible adapter,
  driven by `httpx.MockTransport` (real HTTP client, real code paths, deterministic fake server) —
  including retry-on-429, error normalisation, usage capture and malformed-response handling.
- Mock paths for all three connectors are verified: they never send and always label themselves
  `mock`.
- No claim is made anywhere in code, docs or UI that a provider is LIVE when it is not.

## 2. Provider status matrix (as observed on this host)

| Provider | Env key | Status | Evidence |
|---|---|---|---|
| `local` (MockProvider) | — | **MOCK** | always available; deterministic; labelled "not a frontier model" |
| `openai` | `OPENAI_API_KEY` | **NOT CONFIGURED** | key absent; provider not instantiated |
| `deepseek` | `DEEPSEEK_API_KEY` | **NOT CONFIGURED** | key absent |
| `qwen` | `QWEN_API_KEY` / `DASHSCOPE_API_KEY` | **NOT CONFIGURED** | key absent |
| `glm` | `GLM_API_KEY` | **NOT CONFIGURED** | key absent |
| `custom` | `SKYLA_CUSTOM_BASE_URL` | **NOT CONFIGURED** | no base URL set |
| Gmail | `GOOGLE_OAUTH_CLIENT_ID/SECRET` + `GOOGLE_REFRESH_TOKEN` | **MOCK** | `mode=mock`, `live=False` |
| Google Calendar | same OAuth triple | **MOCK** | `mode=mock`, `live=False` |
| Telegram | `TELEGRAM_BOT_TOKEN` | **MOCK** | `mode=mock`, `live=False` |

Observed: `providers: ['local']`; all three connectors report `mode: mock | live: False`.
`/api/providers/health` returns `MOCK` for `local` and would return `LIVE`/`NOT CONFIGURED`
per provider health check for configured ones.

There is **no** `DISABLED` state in this deployment because disabling is a deployment choice
(`SKYLA_EXECUTION_PROVIDER=disabled`, empty keys). A provider without a key is *not configured*, which
is reported as such rather than as a failure.

## 3. Model adapter — what was validated (mocked HTTP)

`skyla/models/http_provider.py` — `OpenAICompatibleProvider`.

| Requirement | Implementation | Test | Result |
|---|---|---|---|
| Official auth scheme | `Authorization: Bearer <key>` | request construction | **PASS** |
| Valid request construction | `POST {base}/chat/completions` with `model`, `messages[{system},{user}]`, `temperature`, `max_tokens` | `test_provider_success_and_usage` | **PASS** |
| Response validation | `choices[0].message.content` extracted; `KeyError/IndexError/TypeError` → `RuntimeError("Malformed provider response…")` | `test_provider_error_normalization` | **PASS** |
| Timeout handling | `httpx` client timeout; timeout counts as retryable | retry loop | **PASS** |
| Rate-limit handling | 429 is retryable, exponential backoff `2**attempt` | `test_provider_retry_on_429` (429, 429, 200 → 3 attempts, success) | **PASS** |
| Retry strategy | max 3 attempts on 429/5xx/network; **4xx other than 429 is not retried** (caller error) | as above | **PASS** |
| Error normalisation | `ProviderError(status, message)` for non-retryable/terminal failures | `test_provider_error_normalization` (401 → `ProviderError.status == 401`) | **PASS** |
| Health check | `GET {base}/models`; returns provider, status, model count / error | `/api/providers/health` | **PASS (mock transport)** |
| Model-ID verification | `health_check` lists the provider's real model ids and reports whether the configured `model_id` is present — **not asserted against a live catalogue** | implementation only | **NOT VERIFIED** (no key) |
| Usage logging | `usage.prompt_tokens` / `completion_tokens` → `ChatResult`, then `db.log_usage` | `test_usage_logging`, live `/api/metrics` showed `calls: 4, in_tok: 502, out_tok: 450` | **PASS** |
| Cost logging | per-model pricing table × tokens → `cost_usd`, persisted per call | `/api/metrics` → `usage.cost` | **PASS** |
| Latency tracking | `latency_ms` per call, `provider_latency_ms` metric (p50/max) | `/api/metrics` → `observations` | **PASS** |

**Bug fixed during this workstream:** the `usage_callback` existed but was never connected to
anything, so provider cost/usage rows were never written for real HTTP providers. It is now wired at
startup (`_record_usage` → `db.log_usage` + metrics) for every provider that supports it. Errors in the
telemetry path are caught and logged so a metrics failure can never break a completion.

### 3.1 Retry safety note

Retries are safe for *model inference* (no external side effect beyond cost). They are deliberately
**not** the mechanism used for external writes — that is the action ledger's job
(`IDEMPOTENCY_DESIGN.md`). A retried chat completion cannot duplicate an email.

## 4. Model registry and model-ID accuracy

`skyla/models/registry.py` carries 15 candidate models with quality/cost/context/latency/licence and
was assembled from published vendor pricing in November 2026. **Prices and model ids are
vendor-published claims, not values verified against a live API in this environment.** Any deployment
must treat the registry as a starting configuration and re-verify ids and prices against the provider
before enabling live traffic. The registry's job here is routing heuristics, not billing truth.

`skyla-mock-0.1` is explicitly labelled a local deterministic stand-in and is never presented as a
capable model.

## 5. Integrations

### 5.1 Safe test accounts / recipients — blocker

Workstream 6 asks for safe test accounts and test recipients. Setting those up requires:

- a Google Cloud project with OAuth consent and a test user (authorisation + billing relationship),
- a Telegram bot token and a dedicated test chat,
- and explicit permission to send.

None of these exist here, and the constraints forbid acquiring them unilaterally. **Blocker:** no
provisioned test tenant and no authorisation to contact real recipients. Consequently:

- All connectors run in **mock** mode and record `logged-not-sent` / `draft-prepared-not-sent`.
- `test_no_real_sends_in_mock_mode` asserts the mock path can never surface as `live`.
- Live request construction is implemented and code-reviewed but **NOT VERIFIED** end to end.

### 5.2 What the live paths would do (implemented, unverified)

| Connector | Live operation | Auth | Safeguard |
|---|---|---|---|
| Gmail | `GET /gmail/v1/users/me/messages` search; `POST /gmail/v1/users/me/drafts` for a draft | OAuth refresh-token exchange | drafts only — **never** `messages.send`; ledger-guarded |
| Calendar | `GET/POST /calendar/v3/…/events` | same OAuth | ledger-guarded; autonomy ceiling applies |
| Telegram | `POST /bot<token>/sendMessage` | bot token in URL | ledger-guarded; mock chat id by default |

Note the deliberate design choice: the Gmail connector can create a **draft** but there is no code
path that *sends* mail. That is the strongest available guarantee that the platform cannot email a
real person without a human in the loop.

## 6. Secrets handling on provider paths

- Keys are read from environment via `Settings`; they are never returned by an endpoint.
- Error messages record status codes and provider names, not keys; `ProviderError` messages are
  truncated and the observability layer additionally redacts `Bearer …` / `api_key=…` patterns.
- Request logs do not include bodies.
- No key is written to the DB, audit log or metrics.

## 7. Failover behaviour

`ModelRouter` falls back in quality order and always ends at the mock provider, so a task completes
with an honest, labelled, degraded result rather than a 500. `/api/health` exposes which providers
exist, so an operator can see that a deployment is running on mock only. The orchestrator records the
model actually used per step, and `test_end_to_end_task_lifecycle` confirms the pipeline works
end to end on the mock path.

## 8. Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| P-1 | Medium | `usage_callback` was never connected → no provider cost logging | **FIXED** (wired at startup, tested) |
| P-2 | Low | Registry prices/model ids are vendor claims, unverified live | Documented; must be re-verified before live traffic |
| P-3 | Medium | No live provider credentials ⇒ live adapter behaviour unproven | **NOT VERIFIED** — blocker: credentials |
| P-4 | Medium | No safe test tenant for connectors ⇒ live connector behaviour unproven | **NOT VERIFIED** — blocker: test accounts + authorisation |
| P-5 | Low | `metrics` had no generic observation API for latency series | **FIXED** (`observe()` with bounded series) |

## 9. What an operator must do to move a row from NOT VERIFIED to LIVE

1. Provide credentials via environment (never in code, never in chat).
2. Call `/api/providers/health` and confirm the configured model id appears in the provider's list.
3. Run a single low-cost completion and confirm `provider_usage` gains a row with non-zero tokens and
   a plausible cost.
4. For connectors: use a dedicated test account, send to a test recipient only, and confirm the
   action ledger records exactly one execution per idempotency key.
5. Re-run `pytest tests/unit/test_observability_providers.py`.

Until steps 1–5 are done for a given provider, this report's status for it **remains NOT VERIFIED**.
