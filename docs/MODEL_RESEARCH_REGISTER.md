# SKYLA PRIME — Model Research Register

**Researched:** 2026-11-21 (web sources: aimlapi.com, developersdigest.tech,
aibusinessweekly.net, teamday.ai, kingy.ai, fireworks.ai — see citations in
the research log). Prices are per 1M tokens (input/output), USD.

> ⚠️ Model IDs and prices move fast. The registry (`skyla/models/registry.py`)
> stores candidates; always verify the exact model ID against the provider's
> current docs before enabling. Scores are routing heuristics, not benchmarks.

## Frontier commercial models (Nov 2026)

| Model | Provider | Context | $/1M in/out | Notes |
|---|---|---|---|---|
| GPT-6 Astra | OpenAI | 1.05M | $10 / $50 | Flagship reasoning/agentic |
| GPT-6.1 Sol | OpenAI | 1.05M | $2 / $10 | Daily coding/knowledge work |
| GPT-6 Luna | OpenAI | 1.05M | $0.10 / $0.50 | High-volume routing/extraction |
| Claude Fable 5.x | Anthropic | 1M | $8–10 / $40–50 | Hardest long-horizon agent work |
| Claude Opus 5.5 | Anthropic | 1M | $4 / $20 | Code review, repo reasoning |
| Claude Sonnet 5.5 | Anthropic | 1M | $2 / $10 | Daily coding/knowledge |
| Claude Haiku 5.5 | Anthropic | 200K | $0.10 / $0.50 | Cheap/fast classification |
| Gemini 4 Argon | Google | 1.05M | $2 / $10 (promo) | Long-context, multimodal |
| Gemini 3.8 Flash | Google | 1M | $0.75 / $3.75 | Fast multimodal |

## Open-weight / low-cost models

| Model | Provider | Context | $/1M in/out | License | Notes |
|---|---|---|---|---|---|
| DeepSeek V4 Pro | DeepSeek | 1M | $1.32 / $3.96 peak | MIT | 1.6T/49B MoE; API easiest path |
| DeepSeek V4.1 Flash | DeepSeek | 1M | $0.30 / $1.20 peak | MIT | Cheapest viable coding API |
| Qwen 3.8 Max/Flash | Alibaba | 1M | $2.50/$7.50 · $0.15/$0.47 | Apache 2.0 (open variants) | Multilingual, agentic coding |
| GLM-5.3 | Z.ai | 1M | $1.40 / $4.40 | MIT | Strong open coding/reasoning |
| Kimi K2.6/K3 | Moonshot | 256K–1M | varies | Modified MIT | Long-horizon tool work |
| Qwen3-Coder-Next | — | 262K | self-host | Apache 2.0 | 80B/3B active; realistic local coding |

## Routing policy (implemented)

- **Complex reasoning** → highest-quality reasoning model available.
- **Coding** → best verified coding model (DeepSeek V4 Pro / GLM-5.3 / Qwen 3.8 Max tier).
- **Routine** → cheapest fast model (Luna/Haiku/Flash tier).
- **Private** → local or open-weight only.
- **Fallback:** ordered candidate list; first success wins; mock is last resort.

## Verification status

- Registry entries: **researched, not yet live-verified** (no provider keys
  in the dev environment). Enabling a key + running a smoke task is the
  verification step — see docs/DEPLOYMENT_GUIDE.md.
- Benchmarks (SWE-bench, GPQA, etc.) are vendor-reported in sources above;
  SKYLA PRIME does not claim them. See docs/BENCHMARK_STRATEGY.md.
