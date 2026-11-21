# SKYLA PRIME — Cost and Resource Plan

**Basis:** Nov-2026 provider pricing (docs/MODEL_RESEARCH_REGISTER.md).
All figures are estimates to be replaced by measured data.

## Tier 1 — Minimum viable research platform (current)

| Item | Monthly |
|---|---|
| Hosting (small VM/container) | $10–50 |
| Model APIs (routine-heavy routing) | $20–200 |
| Storage/networking | $5–20 |
| **Total** | **~$35–270** |

## Tier 2 — Advanced multi-model platform

| Item | Monthly |
|---|---|
| Hosting + Postgres/Qdrant | $100–400 |
| Model APIs (mixed reasoning/coding) | $300–2,000 |
| Monitoring/security tooling | $50–200 |
| **Total** | **~$450–2,600** |

## Tier 3 — Proprietary model research programme

| Item | Monthly |
|---|---|
| GPU rental (training bursts) | $2,000–20,000+ |
| Storage/checkpointing | $200–1,000 |
| Personnel | dominant cost — to be planned |
| **Total** | **$5,000+ (requires feasibility study first)** |

## Cost discipline

- Router prefers cheap/fast models for routine work; expensive models
  only for tasks that need them.
- Every task records `cost_usd` — cost per successful task is tracked
  from day one (see audit + task records).
- No GPU purchases or enterprise commitments without measured workload
  evidence (docs/GPU_INFRASTRUCTURE_PLAN.md).
