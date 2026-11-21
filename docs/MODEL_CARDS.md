# SKYLA PRIME — Model Cards

## skyla-mock-0.1 (local, deterministic)

- **Type:** template-based local provider for development/testing.
- **Intended use:** pipeline verification, offline dev, CI tests.
- **Limitations:** produces no substantive intelligence; responses are
  explicitly labeled as mock. Excluded from all quality/cost claims.
- **License:** internal.

## External models

No external model is bundled. Candidates and their researched metadata
live in `skyla/models/registry.py` and docs/MODEL_RESEARCH_REGISTER.md.
Each enabled provider must be smoke-tested (docs/DEPLOYMENT_GUIDE.md)
before production use; benchmark figures are vendor-reported and are
not SKYLA PRIME claims.

## Proprietary SKYLA models

None exist yet. Phase 7 (fine-tuning/LoRA) and Phase 9 (foundation-model
research) require feasibility studies first — see
docs/IMPLEMENTATION_ROADMAP.md.
