# SKYLA PRIME — GPU Infrastructure Plan

**Current status:** No GPU in the dev environment (2 CPU / 3.8 GB RAM).
Strategy: cloud-first, rented compute for benchmarking; no purchases
without authorization.

## Inference tiers

| Tier | Hardware | Models | Serving |
|---|---|---|---|
| Dev | 1× GPU, 64–128 GB RAM, NVMe | Qwen3-Coder-Next (80B/3B active), small Qwen/Mistral/Gemma | vLLM |
| Advanced inference | Multi-GPU node, NVLink | Mistral Large 3 (NVFP4 on 8×H100), quantized MoE | vLLM / SGLang |
| Training | Distributed cluster | Fine-tuning (PEFT/LoRA), distillation | PyTorch + Ray |
| Research | Multi-node | Scaling experiments | PyTorch distributed |

## Key constraints (from research)

- Aggregate GPU memory does **not** make a model deployable: KV cache,
  interconnect bandwidth and quantization trade-offs dominate.
- Hosted APIs beat self-hosting below ~5M tokens/day for single-host
  models; multi-node MoE (DeepSeek V4 Pro, Kimi K2.6) needs 30–50M/day.
- Therefore: **hosted APIs first**, self-host only when volume/privacy
  justifies it. `SKYLA_CUSTOM_BASE_URL` already supports local vLLM.

## Benchmarking plan

Before any GPU commitment: measure tokens/day, latency SLOs, cost per
successful task on hosted APIs; then size the smallest GPU that meets
them. See docs/COST_AND_RESOURCE_PLAN.md.
