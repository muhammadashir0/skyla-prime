"""Model registry — verified candidate models with routing metadata.

Pricing/context data researched Nov 2026 (see docs/MODEL_RESEARCH_REGISTER.md).
Entries are *candidates*: a model is only used when its provider key is
configured, except the local mock which is always available. Scores are
routing heuristics (0-10), not benchmark claims.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelEntry:
    model_id: str
    provider: str
    display_name: str
    strengths: tuple[str, ...]          # task kinds this model is preferred for
    quality: float                       # 0-10 routing heuristic
    cost_per_1m_in: float                # USD
    cost_per_1m_out: float               # USD
    context: int                         # tokens
    latency_tier: str                    # fast | medium | slow
    env_key: str                         # env var that enables this provider
    open_weight: bool = False
    license: str = ""
    notes: str = ""


REGISTRY: tuple[ModelEntry, ...] = (
    ModelEntry("gpt-6-astra", "openai", "GPT-6 Astra", ("reasoning", "general", "research"),
               10.0, 10.0, 50.0, 1_050_000, "slow", "OPENAI_API_KEY",
               notes="Flagship reasoning/agentic. Verify exact ID at enable time."),
    ModelEntry("gpt-6.1-sol", "openai", "GPT-6.1 Sol", ("coding", "general"),
               9.0, 2.0, 10.0, 1_050_000, "medium", "OPENAI_API_KEY"),
    ModelEntry("gpt-6-luna", "openai", "GPT-6 Luna", ("routine", "general"),
               7.0, 0.10, 0.50, 1_050_000, "fast", "OPENAI_API_KEY"),
    ModelEntry("claude-fable-5", "anthropic", "Claude Fable 5", ("reasoning", "research", "coding"),
               10.0, 10.0, 50.0, 1_000_000, "slow", "ANTHROPIC_API_KEY"),
    ModelEntry("claude-opus-5.5", "anthropic", "Claude Opus 5.5", ("coding", "reasoning"),
               9.5, 4.0, 20.0, 1_000_000, "medium", "ANTHROPIC_API_KEY"),
    ModelEntry("claude-sonnet-5.5", "anthropic", "Claude Sonnet 5.5", ("coding", "general", "research"),
               8.5, 2.0, 10.0, 1_000_000, "medium", "ANTHROPIC_API_KEY"),
    ModelEntry("claude-haiku-5.5", "anthropic", "Claude Haiku 5.5", ("routine", "general"),
               7.0, 0.10, 0.50, 200_000, "fast", "ANTHROPIC_API_KEY"),
    ModelEntry("gemini-4-argon", "google", "Gemini 4 Argon", ("reasoning", "research", "multimodal"),
               9.5, 2.0, 10.0, 1_048_576, "medium", "GOOGLE_API_KEY"),
    ModelEntry("gemini-3.8-flash", "google", "Gemini 3.8 Flash", ("routine", "multimodal", "general"),
               7.5, 0.75, 3.75, 1_000_000, "fast", "GOOGLE_API_KEY"),
    ModelEntry("deepseek-v4-pro", "deepseek", "DeepSeek V4 Pro", ("coding", "reasoning", "research"),
               9.0, 1.32, 3.96, 1_000_000, "medium", "DEEPSEEK_API_KEY",
               open_weight=True, license="MIT"),
    ModelEntry("deepseek-v4.1-flash", "deepseek", "DeepSeek V4.1 Flash", ("routine", "coding", "general"),
               7.5, 0.30, 1.20, 1_000_000, "fast", "DEEPSEEK_API_KEY",
               open_weight=True, license="MIT"),
    ModelEntry("qwen3.8-max", "qwen", "Qwen 3.8 Max", ("coding", "general", "research"),
               9.0, 2.50, 7.50, 1_000_000, "medium", "QWEN_API_KEY"),
    ModelEntry("qwen3.8-flash", "qwen", "Qwen 3.8 Flash", ("routine", "multimodal", "general"),
               7.5, 0.15, 0.47, 1_000_000, "fast", "QWEN_API_KEY"),
    ModelEntry("glm-5.3", "glm", "GLM 5.3 (Z.ai)", ("coding", "reasoning", "general"),
               8.5, 1.40, 4.40, 1_000_000, "medium", "GLM_API_KEY",
               open_weight=True, license="MIT"),
    ModelEntry("skyla-mock-0.1", "local", "SKYLA Local Mock 0.1", ("routine", "general", "research", "coding", "reasoning"),
               2.0, 0.0, 0.0, 8192, "fast", "",
               notes="Deterministic local provider for development/testing. NOT an intelligence model."),
)

# Task-kind -> preferred strength tags, in order.
TASK_PREFERENCES: dict[str, tuple[str, ...]] = {
    "reasoning": ("reasoning", "general"),
    "coding": ("coding", "general"),
    "research": ("research", "reasoning", "general"),
    "routine": ("routine", "general"),
    "general": ("general",),
    "multimodal": ("multimodal", "general"),
    "private": ("general",),  # prefers local/open-weight when available
}


def registry_as_dicts() -> list[dict]:
    return [
        {
            "model_id": m.model_id, "provider": m.provider, "display_name": m.display_name,
            "strengths": list(m.strengths), "quality": m.quality,
            "cost_per_1m_in": m.cost_per_1m_in, "cost_per_1m_out": m.cost_per_1m_out,
            "context": m.context, "latency_tier": m.latency_tier,
            "open_weight": m.open_weight, "license": m.license, "notes": m.notes,
        }
        for m in REGISTRY
    ]
