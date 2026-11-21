"""Dynamic model router — classifies tasks and selects the best available
model, with ordered fallback when a provider fails.

Selection accounts for: task kind, quality, cost, latency tier, context
need, privacy (private tasks prefer local/open-weight), and provider
availability (env key configured). The mock provider is always last-resort.
"""
from __future__ import annotations

import os
import re

from ..config import get_settings
from .base import ChatRequest, ChatResult, ModelProvider
from .http_provider import PROVIDER_ENDPOINTS, OpenAICompatibleProvider
from .mock import MockProvider
from .registry import REGISTRY, TASK_PREFERENCES, ModelEntry

# Lightweight keyword classifier (no model call needed for routing).
_KIND_HINTS: list[tuple[str, tuple[str, ...]]] = [
    ("coding", ("code", "bug", "debug", "refactor", "function", "python", "javascript",
                "typescript", "api", "sql", "test", "implement", "software", "repository", "git")),
    ("research", ("research", "report", "study", "evidence", "source", "cite", "citation",
                  "investigate", "analysis", "compare", "literature", "paper")),
    ("reasoning", ("prove", "theorem", "math", "calculate", "equation", "logic", "hypothesis",
                   "root cause", "strategy", "decision", "reason")),
    ("multimodal", ("image", "video", "audio", "photo", "screenshot", "vision")),
    ("private", ("private", "confidential", "secret", "sensitive", "password")),
]


def classify_task(instruction: str) -> str:
    low = instruction.lower()
    for kind, hints in _KIND_HINTS:
        if any(h in low for h in hints):
            return kind
    return "routine" if len(instruction) < 200 else "general"


def _entry_available(entry: ModelEntry) -> bool:
    if entry.provider == "local":
        return True
    return bool(os.getenv(entry.env_key, ""))


def build_providers() -> dict[str, ModelProvider]:
    """Instantiate providers for all configured env keys + mock."""
    s = get_settings()
    providers: dict[str, ModelProvider] = {}
    key_by_provider = {
        "openai": s.openai_api_key, "deepseek": s.deepseek_api_key,
        "qwen": s.qwen_api_key, "glm": s.glm_api_key,
    }
    for provider, (base, default_model) in PROVIDER_ENDPOINTS.items():
        if provider == "custom":
            if s.custom_base_url:
                providers["custom"] = OpenAICompatibleProvider(
                    "custom", s.custom_base_url, s.custom_api_key or "local",
                    os.getenv("SKYLA_CUSTOM_MODEL", "local-model"))
            continue
        key = key_by_provider.get(provider, "")
        if key:
            entry = next((e for e in REGISTRY if e.provider == provider), None)
            providers[provider] = OpenAICompatibleProvider(
                provider, base, key,
                os.getenv(f"SKYLA_{provider.upper()}_MODEL", default_model),
                entry.cost_per_1m_in if entry else 0.0,
                entry.cost_per_1m_out if entry else 0.0)
    providers["local"] = MockProvider()
    return providers


def route_candidates(task_kind: str, estimated_context: int = 0) -> list[ModelEntry]:
    """Ordered candidate models for a task kind (best first)."""
    prefs = TASK_PREFERENCES.get(task_kind, ("general",))
    available = [e for e in REGISTRY if _entry_available(e) and e.context >= estimated_context]
    if not available:
        available = [e for e in REGISTRY if e.provider == "local"]

    def score(e: ModelEntry) -> float:
        s = e.quality
        # Prefer models whose strengths match the task kind.
        for i, p in enumerate(prefs):
            if p in e.strengths:
                s += (len(prefs) - i) * 2.0
                break
        # Privacy: private tasks strongly prefer local/open-weight.
        if task_kind == "private" and (e.provider == "local" or e.open_weight):
            s += 20.0
        # Cheap + fast bonus for routine work.
        if task_kind == "routine":
            s += max(0.0, 3.0 - e.cost_per_1m_in / 2.0)
        return s

    return sorted(available, key=score, reverse=True)


class ModelRouter:
    def __init__(self, providers: dict[str, ModelProvider] | None = None):
        self.providers = providers or build_providers()

    async def chat(self, req: ChatRequest, estimated_context: int = 0) -> ChatResult:
        """Try candidates in order; fall back on provider failure. Never
        silently calls multiple expensive models for a simple task — the
        first success wins."""
        kind = req.task_kind or classify_task(req.user)
        candidates = route_candidates(kind, estimated_context)
        errors: list[str] = []
        for entry in candidates:
            provider = self.providers.get(entry.provider)
            if provider is None:
                continue
            try:
                return await provider.chat(req)
            except Exception as exc:  # noqa: BLE001 — fallback routing
                errors.append(f"{entry.provider}/{entry.model_id}: {exc}")
                continue
        raise RuntimeError("All model providers failed: " + "; ".join(errors))
