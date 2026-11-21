"""Deterministic local mock provider.

Purpose: development, tests, and offline operation. It produces structured,
honest output that clearly states it is a mock — it never pretends to be a
frontier model. Responses are template-based and deterministic per input.
"""
from __future__ import annotations

import hashlib
import re

from .base import ChatRequest, ChatResult, ModelProvider


class MockProvider(ModelProvider):
    name = "local-mock"
    model_id = "skyla-mock-0.1"
    available = True

    async def chat(self, req: ChatRequest) -> ChatResult:
        digest = hashlib.sha256((req.system + req.user).encode()).hexdigest()[:8]
        user = req.user.strip()
        # Extract a short topic hint for a slightly more useful template.
        topic = re.sub(r"\s+", " ", user)[:120]
        text = (
            f"[SKYLA LOCAL MOCK — not a frontier model; configure a provider key for real intelligence]\n\n"
            f"Task kind: {req.task_kind}\n"
            f"Request (digest {digest}): {topic}\n\n"
            f"This deterministic response confirms the full pipeline works end-to-end "
            f"(routing → agent → verification → audit). To obtain a substantive answer, "
            f"set one of OPENAI_API_KEY / ANTHROPIC_API_KEY / GOOGLE_API_KEY / "
            f"DEEPSEEK_API_KEY / QWEN_API_KEY / GLM_API_KEY, or point "
            f"SKYLA_CUSTOM_BASE_URL at a local vLLM/SGLang server.\n\n"
            f"Structured output:\n"
            f"- summary: mock response for '{topic}'\n"
            f"- status: pipeline-ok\n"
            f"- next: configure a model provider for real generation"
        )
        return ChatResult(
            text=text, model=self.model_id, provider=self.name,
            input_tokens=len((req.system + req.user).split()),
            output_tokens=len(text.split()), cost_usd=0.0, latency_ms=1,
            metadata={"mock": True},
        )
