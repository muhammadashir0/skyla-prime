"""Generic OpenAI-compatible HTTP provider.

One adapter covers OpenAI, DeepSeek, Qwen (DashScope), GLM (Z.ai), and any
local vLLM/SGLang/Ollama endpoint that speaks the OpenAI chat-completions
shape. Anthropic/Google native APIs are added as dedicated adapters when
keys are present (see docs/MODEL_RESEARCH_REGISTER.md for the roadmap);
until then those providers are reached via their OpenAI-compatible
endpoints where offered.
"""
from __future__ import annotations

import time

import httpx

from .base import ChatRequest, ChatResult, ModelProvider

# provider -> (base_url, default model) used when env key present but no explicit model.
PROVIDER_ENDPOINTS: dict[str, tuple[str, str]] = {
    "openai": ("https://api.openai.com/v1", "gpt-6.1-sol"),
    "deepseek": ("https://api.deepseek.com/v1", "deepseek-v4.1-flash"),
    "qwen": ("https://dashscope.aliyuncs.com/compatible-mode/v1", "qwen3.8-flash"),
    "glm": ("https://api.z.ai/api/coding/paas/v4", "glm-5.3"),
    "custom": ("", ""),  # from SKYLA_CUSTOM_BASE_URL
}


class OpenAICompatibleProvider(ModelProvider):
    def __init__(self, provider: str, base_url: str, api_key: str, model_id: str,
                 cost_in: float = 0.0, cost_out: float = 0.0):
        self.name = provider
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model_id = model_id
        self.available = bool(base_url and api_key)
        self._cost_in = cost_in
        self._cost_out = cost_out

    def cost(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens / 1_000_000) * self._cost_in + (output_tokens / 1_000_000) * self._cost_out

    async def chat(self, req: ChatRequest) -> ChatResult:
        if not self.available:
            raise RuntimeError(f"Provider '{self.name}' is not configured (missing key/endpoint)")
        t0 = time.time()
        payload = {
            "model": self.model_id,
            "messages": [
                {"role": "system", "content": req.system},
                {"role": "user", "content": req.user},
            ],
            "temperature": req.temperature,
            "max_tokens": req.max_tokens,
        }
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            resp.raise_for_status()
            data = resp.json()
        latency_ms = int((time.time() - t0) * 1000)
        choice = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        in_tok = int(usage.get("prompt_tokens", 0))
        out_tok = int(usage.get("completion_tokens", 0))
        return ChatResult(
            text=choice, model=self.model_id, provider=self.name,
            input_tokens=in_tok, output_tokens=out_tok,
            cost_usd=self.cost(in_tok, out_tok), latency_ms=latency_ms,
            metadata={"raw": True},
        )
