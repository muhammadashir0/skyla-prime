"""Generic OpenAI-compatible HTTP provider (WS6 hardened).

- Retries with exponential backoff on 429/5xx (max 3 attempts).
- Error normalization: provider errors → ProviderError with status.
- Health check via GET /models.
- Usage/cost logging via callback (wired to DB in the router).
"""
from __future__ import annotations

import asyncio
import time

import httpx
from ..egress_client import client as egress_client

from .base import ChatRequest, ChatResult, ModelProvider

PROVIDER_ENDPOINTS: dict[str, tuple[str, str]] = {
    "openai": ("https://api.openai.com/v1", "gpt-6.1-sol"),
    "deepseek": ("https://api.deepseek.com/v1", "deepseek-v4.1-flash"),
    "qwen": ("https://dashscope.aliyuncs.com/compatible-mode/v1", "qwen3.8-flash"),
    "glm": ("https://api.z.ai/api/coding/paas/v4", "glm-5.3"),
    "custom": ("", ""),
}

_RETRYABLE = {429, 500, 502, 503, 504}


class ProviderError(RuntimeError):
    def __init__(self, provider: str, status: int, message: str):
        super().__init__(f"{provider} HTTP {status}: {message}")
        self.provider = provider
        self.status = status


class OpenAICompatibleProvider(ModelProvider):
    def __init__(self, provider: str, base_url: str, api_key: str, model_id: str,
                 cost_in: float = 0.0, cost_out: float = 0.0,
                 usage_callback=None, max_retries: int = 3):
        self.name = provider
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model_id = model_id
        self.available = bool(base_url and api_key)
        self._cost_in = cost_in
        self._cost_out = cost_out
        self._usage_callback = usage_callback
        self.max_retries = max_retries

    def cost(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens / 1_000_000) * self._cost_in + (output_tokens / 1_000_000) * self._cost_out

    async def health_check(self) -> dict:
        """Verify auth + model ID via GET /models. Returns status dict."""
        if not self.available:
            return {"provider": self.name, "status": "NOT_CONFIGURED"}
        try:
            async with egress_client("model-provider", timeout=15) as client:
                resp = await client.get(f"{self.base_url}/models",
                                        headers={"Authorization": f"Bearer {self.api_key}"})
                if resp.status_code == 401:
                    return {"provider": self.name, "status": "AUTH_FAILED"}
                resp.raise_for_status()
                data = resp.json()
            ids = [m.get("id") for m in data.get("data", [])]
            return {"provider": self.name, "status": "LIVE",
                    "model_present": self.model_id in ids if ids else None,
                    "models_seen": len(ids)}
        except Exception as exc:  # noqa: BLE001
            return {"provider": self.name, "status": "UNREACHABLE", "error": str(exc)[:200]}

    async def chat(self, req: ChatRequest) -> ChatResult:
        if not self.available:
            raise RuntimeError(f"Provider '{self.name}' is not configured (missing key/endpoint)")
        payload = {
            "model": self.model_id,
            "messages": [
                {"role": "system", "content": req.system},
                {"role": "user", "content": req.user},
            ],
            "temperature": req.temperature,
            "max_tokens": req.max_tokens,
        }
        t0 = time.time()
        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                async with egress_client("model-provider", timeout=120) as client:
                    resp = await client.post(
                        f"{self.base_url}/chat/completions", json=payload,
                        headers={"Authorization": f"Bearer {self.api_key}"})
                if resp.status_code in _RETRYABLE and attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                if resp.status_code >= 400:
                    raise ProviderError(self.name, resp.status_code, resp.text[:300])
                data = resp.json()
                break
            except ProviderError:
                raise
            except Exception as exc:  # noqa: BLE001 — network/timeout
                last_exc = exc
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise
        else:
            raise last_exc or RuntimeError(f"{self.name}: retries exhausted")
        latency_ms = int((time.time() - t0) * 1000)
        try:
            choice = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"Malformed provider response from {self.name}: {exc}") from exc
        usage = data.get("usage", {})
        in_tok = int(usage.get("prompt_tokens", 0))
        out_tok = int(usage.get("completion_tokens", 0))
        cost = self.cost(in_tok, out_tok)
        if self._usage_callback:
            self._usage_callback(self.name, self.model_id, in_tok, out_tok, cost, latency_ms)
        return ChatResult(text=choice, model=self.model_id, provider=self.name,
                          input_tokens=in_tok, output_tokens=out_tok,
                          cost_usd=cost, latency_ms=latency_ms, metadata={"raw": True})
