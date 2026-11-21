"""Model provider interface. Every provider (commercial API, open-weight
endpoint, local mock) implements this contract so the router can swap
providers without rewriting the platform."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ChatResult:
    text: str
    model: str
    provider: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: int = 0
    metadata: dict = field(default_factory=dict)


@dataclass
class ChatRequest:
    system: str
    user: str
    temperature: float = 0.3
    max_tokens: int = 2048
    task_kind: str = "general"


class ModelProvider(ABC):
    name: str = "base"
    model_id: str = "unknown"
    available: bool = False

    @abstractmethod
    async def chat(self, req: ChatRequest) -> ChatResult:
        raise NotImplementedError

    def cost(self, input_tokens: int, output_tokens: int) -> float:
        return 0.0
