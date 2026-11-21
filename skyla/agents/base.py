"""Agent interface. Agents have explicit roles, permissions and budgets;
they never perform external side-effects directly — side-effects go through
connectors with autonomy checks."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..models.base import ChatRequest, ChatResult
from ..models.router import ModelRouter


class Agent(ABC):
    name: str = "agent"
    role: str = ""
    system_prompt: str = ""

    @abstractmethod
    async def execute(self, instruction: str, step_title: str, context: str,
                      router: ModelRouter) -> ChatResult:
        raise NotImplementedError

    def _request(self, instruction: str, step_title: str, context: str) -> ChatRequest:
        user = f"Original instruction: {instruction}\n\nCurrent step: {step_title}"
        if context:
            user += f"\n\nContext from previous steps:\n{context[:8000]}"
        return ChatRequest(system=self.system_prompt, user=user)
