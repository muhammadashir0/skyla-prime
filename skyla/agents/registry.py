"""Agent registry — specialist agents with explicit roles.

MVP ships: executive, research, engineering, operations, verification.
Science/mathematics/business/communication agents are registered as
specializations of the executive agent until their dedicated toolchains
(symbolic solvers, simulators) land — see docs/AUTONOMOUS_AGENT_SPECIFICATION.md.
"""
from __future__ import annotations

from ..models.base import ChatRequest, ChatResult
from ..models.router import ModelRouter
from .base import Agent


class ExecutiveAgent(Agent):
    name = "executive"
    role = "Understand objectives, execute general tasks, coordinate specialists"
    system_prompt = ("You are the SKYLA PRIME Executive Intelligence Agent. "
                     "Execute the given step precisely and return a clear, "
                     "structured result. Separate facts from assumptions.")

    async def execute(self, instruction, step_title, context, router: ModelRouter) -> ChatResult:
        return await router.chat(self._request(instruction, step_title, context))


class ResearchAgent(Agent):
    name = "research"
    role = "Gather evidence, compare sources, produce cited findings"
    system_prompt = ("You are the SKYLA PRIME Research Director. Synthesize only "
                     "from provided evidence. Cite sources explicitly. Flag "
                     "conflicting or missing evidence; never invent citations.")

    async def execute(self, instruction, step_title, context, router: ModelRouter) -> ChatResult:
        return await router.chat(self._request(instruction, step_title, context))


class EngineeringAgent(Agent):
    name = "engineering"
    role = "Design and implement software solutions with tests"
    system_prompt = ("You are the SKYLA PRIME Engineering Director. Produce "
                     "correct, minimal, tested code. State assumptions and "
                     "how the solution was validated.")

    async def execute(self, instruction, step_title, context, router: ModelRouter) -> ChatResult:
        return await router.chat(self._request(instruction, step_title, context))


class OperationsAgent(Agent):
    name = "operations"
    role = "Coordinate email, calendar, meetings and recurring operations"
    system_prompt = ("You are the SKYLA PRIME Personal Operations Manager. "
                     "Prepare precise, auditable operational outputs. Never "
                     "claim an external action completed without provider "
                     "confirmation.")

    async def execute(self, instruction, step_title, context, router: ModelRouter) -> ChatResult:
        return await router.chat(self._request(instruction, step_title, context))


class VerificationAgent(Agent):
    name = "verification"
    role = "Independent review: correctness, evidence, completeness, safety"
    system_prompt = ("You are the SKYLA PRIME Independent Verification Agent. "
                     "You did NOT produce the work under review. Check it "
                     "critically: unsupported claims, missing evidence, "
                     "incomplete steps, unsafe actions. End your response "
                     "with exactly one line: VERDICT: PASS or VERDICT: FAIL "
                     "followed by brief reasons.")

    async def execute(self, instruction, step_title, context, router: ModelRouter) -> ChatResult:
        return await router.chat(self._request(instruction, step_title, context))


_AGENTS: dict[str, Agent] = {
    "executive": ExecutiveAgent(),
    "research": ResearchAgent(),
    "engineering": EngineeringAgent(),
    "operations": OperationsAgent(),
    "verification": VerificationAgent(),
}


def get_agent(name: str) -> Agent:
    return _AGENTS.get(name, _AGENTS["executive"])


def list_agents() -> list[dict]:
    return [{"name": a.name, "role": a.role} for a in _AGENTS.values()]
