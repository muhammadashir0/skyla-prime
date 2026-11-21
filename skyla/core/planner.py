"""Task planner — decomposes an instruction into an ordered step graph.

Deterministic rule-based decomposition for the MVP (no model call needed),
producing steps with agent assignment and dependencies. An LLM-assisted
planner can replace this behind the same interface later.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models.router import classify_task


@dataclass
class PlanStep:
    idx: int
    title: str
    agent: str
    depends_on: list[int] = field(default_factory=list)


@dataclass
class Plan:
    kind: str
    steps: list[PlanStep]
    summary: str


def _agent_for(kind: str, title: str) -> str:
    t = title.lower()
    if any(w in t for w in ("research", "source", "evidence", "report", "search")):
        return "research"
    if any(w in t for w in ("code", "implement", "test", "software", "debug")):
        return "engineering"
    if any(w in t for w in ("email", "calendar", "meeting", "schedule", "message")):
        return "operations"
    if any(w in t for w in ("verify", "check", "review", "audit")):
        return "verification"
    return "executive"


def plan_task(instruction: str) -> Plan:
    kind = classify_task(instruction)
    instr = instruction.strip()
    steps: list[PlanStep] = []

    def add(title: str, depends: list[int] | None = None) -> int:
        idx = len(steps)
        steps.append(PlanStep(idx=idx, title=title, agent=_agent_for(kind, title),
                              depends_on=depends or []))
        return idx

    if kind == "research":
        a = add("Gather evidence and primary sources")
        b = add("Compare findings and identify conflicts", [a])
        c = add("Draft sourced report with citations", [b])
        add("Verify citations and claims", [c])
    elif kind == "coding":
        a = add("Analyze requirements and design approach")
        b = add("Implement solution", [a])
        c = add("Test and validate implementation", [b])
        add("Review changes and verify results", [c])
    elif kind == "reasoning":
        a = add("Formalize problem and assumptions")
        b = add("Work through reasoning steps", [a])
        add("Verify conclusion and check assumptions", [b])
    else:
        a = add(f"Understand and execute: {instr[:80]}")
        add("Verify result and summarize", [a])

    return Plan(kind=kind, steps=steps,
                summary=f"{kind} task decomposed into {len(steps)} steps")
