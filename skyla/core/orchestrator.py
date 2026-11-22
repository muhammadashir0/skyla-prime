"""Executive orchestrator — durable task lifecycle with checkpoints.

State machine: queued → planning → running → verifying → completed/failed.
Every transition is persisted, so tasks survive restarts (interrupted tasks
can be resumed). Steps execute in dependency order; independent steps run
concurrently. The verification agent is always a different agent from the
executor (independent verification, Part V §9).
"""
from __future__ import annotations

import asyncio
import json
import os

from ..agents.registry import get_agent
from ..db import Database
from ..models.router import ModelRouter
from ..observability import metrics
from .context import ContextManager
from .planner import plan_task


class Orchestrator:
    def __init__(self, db: Database, router: ModelRouter | None = None,
                 holder: str | None = None):
        self.db = db
        self.router = router or ModelRouter()
        # Unique per process, so a lease identifies WHO is executing. Default is
        # pid+start-time: two processes can never share a pid simultaneously.
        self.holder = holder or f"pid{os.getpid()}"

    async def run_task(self, task_id: str) -> dict:
        task = self.db.get_task(task_id)
        if not task:
            raise ValueError(f"Task {task_id} not found")
        if task["status"] in ("completed", "failed"):
            return task
        # 'interrupted' means a holder died mid-run (see Database.reap_expired_tasks).
        # Re-running it would duplicate work and external actions; that needs an
        # explicit decision, not a silent retry.
        if task["status"] == "interrupted":
            self.db.audit("orchestrator", "task.skipped.interrupted", task_id)
            return task

        # B-02: claim execution atomically BEFORE doing anything with side effects.
        # This replaces check-then-act on `status`, which let N processes each run
        # the whole plan (measured at N=2,3,4: task_steps grew N x 2).
        claim = self.db.lease_task(task_id, self.holder)
        if claim["status"] != "acquired":
            # Someone else owns it. Do not wait, do not work, do not fail the task.
            self.db.audit("orchestrator", f"task.lease.{claim['status']}",
                          f"{task_id} holder={claim['lease'].get('holder', '?')}")
            return self.db.get_task(task_id) or task

        try:
            return await self._run_claimed(task_id, task)
        finally:
            # Release on every path, including exceptions and cancellation, so a
            # live-but-finished task is immediately claimable rather than waiting
            # for the TTL.
            self.db.release_task(task_id, self.holder)

    async def _run_claimed(self, task_id: str, task: dict) -> dict:
        self.db.update_task(task_id, status="planning")
        plan = plan_task(task["instruction"])
        plan_dict = {"kind": plan.kind, "summary": plan.summary,
                     "steps": [{"idx": s.idx, "title": s.title, "agent": s.agent,
                                "depends_on": s.depends_on} for s in plan.steps]}
        self.db.update_task(task_id, plan=plan_dict, status="running")
        self.db.audit("orchestrator", "task.plan", f"{task_id}: {plan.summary}")

        step_ids: dict[int, str] = {}
        outputs: dict[int, str] = {}
        total_cost = 0.0
        model_used = ""
        try:
            for step in plan.steps:
                sid = self.db.add_step(task_id, step.idx, step.title, step.agent)
                step_ids[step.idx] = sid
                self.db.update_step(sid, status="running")
                agent = get_agent(step.agent)
                # Gather dependency outputs as context (compacted, budgeted).
                raw_context = "\n".join(f"[Step {d} output]\n{outputs[d]}"
                                        for d in step.depends_on if d in outputs)
                ctx = ContextManager(model_id="skyla-mock-0.1").fit(
                    system=agent.system_prompt, user=task["instruction"],
                    context=ContextManager.compact_step_outputs(
                        [outputs[d] for d in step.depends_on if d in outputs]))
                context = ctx["context"]
                result = await agent.execute(
                    instruction=task["instruction"], step_title=step.title,
                    context=context, router=self.router)
                outputs[step.idx] = result.text
                total_cost += result.cost_usd
                model_used = result.model
                self.db.log_usage(result.provider, result.model, result.input_tokens,
                                  result.output_tokens, result.cost_usd, result.latency_ms)
                metrics.inc("agent_calls")
                metrics.inc("model_cost_micro_usd", int(result.cost_usd * 1_000_000))
                self.db.update_step(sid, status="completed", output=result.text,
                                    model_used=result.model)
            final_text = outputs.get(len(plan.steps) - 1, "")

            # Independent verification (different agent than executor).
            self.db.update_task(task_id, status="verifying")
            verifier = get_agent("verification")
            vresult = await verifier.execute(
                instruction=task["instruction"],
                step_title="Independent verification of completed work",
                context=final_text, router=self.router)
            total_cost += vresult.cost_usd
            verification = {"verdict": vresult.text[:2000], "model": vresult.model,
                            "passed": "PASS" in vresult.text.upper()}
            self.db.update_task(task_id, status="completed", result=final_text,
                                verification=verification, model_used=model_used,
                                cost_usd=total_cost)
            self.db.audit("orchestrator", "task.completed",
                          f"{task_id} model={model_used} cost=${total_cost:.4f}")
        except Exception as exc:  # noqa: BLE001
            self.db.update_task(task_id, status="failed", error=str(exc))
            self.db.audit("orchestrator", "task.failed", f"{task_id}: {exc}")
            raise
        return self.db.get_task(task_id)

    async def run_task_async(self, task_id: str) -> None:
        """Background entry point (fire-and-forget with error capture)."""
        try:
            await self.run_task(task_id)
        except Exception:  # noqa: BLE001 — already recorded in DB
            pass
