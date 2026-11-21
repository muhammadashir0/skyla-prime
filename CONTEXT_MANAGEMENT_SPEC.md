# CONTEXT MANAGEMENT SPEC — SKYLA PRIME v0.2.0

**Status:** implemented and tested (`tests/unit/test_idempotency_context.py`, 9 tests).
**Scope:** Workstream 4 — model-specific limits, token budgets, truncation, compaction, recovery.

---

## 1. Problem statement

v0.1.0 concatenated dependency outputs into a prompt with no accounting. A multi-step task with
verbose upstream steps could either exceed the provider's window (hard API failure, wasted cost) or
silently lose the task instruction — the worst outcome, because the model then completes a
*different* task and reports success. Context handling is a correctness concern, not an
optimisation.

## 2. Design principles

1. **Instructions outrank context.** `system` + `user` (the task instruction) are reserved before any
   context is admitted. Task requirements are never dropped in favour of tool output.
2. **Truncation is always flagged.** Every truncation sets `truncated: true` and inserts a visible
   marker; nothing is silently discarded.
3. **Compact before truncating.** Older step outputs are summarised first; verbatim truncation is a
   last resort.
4. **Budgets are model-specific**, read from the model registry, not a global constant.

## 3. Token counting — stated approximation

```
estimate_tokens(text) = max(1, len(text) // 4)
```

A characters/4 heuristic. **This is an approximation, not a tokenizer.** Consequences, declared:

- For English prose it is usually within ~±15 % of a real BPE count.
- For code, CJK text, or long numeric payloads it can under- or over-estimate more.
- The 2 048-token output reservation therefore acts as a safety margin, not a precise split.

**Blocker for exact counting:** provider tokenizers (`tiktoken`, vendor SDKs) are not installed and
would add dependencies; none of the configured providers is reachable for calibration (no
credentials). The correct upgrade path is a `count_tokens(model_id, text)` adapter per provider —
recorded here as the required next step, and no document claims exact accounting.

## 4. Budget arithmetic

```
limit          = registry[model_id].context           (default 8192 if unknown)
reserve_output = 2048                                  (configurable per ContextManager)
budget         = max(512, limit - reserve_output)
remaining      = budget - estimate(system) - estimate(user)
```

- `remaining >= 0` → context is admitted up to `remaining` tokens, truncated with a marker if larger.
- `remaining < 0` → instructions alone exceed the window. `user` is truncated to
  `max(256, budget - estimate(system))` and **flagged**; `system` is never truncated. This is
  deliberately the last thing to go, and the caller can see `truncated: true` in the result.

## 5. `fit()` contract

```python
ContextManager(model_id="skyla-mock-0.1").fit(system, user, context) -> {
    "system": str, "user": str, "context": str,
    "tokens": int,      # estimated total after fitting
    "budget": int,      # usable window
    "truncated": bool   # True if ANY component was cut
}
```

`tokens <= budget` is the invariant asserted by `test_context_fit_prioritizes_instructions`, using a
100 000-character context against the 8 192-token model: the instruction survives verbatim, context
is cut and flagged.

## 6. Compaction

`compact_step_outputs(outputs, keep_last=2)`:

- The **N most recent** step outputs are kept verbatim (recent work is what the next step reasons
  about).
- Older outputs are replaced by a structured summary, one line each, first 200 characters:
  `Compacted earlier step outputs:\n- Step output 1: …\n- Step output 2: …`
- Instructions and the plan are **never** compacted.
- Verified to reduce total size while retaining the two latest outputs
  (`test_compaction_keeps_recent`).

## 7. Orchestrator integration

Every agent step in `Orchestrator.run_task_async` now:

1. gathers dependency outputs,
2. compacts them (`compact_step_outputs`),
3. fits system + instruction + compacted context into the budget,
4. passes only the fitted context to the agent,
5. logs provider usage (tokens, cost, latency) to `provider_usage`.

This means the context policy is exercised by every task the system runs — it is wired into the real
execution path, visible in `/api/metrics` (`usage.in_tok`, `usage.out_tok`).

## 8. Memory retrieval and long-running recovery

- **Memory retrieval:** `KnowledgeStore` recall is reliability-ordered and is injected as *context*
  (lowest priority), so a stale memory can never displace the current instruction.
- **Long-running task recovery:** tasks left `running` when the process dies are marked
  `interrupted` at startup (not auto-resumed). `get_task` returns plan, steps and per-step outputs,
  so a resumed task can rebuild context from stored outputs rather than from in-memory state.
  Automatic resume with re-fitted context is documented as the next step; **not implemented**.
- **Structured summaries:** compaction output is structured (numbered, bounded), so it is stable and
  diff-friendly in the audit trail.

## 9. Tests

| Test | Assertion |
|---|---|
| `test_estimate_tokens` | 400 chars → 100 tokens; empty → 1 |
| `test_truncate_flags` | oversized text cut to ≤ budget and flagged; short text untouched |
| `test_context_fit_prioritizes_instructions` | instruction preserved, context truncated, `tokens ≤ budget` |
| `test_context_fit_small` | small inputs → `truncated: False`, context intact |
| `test_compaction_keeps_recent` | last outputs verbatim, summary present, size reduced |
| `test_context_limits_per_model` | per-model limits; unknown model → 8192 default |

Interrupted-workflow context recovery is covered indirectly by the orchestrator/database tests
(`test_recover_interrupted_tasks`, `test_end_to_end_task_lifecycle`).

## 10. Limitations (declared)

1. Token counting is heuristic (§3) — no exact tokenizer.
2. Compaction summaries are extractive (truncated originals), not model-generated abstracts; a
   summarisation pass would cost tokens and add latency and is not implemented.
3. No cross-task context cache; each step re-fits from scratch.
4. Automatic resume-after-interruption is not implemented (state is preserved and inspectable).
5. `reserve_output` is per-`ContextManager`, not per-model tuned.

## 11. Decision record

- **ADR-4.1** Reserve instructions first, admit context last — protects task correctness.
- **ADR-4.2** Flag every truncation — a silent cut turns into a silently wrong answer.
- **ADR-4.3** Compact older steps rather than dropping the oldest outright — preserves the trace of
  what happened for the verification agent.
- **ADR-4.4** Heuristic token counting with a conservative output reservation, explicitly documented
  as approximate, rather than adding an uncalibrated tokenizer dependency.
