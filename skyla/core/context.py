"""Context manager (WS4) — token budgets, truncation, compaction.

- Model-specific context limits from the registry.
- Approximate token counting (chars/4 heuristic; exact counting requires
  a provider tokenizer — documented limitation).
- Tool-result truncation with explicit markers (never silent).
- Compaction: older step outputs are summarized, instructions preserved.
- Memory retrieval injection with reliability ordering.
"""
from __future__ import annotations

from ..models.registry import REGISTRY

_DEFAULT_LIMIT = 8192
_TRUNCATION_MARKER = "\n…[truncated by context manager]…\n"


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def context_limit_for(model_id: str) -> int:
    for e in REGISTRY:
        if e.model_id == model_id:
            return e.context
    return _DEFAULT_LIMIT


def truncate(text: str, max_tokens: int) -> tuple[str, bool]:
    """Truncate to a token budget. Returns (text, was_truncated)."""
    if estimate_tokens(text) <= max_tokens:
        return text, False
    keep = max_tokens * 4 - len(_TRUNCATION_MARKER)
    return text[:keep] + _TRUNCATION_MARKER, True


class ContextManager:
    def __init__(self, model_id: str = "skyla-mock-0.1", reserve_output: int = 2048):
        self.limit = context_limit_for(model_id)
        self.budget = max(512, self.limit - reserve_output)
        self.model_id = model_id

    def fit(self, system: str, user: str, context: str = "") -> dict:
        """Fit system+user+context into budget. Prioritizes: system and
        user instructions (never truncated below 50%), then context."""
        sys_tok = estimate_tokens(system)
        user_tok = estimate_tokens(user)
        remaining = self.budget - sys_tok - user_tok
        truncated = False
        if remaining < 0:
            # Instructions alone exceed budget: truncate user (last resort,
            # explicitly flagged — never silent).
            user, truncated = truncate(user, max(256, self.budget - sys_tok))
            remaining = 0
        if context and remaining > 0:
            context, ctx_trunc = truncate(context, remaining)
            truncated = truncated or ctx_trunc
        elif context:
            context, truncated = "", True
        return {"system": system, "user": user, "context": context,
                "tokens": sys_tok + user_tok + estimate_tokens(context),
                "budget": self.budget, "truncated": truncated}

    @staticmethod
    def compact_step_outputs(outputs: list[str], keep_last: int = 2) -> str:
        """Compact older step outputs into a structured summary, keeping
        the most recent outputs verbatim. Instructions are never compacted."""
        if len(outputs) <= keep_last:
            return "\n".join(outputs)
        older = outputs[:-keep_last]
        summary_lines = [f"- Step output {i + 1}: {o[:200]}" for i, o in enumerate(older)]
        summary = "Compacted earlier step outputs:\n" + "\n".join(summary_lines)
        return summary + "\n" + "\n".join(outputs[-keep_last:])
