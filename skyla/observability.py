"""Structured logging + metrics with secret/PII redaction (WS7)."""
from __future__ import annotations

import json
import logging
import re
import sys
import time
import uuid

_REDACT_PATTERNS = [
    (re.compile(r"(skp_|sess_|skt_)[A-Za-z0-9_\-]{8,}"), r"\1[REDACTED]"),
    (re.compile(r"(api[_-]?key|password|secret|token)\s*[:=]\s*\S+", re.I), r"\1=[REDACTED]"),
    (re.compile(r"Bearer\s+\S+", re.I), "Bearer [REDACTED]"),
]


def redact(text: str) -> str:
    out = str(text)
    for pat, repl in _REDACT_PATTERNS:
        out = pat.sub(repl, out)
    return out


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.Formatter) -> str:
        payload = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
                   "level": record.levelname, "logger": record.name,
                   "msg": redact(record.getMessage())}
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload)


def get_logger(name: str = "skyla") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


class Metrics:
    """In-process counters (single-instance; Prometheus export is Phase-2)."""

    def __init__(self):
        self.counters: dict[str, int] = {}
        self.task_latencies_ms: list[int] = []
        self.observations: dict[str, list[int]] = {}

    def inc(self, key: str, n: int = 1) -> None:
        self.counters[key] = self.counters.get(key, 0) + n

    def observe_task(self, latency_ms: int) -> None:
        self.task_latencies_ms.append(latency_ms)

    def observe(self, key: str, value: int) -> None:
        """Record a numeric observation (e.g. provider latency) for p50/max."""
        series = self.observations.setdefault(key, [])
        series.append(value)
        if len(series) > 2000:  # bounded: in-process only, no unbounded growth
            del series[: len(series) - 2000]

    @staticmethod
    def _stats(values: list[int]) -> dict:
        v = sorted(values)
        return {"count": len(v), "p50": v[len(v) // 2] if v else 0,
                "max": v[-1] if v else 0}

    def snapshot(self) -> dict:
        return {"counters": dict(self.counters),
                "task_latency_ms": self._stats(self.task_latencies_ms),
                "observations": {k: self._stats(v)
                                 for k, v in self.observations.items()}}


metrics = Metrics()


def new_trace_id() -> str:
    return f"tr_{uuid.uuid4().hex[:12]}"
