"""Aggregate execution capacity control (v0.3.0 PRIME CONTAINMENT).

Audit finding A-03: there was no global bound on concurrent workloads, so N
simultaneous executions each received their own allowance and the *API process*
was selected by the OOM killer.

Two independent layers protect the application:

1. **Admission control** (`CapacityGovernor`) — a bounded semaphore plus a queue
   timeout. Requests beyond capacity are REJECTED with a clear error instead of
   being accepted and starving the host.
2. **Separate-process execution** — workloads run in `skyla-sup` under `unshare`,
   a different process tree from the API. A workload crash cannot take the API
   with it; the governor bounds how much can ever be in flight.

Layer 3 (kernel-arbitrated per-workload memory/CPU via cgroup v2) is **not
available unprivileged on this host** (verified: /sys/fs/cgroup is not writable
and a private cgroup2 mount is denied). That is recorded as NOT VERIFIED in
RESOURCE_CONTROL_DESIGN.md rather than pretended.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass


class CapacityExceeded(RuntimeError):
    """Too many workloads in flight; the request was refused, not queued."""


@dataclass
class CapacityStats:
    in_flight: int
    limit: int
    accepted: int
    rejected: int
    peak_in_flight: int


class CapacityGovernor:
    """Bounded concurrency for workload execution.

    Thread-safe: FastAPI runs the execute endpoint in a threadpool, so a
    `threading.Semaphore` (not an asyncio one) is the correct primitive here.
    """

    def __init__(self, limit: int | None = None, acquire_timeout_s: float = 5.0,
                 max_memory_mb: int | None = None):
        self.limit = int(limit if limit is not None
                         else os.getenv("SKYLA_MAX_CONCURRENT_EXECUTIONS", "2"))
        self.acquire_timeout_s = float(acquire_timeout_s)
        self.max_memory_mb = int(max_memory_mb
                                 if max_memory_mb is not None
                                 else os.getenv("SKYLA_EXEC_MAX_MEMORY_MB", "512"))
        self._sem = threading.BoundedSemaphore(max(1, self.limit))
        self._lock = threading.Lock()
        self._in_flight = 0
        self._accepted = 0
        self._rejected = 0
        self._peak = 0

    def acquire(self) -> None:
        if not self._sem.acquire(timeout=self.acquire_timeout_s):
            with self._lock:
                self._rejected += 1
            raise CapacityExceeded(
                f"Execution capacity exceeded ({self.limit} concurrent workloads). "
                "Retry later or raise SKYLA_MAX_CONCURRENT_EXECUTIONS.")
        with self._lock:
            self._in_flight += 1
            self._accepted += 1
            self._peak = max(self._peak, self._in_flight)

    def release(self) -> None:
        with self._lock:
            self._in_flight = max(0, self._in_flight - 1)
        try:
            self._sem.release()
        except ValueError:  # pragma: no cover - defensive
            pass

    def clamp_memory(self, requested_mb: int) -> int:
        """Never let a caller request more than the deployment allowance."""
        return max(32, min(int(requested_mb), self.max_memory_mb))

    def stats(self) -> dict:
        with self._lock:
            return {
                "in_flight": self._in_flight,
                "limit": self.limit,
                "accepted": self._accepted,
                "rejected": self._rejected,
                "peak_in_flight": self._peak,
                "max_memory_mb_per_job": self.max_memory_mb,
            }

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()
        return False


governor = CapacityGovernor()
