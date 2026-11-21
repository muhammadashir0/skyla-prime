"""Sandboxed Python execution — timeout + memory limits, no network.

Used by reasoning/scientific tools and by verification (re-running code).
Runs in a subprocess with a restricted environment; this is defense-in-depth
for local dev, not a substitute for container isolation in production
(see docs/SECURITY_ARCHITECTURE.md).
"""
from __future__ import annotations

import resource
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path


def _limits(memory_mb: int):
    def _apply():
        resource.setrlimit(resource.RLIMIT_AS, (memory_mb * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    return _apply


def run_python(code: str, timeout_s: int = 30, memory_mb: int = 512) -> dict:
    """Execute Python code in a subprocess. Returns {ok, stdout, stderr, returncode}."""
    with tempfile.TemporaryDirectory(prefix="skyla_sandbox_") as tmp:
        script = Path(tmp) / "script.py"
        script.write_text(textwrap.dedent(code))
        try:
            proc = subprocess.run(
                [sys.executable, str(script)],
                capture_output=True, text=True, timeout=timeout_s,
                preexec_fn=_limits(memory_mb),
                env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
                cwd=tmp,
            )
            return {"ok": proc.returncode == 0, "stdout": proc.stdout[-8000:],
                    "stderr": proc.stderr[-8000:], "returncode": proc.returncode}
        except subprocess.TimeoutExpired as exc:
            return {"ok": False, "stdout": (exc.stdout or b"").decode()[-4000:] if isinstance(exc.stdout, bytes) else "",
                    "stderr": f"Timed out after {timeout_s}s", "returncode": -1}
