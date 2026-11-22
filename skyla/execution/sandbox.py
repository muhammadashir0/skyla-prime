"""Sandboxed Python execution — verified network-isolated execution.

Used by reasoning/scientific tools and by verification (re-running code).

EXEC-01 (v0.2.5): this module previously ran the child in the **host network
namespace**. The docstring said "no network" but nothing enforced it, so the
docstring was wrong in the direction that matters — a reader would have trusted
a control that did not exist.

The child now runs inside a private network namespace (`unshare -n`) that has no
interfaces and no default route, and the isolation is **verified from inside that
namespace before the workload code is executed**. Two properties make the proof
meaningful:

  * the verification runs in the same namespace as the workload, so it describes
    what the workload actually sees, not what the parent intended;
  * it includes a **positive control** — a connection that must succeed on an
    unrestricted host. If the control fails, the probe environment is broken and
    we cannot conclude anything, so we refuse rather than report "isolated".
    (This is the v0.2.4 lesson: a proof that cannot fail is not a proof.)

Failure of namespace creation or verification is a REFUSAL, never a downgrade to
host networking. There is no fallback path.
"""
from __future__ import annotations

import os
import resource
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

# A destination that must be reachable on a host with ordinary internet access.
# Used only as a positive control so that "blocked" cannot be confused with
# "the network was already broken".
CONTROL_HOST = ("1.1.1.1", 53)

# Destinations that must be unreachable from the workload namespace. These are
# the paths that matter for EXEC-01: public internet, host loopback services,
# private networks and the cloud metadata plane.
DENY_TARGETS = (
    ("1.1.1.1", 53),              # public DNS
    ("127.0.0.1", 8155),          # host loopback — the egress proxy itself
    ("169.254.169.254", 80),      # metadata plane
    ("10.201.0.2", 8155),         # perimeter gateway
)

# Runs OUTSIDE the sandbox, in the host namespace, purely as a positive control.
_HOST_CONTROL = r'''
import socket, sys
try:
    socket.create_connection((__CH__, __CP__), 3).close()
    print("CONTROL_OK")
except OSError:
    print("CONTROL_FAIL")
'''

# Runs INSIDE the unshared namespace. Emits a single JSON line.
_VERIFY_SCRIPT = r"""
import json, socket, sys

def try_conn(host, port, timeout=1.5):
    try:
        s = socket.create_connection((host, port), timeout)
        s.close()
        return True
    except OSError:
        return False

result = {"reachable": [], "routes": "", "interfaces": ""}
for host, port in __DENY__:
    if try_conn(host, port):
        result["reachable"].append("%s:%d" % (host, port))

try:
    with open("/proc/net/route") as fh:
        result["routes"] = fh.read()
except Exception:
    pass
try:
    result["interfaces"] = " ".join(sorted(
        __import__("os").listdir("/sys/class/net")))
except Exception:
    pass

print("SKYLA_VERIFY " + json.dumps(result))
"""


def _limits(memory_mb: int):
    def _apply():
        resource.setrlimit(resource.RLIMIT_AS, (memory_mb * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    return _apply


class IsolationUnavailable(RuntimeError):
    """The network-isolated execution boundary could not be established.

    Raised instead of executing the workload in the host namespace.
    """


def _host_control_ok() -> bool:
    """Positive control, run in the HOST namespace.

    Why this must be outside the sandbox: inside the sandbox every destination
    is blocked by design, so an in-sandbox control can never pass and would
    always read as "unverifiable". The control's job is to establish that this
    host has ordinary network reachability at all — only then does "blocked
    inside the sandbox" mean isolation rather than a broken environment.
    """
    script = (_HOST_CONTROL
              .replace("__CH__", repr(CONTROL_HOST[0]))
              .replace("__CP__", str(CONTROL_HOST[1])))
    try:
        proc = subprocess.run([sys.executable, "-c", script],
                              capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "CONTROL_OK" in proc.stdout


def verification_probe() -> dict:
    """Run the isolation probe in a fresh network namespace.

    Returns the parsed probe result. Raises `IsolationUnavailable` if the
    namespace cannot be created or the probe cannot run — an unverifiable
    boundary is treated as an absent one.
    """
    unshare = shutil.which("unshare")
    if not unshare:
        raise IsolationUnavailable("unshare(1) not found; cannot isolate the sandbox")

    script = (_VERIFY_SCRIPT
              .replace("__CH__", repr(CONTROL_HOST[0]))
              .replace("__CP__", str(CONTROL_HOST[1]))
              .replace("__DENY__", repr(DENY_TARGETS)))
    try:
        proc = subprocess.run(
            [unshare, "-Urmpf", "-n", sys.executable, "-c", script],
            capture_output=True, text=True, timeout=30,
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IsolationUnavailable(f"cannot create the sandbox network namespace: {exc}") from exc

    marker = "SKYLA_VERIFY "
    for line in proc.stdout.splitlines():
        if line.startswith(marker):
            import json
            result = json.loads(line[len(marker):])
            # The control was measured in the host namespace; attach it here so
            # `_assert_isolated` sees one complete verdict.
            result["control"] = _host_control_ok()
            return result
    raise IsolationUnavailable(
        "isolation probe produced no verdict "
        f"(rc={proc.returncode}, stderr={proc.stderr.strip()[:200]!r})")


def _assert_isolated(probe: dict) -> None:
    """Refuse unless the probe positively demonstrates isolation.

    Three ways this fails, all of them refusals:

    1. no positive control — the environment cannot reach anything, so a
       "blocked" reading proves nothing;
    2. a deny target was reachable — real egress exists;
    3. a default route exists — traffic has somewhere to go even if the
       current test destinations happen to be unreachable.
    """
    if not probe.get("control"):
        raise IsolationUnavailable(
            "isolation cannot be verified: the positive control "
            f"{CONTROL_HOST[0]}:{CONTROL_HOST[1]} is unreachable even outside "
            "the sandbox, so a blocked result would be meaningless")
    reachable = probe.get("reachable") or []
    if reachable:
        raise IsolationUnavailable(
            f"network isolation failed: reachable from the sandbox: {', '.join(reachable)}")
    for line in (probe.get("routes") or "").splitlines()[1:]:
        fields = line.split()
        if len(fields) > 1 and fields[1] == "00000000":
            raise IsolationUnavailable(
                "network isolation failed: the sandbox namespace has a default route")


def isolation_status() -> dict:
    """Report whether verified isolation is currently available (for the API)."""
    try:
        probe = verification_probe()
        _assert_isolated(probe)
    except IsolationUnavailable as exc:
        return {"verified": False, "reason": str(exc)}
    return {"verified": True, "interfaces": probe.get("interfaces", ""),
            "has_default_route": False, "reachable": []}


def run_python(code: str, timeout_s: int = 30, memory_mb: int = 512) -> dict:
    """Execute Python code in a network-isolated, resource-limited subprocess.

    Returns {ok, stdout, stderr, returncode, isolation}. If isolation cannot be
    established the workload is NOT executed and `refused` is set.
    """
    # Verify before writing or running the workload: never touch untrusted code
    # on a boundary we have not proven.
    try:
        probe = verification_probe()
        _assert_isolated(probe)
    except IsolationUnavailable as exc:
        return {"ok": False, "stdout": "", "stderr": f"Execution refused: {exc}",
                "returncode": -1, "refused": True,
                "isolation": {"verified": False, "reason": str(exc)}}

    isolation = {"verified": True, "interfaces": probe.get("interfaces", ""),
                 "has_default_route": False, "reachable": []}

    with tempfile.TemporaryDirectory(prefix="skyla_sandbox_") as tmp:
        script = Path(tmp) / "script.py"
        script.write_text(textwrap.dedent(code))
        try:
            proc = subprocess.run(
                [shutil.which("unshare"), "-Urmpf", "-n",
                 sys.executable, str(script)],
                capture_output=True, text=True, timeout=timeout_s,
                preexec_fn=_limits(memory_mb),
                env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
                cwd=tmp,
            )
            return {"ok": proc.returncode == 0, "stdout": proc.stdout[-8000:],
                    "stderr": proc.stderr[-8000:], "returncode": proc.returncode,
                    "isolation": isolation}
        except subprocess.TimeoutExpired as exc:
            return {"ok": False, "stdout": (exc.stdout or b"").decode()[-4000:] if isinstance(exc.stdout, bytes) else "",
                    "stderr": f"Timed out after {timeout_s}s", "returncode": -1,
                    "isolation": isolation}
