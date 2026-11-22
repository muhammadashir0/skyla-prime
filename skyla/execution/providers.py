"""Pluggable execution providers (WS1).

Providers:
  namespace  — unshare(user,mount,pid,net) + chroot minimal rootfs.
               Genuine OS-level isolation, unprivileged. DEFAULT when available.
  container  — Docker rootless container (auto-detected; DISABLED if absent).
  restricted — legacy subprocess with rlimits. NOT a security boundary;
               dev-only, explicitly labeled unsafe.
  disabled   — execution refused.

The active provider is reported honestly in every API response.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from abc import ABC, abstractmethod
from pathlib import Path

from ..config import get_settings


class ExecutionProvider(ABC):
    name: str = "base"
    isolated: bool = False
    safe_for_untrusted: bool = False

    @abstractmethod
    def run(self, code: str, timeout_s: int = 30, memory_mb: int = 512,
            network: bool = False) -> dict:
        raise NotImplementedError

    def status(self) -> dict:
        return {"provider": self.name, "isolated": self.isolated,
                "safe_for_untrusted": self.safe_for_untrusted}


class DisabledProvider(ExecutionProvider):
    name = "disabled"

    def run(self, code, timeout_s=30, memory_mb=512, network=False) -> dict:
        return {"ok": False, "stdout": "", "stderr": "Execution disabled by configuration",
                "returncode": -1}


class RestrictedProvider(ExecutionProvider):
    """Local subprocess with verified network isolation (EXEC-01, v0.2.5).

    History: this provider used to run the child in the host network namespace
    and was correctly labelled "NOT isolated". As of v0.2.5 the child runs in a
    private netns whose isolation is proven before any workload code executes,
    so the network boundary is now real. It remains weaker than the `namespace`
    provider — no seccomp, no Landlock, no PID-namespace termination — so it is
    still not `safe_for_untrusted`, and that distinction is reported rather than
    blurred.
    """
    name = "restricted"

    @property
    def isolated(self) -> bool:      # type: ignore[override]
        # True only when isolation is currently verified on this host.
        from .sandbox import isolation_status
        return bool(isolation_status().get("verified"))

    @property
    def safe_for_untrusted(self) -> bool:   # type: ignore[override]
        # Network confinement does not make this a full security boundary:
        # no seccomp/Landlock/PID-namespace kill. Refuse to imply otherwise.
        return False

    def status(self) -> dict:
        from .sandbox import isolation_status
        iso = isolation_status()
        return {"provider": self.name, "isolated": bool(iso.get("verified")),
                "safe_for_untrusted": False,
                "network_isolation": iso,
                "weaker_than": "namespace provider (no seccomp/Landlock/pid-kill)"}

    def run(self, code, timeout_s=30, memory_mb=512, network=False) -> dict:
        from .sandbox import run_python
        if network:
            # There is no authorised egress path from this provider. Refuse
            # rather than silently granting host networking to untrusted code.
            return {"ok": False, "stdout": "", "returncode": -1, "refused": True,
                    "stderr": "Network-enabled execution is not supported by the "
                              "local provider (deny by default; no authorised "
                              "egress gateway path is wired to local execution)."}
        return run_python(code, timeout_s, memory_mb)


class ContainerProvider(ExecutionProvider):
    """Docker-based isolation (auto-disabled when Docker is unavailable)."""
    name = "container"
    isolated = True
    safe_for_untrusted = True

    def __init__(self):
        self.docker = shutil.which("docker")

    def status(self) -> dict:
        s = super().status()
        s["available"] = bool(self.docker)
        return s

    def run(self, code, timeout_s=30, memory_mb=512, network=False) -> dict:
        if not self.docker:
            return {"ok": False, "stdout": "", "returncode": -1,
                    "stderr": "Docker not available; container provider disabled"}
        with tempfile.TemporaryDirectory(prefix="skyla_exec_") as tmp:
            Path(tmp, "script.py").write_text(textwrap.dedent(code))
            cmd = [self.docker, "run", "--rm", "--network",
                   "host" if network else "none",
                   "--memory", f"{memory_mb}m", "--cpus", "1",
                   "--pids-limit", "64", "--read-only",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                   "-v", f"{tmp}:/workspace:rw", "-w", "/workspace",
                   "python:3.11-slim", "python3", "script.py"]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 10)
                return {"ok": proc.returncode == 0, "stdout": proc.stdout[-8000:],
                        "stderr": proc.stderr[-8000:], "returncode": proc.returncode}
            except subprocess.TimeoutExpired:
                return {"ok": False, "stdout": "", "stderr": f"Timed out after {timeout_s}s",
                        "returncode": -1}


class NamespaceProvider(ExecutionProvider):
    """Contained execution: user/mount/PID/net namespaces + skyla-sup supervisor.

    All controls live in the compiled supervisor (see EXECUTION_HOST_SECURITY.md):
    capabilities dropped and verified zero, PR_SET_NO_NEW_PRIVS, seccomp
    allowlist, Landlock write-confinement, rlimits, PID-namespace termination.

    If the supervisor cannot be built or a mandatory control fails, execution is
    REFUSED. There is no silent degradation to an unsafe provider.
    """
    name = "namespace"
    isolated = True
    safe_for_untrusted = True

    def __init__(self):
        from . import workload
        self._wl = workload

    def status(self) -> dict:
        from .workload import containment_status, SupervisorUnavailable
        s = super().status()
        try:
            c = containment_status()
            s["available"] = bool(c.get("supervisor"))
            s["controls"] = {
                "capability_drop": "verified-zero",
                "no_new_privs": True,
                "seccomp": bool(c.get("seccomp")),
                "landlock_abi": c.get("landlock_abi", 0),
                "cgroup_v2": bool(c.get("cgroup_v2")),
                "user_namespace": c.get("userns"),
                "network_namespace": c.get("netns"),
                "termination": "pid-namespace-kill",
            }
        except Exception as exc:  # SupervisorUnavailable or build failure
            s["available"] = False
            s["isolated"] = False
            s["safe_for_untrusted"] = False
            s["error"] = str(exc)
        return s

    def run(self, code, timeout_s=30, memory_mb=512, network=False,
            task_id: str = "") -> dict:
        from .workload import SupervisorUnavailable, run_isolated
        if network:
            # Approved-network execution is not implemented: refuse rather than
            # silently granting host networking to untrusted code.
            return {"ok": False, "stdout": "", "returncode": -1,
                    "stderr": "Network-enabled execution is not supported by the "
                              "contained provider (deny by default)."}
        # v0.2.2: wrap the run in an OS-enforced cgroup when available. The
        # supervisor's rlimits remain the per-process backstop; the cgroup adds
        # the aggregate ceiling and cgroup.kill tree termination. If cgroups are
        # unavailable we still run (rlimits + namespaces are verified), but we say
        # so in `controls` rather than implying kernel-level aggregate limits.
        cg_status = {"cgroup_v2": False, "placement": False,
                     "reason": "not attempted"}
        job = None
        try:
            from .cgroups import (AggregateCapacityExceeded, CgroupUnavailable,
                                  JobLimits, cgroup_governor)
            cg_status = cgroup_governor.status()
            if cg_status.get("cgroup_v2") and cg_status.get("placement"):
                job = cgroup_governor.create_job(JobLimits(
                    memory_mb=int(memory_mb),
                    pids=24,
                    cpu_quota_us=max(10_000, int(timeout_s) * 100_000 // 10),
                    timeout_s=float(timeout_s)))
            else:
                cg_status["reason"] = cg_status.get("reason") or cg_status.get("placement_reason")
        except AggregateCapacityExceeded as exc:
            return {"ok": False, "stdout": "", "returncode": -1,
                    "stderr": f"Execution refused: aggregate capacity ({exc})",
                    "refused": True, "capacity_exceeded": True}
        except CgroupUnavailable as exc:
            cg_status = {"cgroup_v2": False, "placement": False, "reason": str(exc)}
        except Exception as exc:                      # noqa: BLE001
            cg_status = {"cgroup_v2": False, "placement": False, "reason": str(exc)}

        try:
            r = run_isolated(
                code,
                cpu_s=max(1, int(timeout_s)),
                memory_mb=int(memory_mb),
                fsize_mb=32,
                nproc=24,
                timeout_s=int(timeout_s),
                sandbox_uid=65534,
                sandbox_gid=65534,
                cgroup=job,
            )
        except SupervisorUnavailable as exc:
            # FAIL CLOSED. No fallback provider, ever.
            return {"ok": False, "stdout": "", "returncode": -1,
                    "stderr": f"Execution refused: containment unavailable ({exc})",
                    "refused": True}
        controls = dict(r.controls)
        controls["cgroup"] = {
            "enabled": job is not None,
            "cgroup_v2": bool(cg_status.get("cgroup_v2")),
            "placement": bool(cg_status.get("placement")),
            "reason": cg_status.get("reason", ""),
        }
        if job is not None:
            # Sample BEFORE reading the fields: peak counters only reflect the
            # run once they have been read from the kernel after it finished.
            job.sample()
            controls["cgroup"].update({
                "memory_peak_mb": job.peak_memory_mb,
                "pids_peak": job.pids_peak,
                "oom_kills": job.oom_kills,
                "exceeded": job.exceeded(),
            })
            job.kill()
            job.destroy()
        return {"ok": r.ok, "stdout": r.stdout, "stderr": r.stderr,
                "returncode": r.returncode, "timed_out": r.timed_out,
                "terminated": r.terminated, "processes_killed": r.processes_killed,
                "controls": controls}


def get_execution_provider() -> ExecutionProvider:
    """Select an execution provider.

    Fail-closed policy (v0.3.0): `auto` NEVER falls back to the unsafe
    RestrictedProvider. If no contained runtime is available, the DisabledProvider
    is returned and arbitrary execution is refused outright.
    """
    mode = os.getenv("SKYLA_EXECUTION_PROVIDER", "auto").lower()
    if mode == "disabled":
        return DisabledProvider()
    if mode == "restricted":
        # Explicit opt-in only, for a developer who has read the warning.
        if os.getenv("SKYLA_ALLOW_UNSAFE_EXECUTION") == "1":
            return RestrictedProvider()
        return DisabledProvider()
    if mode == "container":
        cont = ContainerProvider()
        return cont if cont.status()["available"] else DisabledProvider()
    if mode == "namespace":
        return NamespaceProvider()
    ns = NamespaceProvider()
    if ns.status().get("available"):
        return ns
    cont = ContainerProvider()
    if cont.status()["available"]:
        return cont
    return DisabledProvider()   # NOT RestrictedProvider
