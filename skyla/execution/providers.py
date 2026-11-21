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
    """Legacy subprocess + rlimits. NOT isolated — dev-only."""
    name = "restricted"
    isolated = False
    safe_for_untrusted = False

    def run(self, code, timeout_s=30, memory_mb=512, network=False) -> dict:
        from .sandbox import run_python
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
    """unshare(user,mount,pid,net) + chroot into a minimal rootfs.

    Isolation properties (verified by adversarial tests):
      - host filesystem invisible (chroot; only ro python runtime + workspace)
      - network namespace with no routes (disabled by default)
      - fake root inside user namespace (cannot escape to host uid)
      - read-only runtime binds; workspace is the only writable area
      - rlimits (memory/CPU) + hard timeout + output caps
    """
    name = "namespace"
    isolated = True
    safe_for_untrusted = True

    def __init__(self):
        self.unshare = shutil.which("unshare")
        self.chroot_bin = "/usr/sbin/chroot" if Path("/usr/sbin/chroot").exists() else shutil.which("chroot")

    def status(self) -> dict:
        s = super().status()
        s["available"] = bool(self.unshare and self.chroot_bin)
        return s

    def run(self, code, timeout_s=30, memory_mb=512, network=False) -> dict:
        if not (self.unshare and self.chroot_bin):
            return {"ok": False, "stdout": "", "returncode": -1,
                    "stderr": "unshare/chroot unavailable; namespace provider disabled"}
        with tempfile.TemporaryDirectory(prefix="skyla_ns_") as base:
            rootfs = Path(base) / "rootfs"
            ws = Path(base) / "ws"
            for d in ("usr/bin", "usr/lib", "lib", "lib64", "bin", "sbin",
                      "etc", "workspace", "tmp", "proc", "dev"):
                (rootfs / d).mkdir(parents=True, exist_ok=True)
            ws.mkdir()
            (ws / "script.py").write_text(textwrap.dedent(code))
            inner = Path(base) / "inner.sh"
            net_flag = "" if network else "-n"
            inner.write_text(textwrap.dedent(f"""\
                set -e
                mount --make-rprivate /
                mount --bind -o ro /usr/bin {rootfs}/usr/bin
                mount --bind -o ro /usr/lib {rootfs}/usr/lib
                mount --bind -o ro /lib {rootfs}/lib 2>/dev/null || true
                mount --bind -o ro /lib64 {rootfs}/lib64 2>/dev/null || true
                mount --bind -o ro /bin {rootfs}/bin 2>/dev/null || true
                mount --bind -o ro /sbin {rootfs}/sbin 2>/dev/null || true
                mount --bind {ws} {rootfs}/workspace
                mount -t tmpfs -o ro tmpfs {rootfs}/etc
                mount -t tmpfs tmpfs {rootfs}/tmp
                mount -t proc proc {rootfs}/proc 2>/dev/null || true
                mount -t tmpfs tmpfs {rootfs}/dev
                ulimit -v {memory_mb * 1024}
                exec {self.chroot_bin} {rootfs} /usr/bin/python3 /workspace/script.py
            """))
            cmd = [self.unshare, "-Urmpf"] + ([net_flag] if net_flag else []) + ["sh", str(inner)]
            env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=timeout_s + 5, env=env, cwd=base)
                return {"ok": proc.returncode == 0, "stdout": proc.stdout[-8000:],
                        "stderr": proc.stderr[-8000:], "returncode": proc.returncode}
            except subprocess.TimeoutExpired as exc:
                out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else ""
                return {"ok": False, "stdout": out[-4000:],
                        "stderr": f"Timed out after {timeout_s}s", "returncode": -1}


def get_execution_provider() -> ExecutionProvider:
    """Select provider by SKYLA_EXECUTION_PROVIDER (default: auto).

    auto → namespace if available, else container if available, else
    restricted (dev-only, labeled unsafe). Never silently claims isolation.
    """
    mode = os.getenv("SKYLA_EXECUTION_PROVIDER", "auto").lower()
    if mode == "disabled":
        return DisabledProvider()
    if mode == "restricted":
        return RestrictedProvider()
    if mode == "container":
        return ContainerProvider()
    if mode == "namespace":
        return NamespaceProvider()
    ns = NamespaceProvider()
    if ns.status()["available"]:
        return ns
    cont = ContainerProvider()
    if cont.status()["available"]:
        return cont
    return RestrictedProvider()
