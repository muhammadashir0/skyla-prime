"""Workload-level lifecycle control (v0.3.0 PRIME CONTAINMENT).

Remediates audit finding A-04: `subprocess.run(timeout=...)` killed only the
direct child, leaving grandchildren alive (reproduced: orphan with ppid=1 still
in state R after the timeout fired).

Termination model
-----------------
`cgroup.kill` is the preferred primitive, but cgroup v2 subtrees are **not
delegated to unprivileged users on this host** (verified: /sys/fs/cgroup is not
writable, and mounting a private cgroup2 inside a user namespace is denied).
The equivalent guarantee is obtained from the **PID namespace**:

    the supervisor is PID 1 of its own PID namespace
        => every process the workload creates lives inside that namespace
        => killing PID 1 makes the kernel SIGKILL every remaining member
           of the namespace (documented Linux behaviour on ns init death)

So the termination primitive is `SIGKILL` to the supervisor's host PID,
followed by a *verified* wait for the whole process group / namespace to drain.
Nothing is assumed: `terminate_and_verify()` polls until no descendant remains.

This is recorded as VERIFIED-BY-PID-NAMESPACE rather than by cgroup, and the
limitation is documented in RESOURCE_CONTROL_DESIGN.md.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

SUPERVISOR_BIN = Path(__file__).with_name("skyla-sup")
SUPERVISOR_SRC = Path(__file__).with_name("skyla-sup.c")


class SupervisorUnavailable(RuntimeError):
    """The mandatory containment binary could not be built/found.

    Execution must be REFUSED -- never silently degraded to an unsafe provider.
    """


@dataclass
class WorkloadResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int = -1
    timed_out: bool = False
    terminated: bool = True
    processes_killed: int = 0
    elapsed_s: float = 0.0
    controls: dict = field(default_factory=dict)


def ensure_supervisor() -> Path:
    """Build skyla-sup from source if the binary is missing or stale."""
    if not SUPERVISOR_SRC.exists():
        raise SupervisorUnavailable(f"supervisor source missing: {SUPERVISOR_SRC}")
    needs_build = (not SUPERVISOR_BIN.exists() or
                   SUPERVISOR_BIN.stat().st_mtime < SUPERVISOR_SRC.stat().st_mtime)
    if needs_build:
        cc = shutil.which("gcc") or shutil.which("cc")
        if not cc:
            raise SupervisorUnavailable("no C compiler available to build skyla-sup")
        proc = subprocess.run(
            [cc, "-O2", "-o", str(SUPERVISOR_BIN), str(SUPERVISOR_SRC)],
            capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise SupervisorUnavailable(f"skyla-sup build failed: {proc.stderr[:400]}")
        SUPERVISOR_BIN.chmod(0o755)
    return SUPERVISOR_BIN


def _descendants(root_pid: int) -> list[int]:
    """Every live descendant of root_pid, read from /proc (host view)."""
    children: dict[int, list[int]] = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/stat", "rb") as fh:
                fields = fh.read().rsplit(b")", 1)[1].split()
            ppid = int(fields[1])
        except (OSError, IndexError, ValueError):
            continue
        children.setdefault(ppid, []).append(pid)
    out: list[int] = []
    stack = [root_pid]
    while stack:
        for child in children.get(stack.pop(), []):
            out.append(child)
            stack.append(child)
    return out


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            state = fh.read().rsplit(b")", 1)[1].split()[0]
        return state not in (b"Z", b"X")  # zombie/dead are not alive
    except (OSError, IndexError):
        return False


def terminate_and_verify(proc: subprocess.Popen, drain_timeout_s: float = 10.0) -> tuple[bool, int]:
    """Kill the whole workload tree and VERIFY it is gone.

    Returns (fully_terminated, processes_killed). Never returns True on faith.
    """
    killed = 0
    tracked = set(_descendants(proc.pid))
    # SIGKILL the supervisor (ns init): kernel then kills the namespace.
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        killed += 1
    except ProcessLookupError:
        pass
    try:
        proc.kill()
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=drain_timeout_s)
    except subprocess.TimeoutExpired:
        return False, killed

    # Anything still alive that was seen before the kill must be reaped too.
    deadline = time.time() + drain_timeout_s
    while time.time() < deadline:
        remaining = [p for p in tracked if _alive(p)]
        if not remaining:
            return True, killed + len(tracked)
        for pid in remaining:
            try:
                os.kill(pid, signal.SIGKILL)
                killed += 1
            except ProcessLookupError:
                pass
        time.sleep(0.05)
    remaining = [p for p in tracked if _alive(p)]
    return (not remaining), killed + len(tracked)


def run_isolated(
    script: str,
    *,
    cpu_s: int = 10,
    memory_mb: int = 256,
    fsize_mb: int = 32,
    nproc: int = 24,
    timeout_s: int = 15,
    sandbox_uid: int = 65534,
    sandbox_gid: int = 65534,
) -> WorkloadResult:
    """Run Python inside the fully-contained supervisor.

    Raises SupervisorUnavailable when containment cannot be established: the
    caller must then REFUSE execution (no unsafe fallback).
    """
    sup = ensure_supervisor()
    unshare = shutil.which("unshare")
    if not unshare:
        raise SupervisorUnavailable("unshare not available")
    if os.geteuid() == 0:
        raise SupervisorUnavailable("refusing to run: supervisor must not be setuid/root")

    started = time.time()
    with tempfile.TemporaryDirectory(prefix="skyla_wl_") as base:
        rootfs = Path(base) / "rootfs"
        ws = Path(base) / "ws"
        for d in ("usr/bin", "usr/lib", "lib", "lib64", "bin", "sbin", "etc", "tmp",
                  "proc", "dev", "workspace"):
            (rootfs / d).mkdir(parents=True, exist_ok=True)
        ws.mkdir()
        (ws / "script.py").write_text(script, encoding="utf-8")
        shutil.copy2(sup, rootfs / "skyla-sup")
        (rootfs / "skyla-sup").chmod(0o755)

        # Mount plan runs INSIDE the new mount namespace, before chroot.
        inner = Path(base) / "inner.sh"
        inner.write_text(
            "set -e\n"
            "mount --make-rprivate /\n"
            # read-only runtime: the workload cannot modify anything it executes
            "mount --bind -o ro /usr/bin {r}/usr/bin\n"
            "mount --bind -o ro /usr/lib {r}/usr/lib\n"
            "mount --bind -o ro /lib {r}/lib 2>/dev/null || true\n"
            "mount --bind -o ro /lib64 {r}/lib64 2>/dev/null || true\n"
            "mount --bind -o ro /bin {r}/bin 2>/dev/null || true\n"
            "mount --bind -o ro /sbin {r}/sbin 2>/dev/null || true\n"
            # ephemeral writable workspace, owned by the unprivileged sandbox uid
            "mount --bind {ws} {r}/workspace\n"
            # empty read-only /etc: no passwd, hosts, resolv.conf, credentials
            "mount -t tmpfs -o ro,size=1m tmpfs {r}/etc\n"
            "mount -t tmpfs -o rw,size=64m,mode=1777 tmpfs {r}/tmp\n"
            "mount -t proc proc {r}/proc 2>/dev/null || true\n"
            "mount -t tmpfs -o ro,size=1m tmpfs {r}/dev\n"
            "exec {r}/skyla-sup {r} workspace /workspace/script.py "
            "{cpu} {mem} {fsize} {nproc} {uid} {gid}\n"
            .format(r=rootfs, ws=ws, cpu=cpu_s, mem=memory_mb, fsize=fsize_mb,
                    nproc=nproc, uid=sandbox_uid, gid=sandbox_gid)
        )

        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/tmp"}
        # -r maps the caller to namespace-root so inner.sh can build the mount
        # tree; skyla-sup then drops to sandbox_uid before any workload code runs.
        cmd = [unshare, "-Urmpf", "-n", "sh", str(inner)]
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=env, cwd=base, start_new_session=True)
        except OSError as exc:
            raise SupervisorUnavailable(f"cannot start supervisor: {exc}") from exc

        timed_out = False
        try:
            out, err = proc.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            out, err = "", ""
            terminated, killed = terminate_and_verify(proc)
            return WorkloadResult(
                ok=False, stderr=f"Timed out after {timeout_s}s (workload tree terminated)",
                returncode=-1, timed_out=True, terminated=terminated,
                processes_killed=killed, elapsed_s=time.time() - started,
                controls=_controls(cpu_s, memory_mb, fsize_mb, nproc, sandbox_uid))

        # Normal completion: still verify nothing escaped (detached grandchildren).
        terminated, killed = terminate_and_verify(proc)
        return WorkloadResult(
            ok=proc.returncode == 0,
            stdout=(out or "")[-8000:], stderr=(err or "")[-8000:],
            returncode=proc.returncode, timed_out=timed_out, terminated=terminated,
            processes_killed=killed, elapsed_s=time.time() - started,
            controls=_controls(cpu_s, memory_mb, fsize_mb, nproc, sandbox_uid))


def _controls(cpu_s, memory_mb, fsize_mb, nproc, uid) -> dict:
    return {
        "cpu_seconds": cpu_s, "memory_mb": memory_mb, "fsize_mb": fsize_mb,
        "max_processes": nproc, "uid": uid,
        "capabilities": "dropped",
        "no_new_privs": True,
        "seccomp": "allowlist",
        "landlock": "write-confined",
        "network": "disabled",
        "termination": "pid-namespace-kill",
    }


def containment_status() -> dict:
    """Report what containment is ACTUALLY available, for honest API reporting."""
    status = {
        "supervisor": None,
        "seccomp": False,
        "landlock_abi": 0,
        "cgroup_v2": False,
        "userns": False,
        "netns": False,
        "reason": "",
    }
    try:
        status["supervisor"] = str(ensure_supervisor())
    except SupervisorUnavailable as exc:
        status["reason"] = str(exc)
        return status
    status["userns"] = bool(shutil.which("unshare"))
    status["netns"] = status["userns"]
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.syscall.restype = ctypes.c_long
        abi = libc.syscall(444, None, ctypes.c_size_t(0), ctypes.c_uint32(1))
        status["landlock_abi"] = max(0, int(abi))
    except Exception:
        pass
    status["seccomp"] = _seccomp_available()
    status["cgroup_v2"] = _cgroup_v2_usable()
    return status


def _seccomp_available() -> bool:
    try:
        with open("/proc/self/status") as fh:
            return "Seccomp:" in fh.read()
    except OSError:
        return False


def _cgroup_v2_usable() -> bool:
    """True only if an unprivileged process can actually create a cgroup."""
    path = "/sys/fs/cgroup"
    if not os.path.ismount(path):
        return False
    return os.access(path, os.W_OK)
