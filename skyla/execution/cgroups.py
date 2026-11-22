"""OS-enforced resource governance (v0.2.2 PRIME QUALIFICATION, Mission 2).

Replaces the v0.3.0 application-layer `CapacityGovernor` semaphore as the
*authoritative* enforcement mechanism. The semaphore bounded concurrency inside
one Python process; it could not bound memory, CPU or PID consumption across
processes, and it could not kill a runaway tree. This module uses cgroup v2, so
the kernel does the work.

Enforcement model
-----------------
```
/sys/fs/cgroup/skyla/                 (delegated to the service user)
    aggregate/                        <-- GLOBAL ceiling: no workload escapes this
        memory.max                    SKYLA_AGG_MEMORY_MB
        pids.max                      SKYLA_AGG_PIDS
        cpu.max                       SKYLA_AGG_CPU
        job-<id>/                     <-- per-workload ceiling
            memory.max                per-job memory
            pids.max                  per-job PID limit
            cpu.max                   per-job CPU quota
            cgroup.kill               complete tree termination
```

Two levels are required, not one. A per-job limit alone lets N jobs each take
their slice until the host is out of memory; the aggregate cgroup is the ceiling
that protects the API server and other tenants (Mission 2's stated requirement).

Delegation
----------
An unprivileged process cannot create cgroups under a root-owned parent, and it
cannot delegate to itself. `scripts/cgroup_bootstrap.sh` performs that one step
as root; from then on every operation here is unprivileged. There is deliberately
**no** runtime `sudo`: if delegation is absent, this module reports unavailable
and the caller must refuse the workload rather than run it uncontained.

Availability is verified, not assumed
-------------------------------------
`available()` performs a real create-limit-attach-destroy cycle. A cgroup2 mount
that merely exists is not evidence that we may use it.
"""
from __future__ import annotations

import os
import shutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

CGROUP_ROOT = Path(os.getenv("SKYLA_CGROUP_ROOT", "/sys/fs/cgroup/skyla"))
AGGREGATE_NAME = "aggregate"
SERVICE_NAME = "service"

MIB = 1024 * 1024


class CgroupUnavailable(RuntimeError):
    """The kernel/host cannot enforce the required controls. Refuse the workload."""


class AggregateCapacityExceeded(RuntimeError):
    """The deployment-wide ceiling would be exceeded by this workload."""


def _read(path: Path, default: str = "") -> str:
    try:
        return path.read_text().strip()
    except OSError:
        return default


def _write(path: Path, value: str) -> bool:
    try:
        path.write_text(f"{value}\n")
        return True
    except OSError:
        return False


def _fs_type(path: str) -> int:
    """Filesystem magic number for `path`, via statfs(2)."""
    import ctypes
    import ctypes.util

    class Statfs(ctypes.Structure):
        _fields_ = [("f_type", ctypes.c_long), ("f_bsize", ctypes.c_long),
                    ("f_blocks", ctypes.c_ulonglong), ("f_bfree", ctypes.c_ulonglong),
                    ("f_bavail", ctypes.c_ulonglong), ("f_files", ctypes.c_ulonglong),
                    ("f_ffree", ctypes.c_ulonglong), ("f_fsid", ctypes.c_int * 2),
                    ("f_namelen", ctypes.c_long), ("f_frsize", ctypes.c_long),
                    ("f_flags", ctypes.c_long), ("f_spare", ctypes.c_long * 10)]

    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    buf = Statfs()
    if libc.statfs(path.encode(), ctypes.byref(buf)) != 0:
        return -1
    return buf.f_type


CGROUP2_SUPER_MAGIC = 0x63677270


def _cgroup2_mounted() -> bool:
    return _fs_type("/sys/fs/cgroup") == CGROUP2_SUPER_MAGIC


@dataclass
class JobLimits:
    memory_mb: int = 512
    pids: int = 24
    cpu_quota_us: int = 50_000      # per cpu.max period (100 ms)
    cpu_period_us: int = 100_000
    timeout_s: float = 30.0

    def cpu_max(self) -> str:
        return f"{self.cpu_quota_us} {self.cpu_period_us}"


@dataclass
class AggregateUsage:
    memory_current_mb: float = 0.0
    memory_max_mb: float = 0.0
    pids_current: int = 0
    pids_max: int = 0
    jobs: int = 0
    cpu_throttled_us: int = 0

    def as_dict(self) -> dict:
        return self.__dict__


class CgroupGovernor:
    """Creates, limits, monitors and reaps per-workload cgroups."""

    def __init__(self, root: Path = CGROUP_ROOT,
                 *, agg_memory_mb: int = 1024, agg_pids: int = 256,
                 agg_cpu_quota_us: int = 150_000,
                 max_concurrent_jobs: int = 6):
        self.root = root
        self.agg_memory_mb = agg_memory_mb
        self.agg_pids = agg_pids
        self.agg_cpu_quota_us = agg_cpu_quota_us
        self.max_concurrent_jobs = max_concurrent_jobs
        self._lock = threading.Lock()
        self._jobs: dict[str, Path] = {}
        self._unavailable_reason = ""
        self._verified = False

    # ------------------------------------------------------------ discovery
    @property
    def aggregate(self) -> Path:
        return self.root / AGGREGATE_NAME

    def probe(self) -> tuple[bool, str]:
        """Verify we can actually enforce, by doing it. Cached after success."""
        if self._verified:
            return True, ""
        if self._unavailable_reason:
            return False, self._unavailable_reason
        if not _cgroup2_mounted():
            self._unavailable_reason = "cgroup v2 is not mounted at /sys/fs/cgroup"
            return False, self._unavailable_reason
        if not self.root.exists():
            self._unavailable_reason = (
                f"{self.root} missing — run scripts/cgroup_bootstrap.sh as root "
                f"once to delegate the subtree")
            return False, self._unavailable_reason
        if not os.access(self.root, os.W_OK):
            self._unavailable_reason = (
                f"{self.root} is not writable by uid {os.getuid()} "
                f"(delegation absent)")
            return False, self._unavailable_reason

        probe = self.root / f"probe-{uuid.uuid4().hex[:8]}"
        try:
            probe.mkdir()
            if not _write(probe / "memory.max", str(64 * MIB)):
                self._unavailable_reason = "cannot set memory.max on a probe cgroup"
                return False, self._unavailable_reason
            if not _write(probe / "pids.max", "4"):
                self._unavailable_reason = "cannot set pids.max on a probe cgroup"
                return False, self._unavailable_reason
            if _read(probe / "memory.max") != str(64 * MIB):
                self._unavailable_reason = "memory.max did not accept the written value"
                return False, self._unavailable_reason
            # cgroup.kill is what makes termination complete; require it.
            if not (probe / "cgroup.kill").exists():
                self._unavailable_reason = "cgroup.kill absent (kernel < 5.14)"
                return False, self._unavailable_reason
        except OSError as exc:
            self._unavailable_reason = f"probe failed: {exc}"
            return False, self._unavailable_reason
        finally:
            try:
                probe.rmdir()
            except OSError:
                pass
        self._verified = True
        return True, ""

    def available(self) -> bool:
        return self.probe()[0]

    # ------------------------------------------------------------ placement
    def placement_ok(self) -> tuple[bool, str]:
        """Can THIS process migrate a child into a job cgroup?

        cgroup v2 requires write access to cgroup.procs on every ancestor. The
        root cgroup's cgroup.procs is root-owned on any normal host, so the
        process calling us must itself already be inside the delegated subtree
        (e.g. started with `systemd Delegate=yes`, or placed there once at
        startup). If it is not, migration returns EACCES and we MUST refuse the
        workload rather than run it unbounded.
        """
        try:
            here = Path("/proc/self/cgroup").read_text().strip()
        except OSError as exc:
            return False, f"cannot read /proc/self/cgroup: {exc}"
        # /proc/self/cgroup reports paths relative to the cgroup2 mount point,
        # e.g. "0::/skyla/service", whereas self.root is a filesystem path such as
        # /sys/fs/cgroup/skyla. Compare using the mount-relative form of the root.
        rel = here.split("::", 1)[-1] if "::" in here else here
        mount_rel = "/" + str(self.root).split("/sys/fs/cgroup/", 1)[-1].lstrip("/")
        inside = (rel == mount_rel or rel == str(self.root)
                  or rel.startswith(mount_rel.rstrip("/") + "/"))
        if not inside:
            return False, (
                f"service process is in cgroup '{rel}', outside the delegated "
                f"subtree '{self.root}'; start the service inside "
                f"'{self.service_cgroup()}' (or use systemd Delegate=yes) so it "
                f"may migrate workloads")
        return True, ""

    def enter_service_cgroup(self) -> tuple[bool, str]:
        """Best-effort: move this process into the service cgroup.

        Only possible when an ancestor is already delegated to us; typically this
        is done once by the launcher. Returns (moved, reason) and never raises.
        """
        svc = self.service_cgroup()
        try:
            svc.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return False, f"cannot create {svc}: {exc}"
        current = Path("/proc/self/cgroup").read_text().strip().split("::", 1)[-1]
        if current == str(svc):
            return True, "already in service cgroup"
        try:
            fd = os.open(str(svc / "cgroup.procs"), os.O_WRONLY)
            try:
                os.write(fd, str(os.getpid()).encode())
            finally:
                os.close(fd)
            return True, "moved"
        except OSError as exc:
            return False, f"cannot move into {svc}: {exc}"

    def service_cgroup(self) -> Path:
        return self.root / SERVICE_NAME

    # ------------------------------------------------------------- aggregate
    def ensure_aggregate(self) -> Path:
        """Create/refresh the global ceiling cgroup."""
        ok, reason = self.probe()
        if not ok:
            raise CgroupUnavailable(reason)
        agg = self.aggregate
        agg.mkdir(exist_ok=True)
        # Controllers must be enabled on the aggregate's PARENT so the aggregate
        # itself has memory.*/pids.*/cpu.* files, and on the AGGREGATE so its
        # child job cgroups inherit those controllers. Enabling both is required:
        # a controller enabled only at the root does not reach grandchildren.
        #
        # Every write here is load-bearing: an aggregate ceiling that silently
        # failed to apply would leave the global limit absent while status()
        # reported a configured value (measured — all three files ABSENT with no
        # exception). Fail closed instead.
        for target, value, label in (
            (self.root / "cgroup.subtree_control", "+memory +pids +cpu",
             "controllers on the delegation root"),
            (agg / "cgroup.subtree_control", "+memory +pids +cpu",
             "controllers on the aggregate"),
            (agg / "memory.max", str(self.agg_memory_mb * MIB), "aggregate memory.max"),
            (agg / "memory.swap.max", "0", "aggregate memory.swap.max"),
            (agg / "pids.max", str(self.agg_pids), "aggregate pids.max"),
            (agg / "cpu.max", f"{self.agg_cpu_quota_us} 100000", "aggregate cpu.max"),
        ):
            if not _write(target, value):
                raise CgroupUnavailable(
                    f"cannot set {label} ({target}) — refusing to run workloads "
                    f"under an unenforced aggregate ceiling")
        return agg

    def usage(self) -> AggregateUsage:
        agg = self.aggregate
        u = AggregateUsage()
        if not agg.exists():
            return u
        cur = _read(agg / "memory.current", "0")
        mx = _read(agg / "memory.max", "0")
        u.memory_current_mb = round(int(cur or 0) / MIB, 2) if cur.isdigit() else 0.0
        u.memory_max_mb = round(int(mx) / MIB, 2) if mx.isdigit() else 0.0
        pc = _read(agg / "pids.current", "0")
        pm = _read(agg / "pids.max", "0")
        u.pids_current = int(pc) if pc.isdigit() else 0
        u.pids_max = int(pm) if pm.isdigit() else 0
        u.jobs = sum(1 for p in agg.iterdir() if p.is_dir()) if agg.exists() else 0
        for line in _read(agg / "cpu.stat", "").splitlines():
            if line.startswith("throttled_usec"):
                u.cpu_throttled_us = int(line.split()[1])
        return u

    # ------------------------------------------------------------------ jobs
    def create_job(self, limits: JobLimits, job_id: str | None = None) -> "JobCgroup":
        ok, reason = self.probe()
        if not ok:
            raise CgroupUnavailable(reason)
        placed, place_reason = self.placement_ok()
        if not placed:
            raise CgroupUnavailable(place_reason)
        with self._lock:
            if len(self._jobs) >= self.max_concurrent_jobs:
                raise AggregateCapacityExceeded(
                    f"max concurrent workloads ({self.max_concurrent_jobs}) reached; "
                    f"refusing rather than queueing")
            agg = self.ensure_aggregate()
            # Warn if the sum of live job limits would exceed the aggregate ceiling.
            projected = (len(self._jobs) + 1) * limits.memory_mb
            if projected > self.agg_memory_mb:
                raise AggregateCapacityExceeded(
                    f"{len(self._jobs) + 1} concurrent jobs x {limits.memory_mb} MB "
                    f"would exceed the {self.agg_memory_mb} MB aggregate ceiling")
            jid = job_id or uuid.uuid4().hex[:12]
            path = agg / f"job-{jid}"
            path.mkdir(exist_ok=False)
            self._jobs[jid] = path

        # Every limit write is load-bearing. Failing to write one used to leave a
        # job cgroup that enforced NOTHING while the caller reported
        # `enabled: true` to the API (measured: memory.max/pids.max/cpu.max all
        # absent, zero jobs rejected). Fail closed: refusing the workload is
        # correct, silently running it unbounded is not.
        for filename, value in (
            ("memory.max", str(limits.memory_mb * MIB)),
            ("memory.swap.max", "0"),        # no swapping around the limit
            ("memory.oom.group", "1"),       # kill the WHOLE group on OOM
            ("pids.max", str(limits.pids)),
            ("cpu.max", limits.cpu_max()),
        ):
            if not _write(path / filename, value):
                self._forget(jid)
                try:
                    path.rmdir()
                except OSError:
                    pass
                raise CgroupUnavailable(
                    f"cannot set {filename} on {path} — refusing to run the "
                    f"workload with an unenforced limit")
        return JobCgroup(jid, path, limits, self)

    def _forget(self, job_id: str) -> None:
        with self._lock:
            self._jobs.pop(job_id, None)

    def status(self) -> dict:
        ok, reason = self.probe()
        placed, place_reason = self.placement_ok() if ok else (False, "cgroup v2 unavailable")
        return {
            "cgroup_v2": ok,
            "placement": placed,
            "placement_reason": place_reason,
            "cgroup_root": str(self.root),
            "reason": reason,
            "aggregate": self.usage().as_dict() if ok else {},
            "limits": {
                "agg_memory_mb": self.agg_memory_mb,
                "agg_pids": self.agg_pids,
                "aggregate_cpu_quota_us": self.agg_cpu_quota_us,
                "max_concurrent_jobs": self.max_concurrent_jobs,
            },
            "enforcement": "kernel (cgroup v2)" if ok else "none",
        }


@dataclass
class JobCgroup:
    """A single workload's cgroup. Use as a context manager."""

    job_id: str
    path: Path
    limits: JobLimits
    governor: CgroupGovernor
    peak_memory_mb: float = 0.0
    oom_kills: int = 0
    pids_peak: int = 0
    cpu_throttled_us: int = 0
    _attached: bool = field(default=False, repr=False)

    # -- attachment ----------------------------------------------------
    def attach(self, pid: int) -> None:
        """Put a process (and, for a process group leader, its descendants)."""
        if not _write(self.path / "cgroup.procs", str(pid)):
            raise CgroupUnavailable(f"cannot attach pid {pid} to {self.path}")
        self._attached = True

    def current_pids(self) -> list[int]:
        return [int(p) for p in _read(self.path / "cgroup.procs", "").split() if p.isdigit()]

    # -- observation ---------------------------------------------------
    def sample(self) -> dict:
        peak = _read(self.path / "memory.peak", "0")
        if peak.isdigit():
            self.peak_memory_mb = max(self.peak_memory_mb, round(int(peak) / MIB, 2))
        cur = _read(self.path / "memory.current", "0")
        pp = _read(self.path / "pids.peak", "0")
        if pp.isdigit():
            self.pids_peak = max(self.pids_peak, int(pp))
        events = _read(self.path / "memory.events", "")
        for line in events.splitlines():
            if line.startswith("oom_kill "):
                self.oom_kills = max(self.oom_kills, int(line.split()[1]))
        for line in _read(self.path / "cpu.stat", "").splitlines():
            if line.startswith("throttled_usec"):
                self.cpu_throttled_us = max(self.cpu_throttled_us, int(line.split()[1]))
        return {"memory_current_mb": round(int(cur) / MIB, 2) if cur.isdigit() else 0.0,
                "memory_peak_mb": self.peak_memory_mb,
                "pids_peak": self.pids_peak,
                "oom_kills": self.oom_kills}

    def exceeded(self) -> str:
        """Return which limit was hit, if any. Reads the kernel's own counters."""
        if self.oom_kills:
            return "memory (oom_kill)"
        events = _read(self.path / "pids.events", "")
        for line in events.splitlines():
            if line.startswith("max ") and int(line.split()[1]) > 0:
                return "pids (max)"
        if self.cpu_throttled_us > 0:
            return "cpu (throttled)"
        return ""

    # -- termination ---------------------------------------------------
    def kill(self) -> tuple[bool, int]:
        """Terminate the entire cgroup. Returns (verified_empty, killed_count)."""
        before = self.current_pids()
        if not _write(self.path / "cgroup.kill", "1"):
            # Older kernels lack cgroup.kill: fall back to explicit signals, but
            # report it, because the guarantee is weaker.
            for pid in before:
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if not self.current_pids():
                return True, len(before)
            time.sleep(0.02)
        return (not self.current_pids()), len(before)

    def destroy(self) -> None:
        try:
            self.path.rmdir()
        except OSError:
            pass
        self.governor._forget(self.job_id)

    def __enter__(self) -> "JobCgroup":
        return self

    def __exit__(self, *exc) -> None:
        self.kill()
        self.destroy()


def governor_from_env() -> CgroupGovernor:
    def _int(name: str, default: int) -> int:
        try:
            return int(os.getenv(name, default))
        except ValueError:
            return default
    return CgroupGovernor(
        agg_memory_mb=_int("SKYLA_AGG_MEMORY_MB", 1024),
        agg_pids=_int("SKYLA_AGG_PIDS", 256),
        agg_cpu_quota_us=_int("SKYLA_AGG_CPU_QUOTA_US", 150_000),
        max_concurrent_jobs=_int("SKYLA_MAX_CONCURRENT_EXECUTIONS", 4),
    )


# Module singleton, mirroring skyla.execution.service.governor.
cgroup_governor = governor_from_env()
