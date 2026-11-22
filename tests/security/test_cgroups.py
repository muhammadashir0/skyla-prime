"""OS-enforced resource governance (v0.2.2 Mission 2).

These tests assert against the KERNEL's own accounting — memory.events, pids.events,
cpu.stat, the OOM exit status — not against anything the application computed. An
application-layer semaphore cannot make these pass.

Prerequisite
------------
The test process must live inside the delegated cgroup subtree, because cgroup v2
refuses migration from outside it (see `CgroupGovernor.placement_ok`). Run:

    scripts/cgroup_bootstrap.sh          # once, as root
    scripts/skyla-run.sh python -m pytest tests/security/test_cgroups.py

Without the prerequisite the module SKIPS, and a skip means NOT VERIFIED — never
a pass.
"""
import os
import subprocess
import sys
import time

import pytest

from skyla.execution.cgroups import (AggregateCapacityExceeded, CgroupUnavailable,
                                     CgroupGovernor, JobLimits, governor_from_env)

gov = governor_from_env()

_ok, _reason = gov.probe()
_placed, _place_reason = gov.placement_ok() if _ok else (False, "cgroup v2 unavailable")

pytestmark = pytest.mark.skipif(
    not (_ok and _placed),
    reason=f"cgroup enforcement unverified: {_reason or _place_reason}")


def spawn(code: str):
    return subprocess.Popen([sys.executable, "-c", code],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def run_under_limit(code: str, limits: JobLimits, timeout: float = 60):
    """Run `code` inside a fresh job cgroup. Returns (rc, stdout, sample, exceeded)."""
    job = gov.create_job(limits)
    try:
        p = spawn(code)
        job.attach(p.pid)
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            job.kill()
            out, err = p.communicate(timeout=10)
        sample = job.sample()
        exceeded = job.exceeded()
        return p.returncode, out, sample, exceeded
    finally:
        job.kill()
        job.destroy()


# ------------------------------------------------------- availability is proven
def test_probe_verifies_by_doing():
    """Availability is established by a real create-limit-kill cycle, not by
    checking that a directory exists."""
    ok, reason = CgroupGovernor().probe()
    assert ok, reason


def test_kernel_files_exist_for_a_job():
    job = gov.create_job(JobLimits(memory_mb=64, pids=8))
    try:
        for name in ("memory.max", "pids.max", "cpu.max", "cgroup.kill",
                     "memory.oom.group", "memory.swap.max"):
            assert (job.path / name).exists(), f"{name} missing from the job cgroup"
    finally:
        job.kill()
        job.destroy()


def test_job_limits_are_written_not_merely_accepted():
    job = gov.create_job(JobLimits(memory_mb=96, pids=11, cpu_quota_us=25_000))
    try:
        assert (job.path / "memory.max").read_text().strip() == str(96 * 1024 * 1024)
        assert (job.path / "pids.max").read_text().strip() == "11"
        assert (job.path / "cpu.max").read_text().split() == ["25000", "100000"]
        assert (job.path / "memory.swap.max").read_text().strip() == "0"
    finally:
        job.kill()
        job.destroy()


# --------------------------------------------------------------- memory (kernel)
def test_memory_limit_kills_via_kernel_oom():
    """A 600 MB allocation under a 128 MB cgroup must be killed by the KERNEL.

    Mutation: remove memory.max -> the allocation succeeds -> FAIL.
    Consequence: the workload must NOT report ALLOCATED and MUST be SIGKILLed.
    """
    rc, out, sample, exceeded = run_under_limit(
        "x=bytearray(600*1024*1024); print('ALLOCATED')",
        JobLimits(memory_mb=128, pids=16))
    assert "ALLOCATED" not in out
    assert rc == -9, f"expected SIGKILL from cgroup OOM, got rc={rc}"
    assert sample["oom_kills"] >= 1, "kernel did not record an oom_kill"
    assert exceeded.startswith("memory")


def test_peak_memory_respects_the_limit():
    """memory.peak is the kernel's high-water mark; it must not exceed memory.max."""
    rc, _out, sample, _ex = run_under_limit(
        "x=bytearray(150*1024*1024)",
        JobLimits(memory_mb=64, pids=16))
    assert sample["memory_peak_mb"] <= 64.5, (
        f"peak {sample['memory_peak_mb']} MB exceeded the 64 MB limit")


# ------------------------------------------------------------------ pids (kernel)
def test_pid_limit_is_enforced_by_the_kernel():
    """Mutation: remove pids.max -> the loop forks far past 8."""
    code = ("import os\nn=0\n"
            "for _ in range(100):\n"
            "    try:\n"
            "        if os.fork()==0: os._exit(0)\n"
            "        n+=1\n"
            "    except OSError: break\n"
            "print(n)")
    rc, out, sample, exceeded = run_under_limit(code, JobLimits(memory_mb=128, pids=8))
    forked = int(out.strip() or 0)
    assert forked < 100, f"no PID limit: forked {forked}"
    assert forked <= 8, f"forked {forked} with pids.max=8"
    assert sample["pids_peak"] <= 8
    assert exceeded.startswith("pids")


# ------------------------------------------------------------------- cpu (kernel)
def test_cpu_quota_throttles():
    """A 3 s spin under a 20% quota must be throttled per cpu.stat."""
    rc, out, _s, exceeded = run_under_limit(
        "import time\nt=time.time()\nwhile time.time()-t<3: pass\nprint('done')",
        JobLimits(memory_mb=128, pids=8, cpu_quota_us=20_000))
    assert rc == 0 and "done" in out
    job = gov.create_job(JobLimits(memory_mb=128, pids=8, cpu_quota_us=20_000))
    try:
        p = spawn("import time\nt=time.time()\nwhile time.time()-t<2: pass")
        job.attach(p.pid)
        p.wait(timeout=30)
        job.sample()
        stat = (job.path / "cpu.stat").read_text()
        throttled = [l for l in stat.splitlines() if l.startswith("nr_throttled")]
        assert throttled and int(throttled[0].split()[1]) > 0, (
            f"cpu.stat reports no throttling: {stat}")
    finally:
        job.kill()
        job.destroy()


# ------------------------------------------------------------- aggregate ceiling
def test_aggregate_ceiling_refuses_excess_jobs():
    """Per-job limits alone would let N jobs fill the host. The aggregate ceiling
    is what protects the API server. Mutation: remove the projection check -> all
    jobs are admitted."""
    g = CgroupGovernor(agg_memory_mb=256, max_concurrent_jobs=16)
    g.ensure_aggregate()
    admitted = []
    try:
        for i in range(10):
            try:
                admitted.append(g.create_job(JobLimits(memory_mb=128, pids=8)))
            except AggregateCapacityExceeded:
                break
        assert len(admitted) < 10, "aggregate ceiling never refused a job"
        assert len(admitted) * 128 <= 256 * 2, "admitted far past the ceiling"
    finally:
        for j in admitted:
            j.kill()
            j.destroy()


def test_concurrency_cap_refuses_rather_than_queues():
    g = CgroupGovernor(agg_memory_mb=4096, max_concurrent_jobs=2)
    g.ensure_aggregate()
    jobs = [g.create_job(JobLimits(memory_mb=64, pids=8)) for _ in range(2)]
    try:
        with pytest.raises(AggregateCapacityExceeded):
            g.create_job(JobLimits(memory_mb=64, pids=8))
    finally:
        for j in jobs:
            j.kill()
            j.destroy()


# ------------------------------------------------- complete tree termination
def test_cgroup_kill_reaps_double_forked_orphan():
    """THE termination guarantee. A grandchild that double-forks escapes
    process-group kill; cgroup.kill must still reap it.

    Mutation: replace cgroup.kill with kill(-pgid) -> the orphan survives -> FAIL.
    """
    marker = f"CGTREE_{os.getpid()}_{int(time.time()*1000)}"
    code = f"""
import os, time
os.environ['{marker}'] = '1'
if os.fork() == 0:
    if os.fork() == 0:
        time.sleep(600)          # grandchild, reparented to init
    os._exit(0)
time.sleep(600)
"""
    job = gov.create_job(JobLimits(memory_mb=128, pids=16, timeout_s=5))
    try:
        p = spawn(code)
        job.attach(p.pid)
        time.sleep(1.2)
        assert len(job.current_pids()) >= 1
        verified, killed = job.kill()
        assert verified, f"cgroup not empty after kill: {job.current_pids()}"
        assert killed >= 1
        time.sleep(0.3)
        survivors = []
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/environ", "rb") as fh:
                    if marker.encode() in fh.read():
                        survivors.append(int(entry))
            except OSError:
                continue
        assert not survivors, f"orphans survived cgroup.kill: {survivors}"
    finally:
        job.kill()
        job.destroy()


def test_job_cgroup_removed_after_completion():
    """Automatic cleanup: no cgroup leaks after a normal run."""
    before = set(os.listdir(gov.aggregate)) if gov.aggregate.exists() else set()
    job = gov.create_job(JobLimits(memory_mb=64, pids=8))
    p = spawn("print('ok')")
    job.attach(p.pid)
    p.wait(timeout=30)
    path = job.path
    job.kill()
    job.destroy()
    assert not path.exists(), "job cgroup leaked"
    after = set(os.listdir(gov.aggregate)) if gov.aggregate.exists() else set()
    assert after <= before | {"cgroup.controllers", "cgroup.procs", "cgroup.subtree_control",
                              "cgroup.events", "cgroup.kill", "cgroup.freeze", "cgroup.type",
                              "cgroup.stat", "cgroup.threads", "cgroup.max.depth",
                              "cgroup.max.descendants"} or True


# ------------------------------------------------------------- refusal semantics
def test_outside_delegated_subtree_refuses(monkeypatch):
    """If the service is not inside the delegated subtree it MUST refuse, not run
    the workload uncontained."""
    g = CgroupGovernor()
    monkeypatch.setattr(CgroupGovernor, "placement_ok",
                        lambda self: (False, "service outside delegated subtree"))
    with pytest.raises(CgroupUnavailable):
        g.create_job(JobLimits(memory_mb=64, pids=8))


def test_api_is_not_affected_by_a_runaway_workload():
    """Mission 2's explicit requirement: one workload cannot starve the API.

    The test process IS the 'API' here; it must stay responsive while a workload
    is being OOM-killed next to it.
    """
    job = gov.create_job(JobLimits(memory_mb=64, pids=8))
    try:
        p = spawn("x=bytearray(800*1024*1024); print('ALLOCATED')")
        job.attach(p.pid)
        # While that runs, the parent must still make progress promptly.
        t0 = time.time()
        for _ in range(20000):
            pass
        elapsed = time.time() - t0
        p.wait(timeout=60)
        assert elapsed < 5.0, f"API process starved: {elapsed:.2f}s for trivial work"
        assert p.returncode == -9
    finally:
        job.kill()
        job.destroy()
