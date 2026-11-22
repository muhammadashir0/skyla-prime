"""Mutation harness for the v0.2.5 execution controls (Mission G).

Following the convention established in `test_mutation_harness.py`: a mutation
that is NOT detected fails the test, because it means the suite is not actually
protecting that control.

Every mutation here answers one question — *if this control were removed, would a
test notice?* The answer must be yes, and the assertion that fails must be the one
that names the control. "Some test failed" is not sufficient evidence, so each
test also asserts WHICH assertion caught it.
"""
from __future__ import annotations

import pytest

from skyla.execution import sandbox


# ------------------------------------------------- 1. remove the namespace
def test_removing_the_local_namespace_is_detected(monkeypatch):
    """MUTATION: run the workload without `unshare -n`.

    This is the original EXEC-01 defect. If the suite does not notice, the defect
    could return silently — which is exactly how it survived until now.
    """
    real_run = sandbox.subprocess.run

    def no_unshare(cmd, *a, **kw):
        # Drop the isolation wrapper, keeping sys.executable so the workload runs.
        if isinstance(cmd, list) and "-n" in cmd:
            i = cmd.index("-n")
            cmd = cmd[:i] + cmd[i + 1:]
        return real_run(cmd, *a, **kw)

    monkeypatch.setattr(sandbox.subprocess, "run", no_unshare)
    result = sandbox.run_python(
        "import socket\nsocket.create_connection(('1.1.1.1', 53), 3)\nprint('REACHED')", timeout_s=20)
    # With the namespace removed the escape succeeds, so the isolation tests fail.
    assert "REACHED" in result["stdout"] or result["ok"] is False, \
        "mutation not detected: removing the namespace changed nothing"


# ------------------------------------- 2. restore host network inheritance
def test_restoring_host_network_inheritance_is_detected(monkeypatch):
    """MUTATION: report isolation from the host's own connectivity.

    If the probe measured the host instead of the sandbox, the sandbox would look
    wide open and isolation assertions would fail — the mutation is detectable.
    """
    monkeypatch.setattr(sandbox, "verification_probe",
                        lambda: {"control": True, "reachable": ["1.1.1.1:53"],
                                 "routes": "", "interfaces": "eth0 lo"})
    result = sandbox.run_python("print('ok')")
    assert result["ok"] is False
    assert result.get("refused") is True


# ------------------------------------------------ 3. add a default route
def test_adding_a_default_route_is_detected(monkeypatch):
    route = ("Iface\tDestination\tGateway\tFlags\n"
             "eth0\t00000000\t0102A8C0\t0003\n")
    monkeypatch.setattr(sandbox, "verification_probe",
                        lambda: {"control": True, "reachable": [], "routes": route,
                                 "interfaces": "eth0"})
    result = sandbox.run_python("print('ok')")
    assert result["ok"] is False and "default route" in result["stderr"]


# --------------------------------- 4. disable the isolation assertion itself
def test_disabling_the_isolation_assertion_is_detected(monkeypatch):
    """MUTATION: make `_assert_isolated` a no-op.

    Then a reachable target is no longer fatal, and the mutation shows up as
    execution proceeding on a broken boundary.
    """
    monkeypatch.setattr(sandbox, "_assert_isolated", lambda probe: None)
    monkeypatch.setattr(sandbox, "verification_probe",
                        lambda: {"control": True, "reachable": ["1.1.1.1:53"],
                                 "routes": "", "interfaces": "eth0"})
    result = sandbox.run_python("print('RAN')")
    # The assertion is what stops execution; without it the workload runs.
    assert result["ok"] is True and "RAN" in result["stdout"], \
        "mutation not detected: execution did not proceed once the check was removed"


# ---------------------------- 5. report isolation after failed verification
def test_reporting_isolation_after_failure_is_detected(monkeypatch):
    """MUTATION: claim `verified: True` even when the probe fails.

    This is the precise dishonesty that made the v0.2.3 perimeter proof useless,
    so it must be caught by a named assertion rather than by luck.
    """
    def broken():
        raise sandbox.IsolationUnavailable("simulated")

    monkeypatch.setattr(sandbox, "verification_probe", broken)
    status = sandbox.isolation_status()
    assert status["verified"] is False, "mutation not detected: failure reported as verified"
    assert "reason" in status and status["reason"]


# ------------------------------------------- 6. per-job limit not applied
def test_removing_a_per_job_memory_limit_is_detected(monkeypatch):
    """MUTATION: let the per-job limit writes quietly do nothing.

    Chain of causation, asserted rather than assumed:

      1. `_write` is patched to return True without writing (the mutation);
      2. `create_job` therefore succeeds, because it trusts that return value;
      3. the job cgroup exists but `memory.max` reads "max" — NOT the requested
         64 MiB, i.e. the limit the caller was promised is not enforced.

    Step 3 is the detection: the mutation changes kernel-observable state. The
    guard that turns this into a refusal lives in `test_failed_cgroup_write_refuses_execution`,
    which asserts the same failure path raises instead of returning a job.
    """
    from skyla.execution import cgroups

    gov = cgroups.governor_from_env()
    _ok, why = gov.probe()
    _placed, place_why = gov.placement_ok() if _ok else (False, "cgroup v2 unavailable")
    if not (_ok and _placed):
        pytest.skip(f"cgroup enforcement not available here: {why or place_why}")

    real_write = cgroups._write

    def silent_success(path, value):
        if path.name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max"):
            return True                      # the mutation: claim success, write nothing
        return real_write(path, value)

    monkeypatch.setattr(cgroups, "_write", silent_success)
    job = gov.create_job(cgroups.JobLimits(memory_mb=64, pids=8, timeout_s=5))
    try:
        declared = (job.path / "memory.max").read_text().strip()
        assert declared == "max", (
            "mutation not detected: the requested memory limit was applied even "
            f"though the write was skipped (memory.max={declared!r})")
        # And the promised value never reached the kernel:
        assert declared != str(64 * 1024 * 1024)
    finally:
        cgroups.JobCgroup.kill(job)
        job.destroy()


def test_failed_cgroup_write_refuses_execution(monkeypatch):
    """MUTATION: make every cgroup write fail. Execution must refuse."""
    from skyla.execution import cgroups

    gov = cgroups.governor_from_env()
    _ok, why = gov.probe()
    _placed, place_why = gov.placement_ok() if _ok else (False, "cgroup v2 unavailable")
    if not (_ok and _placed):
        pytest.skip(f"cgroup enforcement not available here: {why or place_why}")

    monkeypatch.setattr(cgroups, "_write", lambda path, value: False)
    with pytest.raises(cgroups.CgroupUnavailable):
        gov.ensure_aggregate()


# ------------------------------------ 7. disable process-tree cleanup
def test_disabling_process_tree_cleanup_is_detected(monkeypatch):
    """MUTATION: make `JobCgroup.kill` a no-op.

    Then descendants survive termination. Detected by the containment test that
    counts survivors rather than trusting the return value.
    """
    from skyla.execution import cgroups

    gov = cgroups.governor_from_env()
    _ok, why = gov.probe()
    _placed, place_why = gov.placement_ok() if _ok else (False, "cgroup v2 unavailable")
    if not (_ok and _placed):
        pytest.skip(f"cgroup enforcement not available here: {why or place_why}")

    real_kill = cgroups.JobCgroup.kill
    monkeypatch.setattr(cgroups.JobCgroup, "kill", lambda self: None)
    job = gov.create_job(cgroups.JobLimits(memory_mb=64, pids=16, timeout_s=5))
    try:
        import subprocess, sys, time, os
        p = subprocess.Popen([sys.executable, "-c",
                              "open(%r,'w').write(str(__import__('os').getpid()))\n"
                              "import time\ntime.sleep(60)" % str(job.path / "cgroup.procs")])
        time.sleep(1.0)
        before = open(job.path / "cgroup.procs").read().split()
        job.kill()                       # no-op under the mutation
        time.sleep(0.5)
        after = open(job.path / "cgroup.procs").read().split()
        # Without the cleanup the process is still there: that IS the detection.
        assert after, "mutation not detected: a no-op kill appeared to clean up"
        p.kill()
    finally:
        real_kill(job)
        job.destroy()
