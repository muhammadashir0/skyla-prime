"""Fail-closed behaviour of the cgroup governor (v0.2.2 Mission 2).

DELIBERATELY SEPARATE from `test_cgroups.py`. That module skips wholesale unless
the test process runs inside the delegated subtree, which means none of its
assertions execute on an ordinary developer machine or CI runner. A governance
control that only fails closed *when cgroups are available* is not a control: the
interesting failure is exactly the case where a limit write does not take effect.

These tests need no kernel privileges. They substitute `_write` — the single
chokepoint every limit passes through — and assert that the governor REFUSES the
workload rather than returning a job that enforces nothing.

Motivating defect (measured, 2026-11-22)
----------------------------------------
`create_job()` wrote memory.max / swap.max / oom.group / pids.max / cpu.max and
IGNORED the boolean result of each write. With every limit write failing it still
returned a `JobCgroup`, and `NamespaceProvider.run()` reported
`controls["cgroup"]["enabled"] = True` to the API because it tested
`job is not None`. The workload ran unbounded while the response claimed kernel
enforcement. `ensure_aggregate()` had the same defect for the global ceiling.
"""
from pathlib import Path

import pytest

import skyla.execution.cgroups as C
from skyla.execution.cgroups import CgroupUnavailable, JobLimits


@pytest.fixture()
def gov(tmp_path):
    """A governor whose availability and placement checks are satisfied, so the
    test reaches the limit-writing code without a real delegated cgroup."""
    g = C.CgroupGovernor(root=tmp_path / "skyla", max_concurrent_jobs=4,
                         agg_memory_mb=1024, agg_pids=256)
    g._verified = True
    g._unavailable_reason = ""
    g.placement_ok = lambda: (True, "")
    g.root.mkdir(parents=True, exist_ok=True)
    return g


def _deny(monkeypatch, names: set[str], *, parent: str | None = None):
    """Make `_write` fail for the given filenames (optionally only under `parent`)."""
    real = C._write
    seen: list[str] = []

    def fake(path: Path, value: str) -> bool:
        if path.name in names and (parent is None or path.parent.name == parent):
            seen.append(str(path))
            return False
        return real(path, value)

    monkeypatch.setattr(C, "_write", fake)
    return seen


# --------------------------------------------------- per-job limits fail closed
@pytest.mark.parametrize("filename", ["memory.max", "memory.swap.max",
                                      "memory.oom.group", "pids.max", "cpu.max"])
def test_a_failed_job_limit_write_refuses_the_workload(gov, monkeypatch, filename):
    """Every per-job limit is load-bearing: none may fail silently."""
    _deny(monkeypatch, {filename})
    with pytest.raises(CgroupUnavailable) as exc:
        gov.create_job(JobLimits(memory_mb=128, pids=8))
    assert filename in str(exc.value), f"error should name {filename}: {exc.value}"


def test_a_refused_job_leaves_no_job_behind(gov, monkeypatch):
    """A refused job must not be counted against capacity or left on disk —
    otherwise a persistent failure would consume the whole budget in phantom
    jobs and the real aggregate ceiling would be unreachable."""
    _deny(monkeypatch, {"pids.max"})
    with pytest.raises(CgroupUnavailable):
        gov.create_job(JobLimits(memory_mb=128, pids=8))
    assert gov._jobs == {}, f"phantom jobs retained: {gov._jobs}"
    leftovers = [p for p in gov.aggregate.iterdir() if p.is_dir()] \
        if gov.aggregate.exists() else []
    assert leftovers == [], f"refused job cgroup left on disk: {leftovers}"


def test_a_job_that_cannot_be_limited_is_never_reported_as_enabled(gov, monkeypatch):
    """The exact defect: a returned JobCgroup implies `enabled: true` upstream.
    If no JobCgroup is returned, the provider reports the cgroup as absent."""
    _deny(monkeypatch, {"memory.max", "pids.max", "cpu.max", "memory.oom.group"})
    job = None
    try:
        job = gov.create_job(JobLimits(memory_mb=64, pids=4))
    except CgroupUnavailable:
        job = None
    assert job is None, "create_job() returned a job whose limits were never applied"


# -------------------------------------------- aggregate ceiling fails closed
@pytest.mark.parametrize("filename", ["memory.max", "memory.swap.max",
                                      "pids.max", "cpu.max",
                                      "cgroup.subtree_control"])
def test_a_failed_aggregate_write_refuses_all_workloads(gov, monkeypatch, filename):
    """The global ceiling is the protection the API server relies on. A ceiling
    that silently failed to apply must stop workloads, not admit them."""
    _deny(monkeypatch, {filename}, parent="aggregate")
    with pytest.raises(CgroupUnavailable) as exc:
        gov.ensure_aggregate()
    assert filename in str(exc.value) or "aggregate" in str(exc.value)


def test_aggregate_failure_propagates_out_of_create_job(gov, monkeypatch):
    _deny(monkeypatch, {"memory.max"}, parent="aggregate")
    with pytest.raises(CgroupUnavailable):
        gov.create_job(JobLimits(memory_mb=64, pids=4))
    assert gov._jobs == {}, "a job was registered despite the aggregate failing"


# --------------------------------------------------- limits really are written
def test_all_five_limits_are_written_when_nothing_fails(gov):
    """Control: with writes succeeding, the job is returned and every limit file
    exists with the requested value. Without this, the tests above could pass
    because create_job() always raises."""
    job = gov.create_job(JobLimits(memory_mb=128, pids=7))
    try:
        assert (job.path / "memory.max").read_text().strip() == str(128 * C.MIB)
        assert (job.path / "memory.swap.max").read_text().strip() == "0"
        assert (job.path / "memory.oom.group").read_text().strip() == "1"
        assert (job.path / "pids.max").read_text().strip() == "7"
        assert (job.path / "cpu.max").read_text().strip() == JobLimits(
            memory_mb=128, pids=7).cpu_max()
    finally:
        job.destroy()


def test_aggregate_ceiling_is_written_when_nothing_fails(gov):
    agg = gov.ensure_aggregate()
    assert (agg / "memory.max").read_text().strip() == str(1024 * C.MIB)
    assert (agg / "pids.max").read_text().strip() == "256"
    assert (agg / "cpu.max").read_text().strip().endswith("100000")
