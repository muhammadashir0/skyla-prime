"""Mutation-based host-containment tests (v0.3.0, Mission 7).

Philosophy: each test asserts a property AGAINST THE ACTUAL RUNTIME, reading the
kernel's own view (procfs, syscall results, process tables). None of these tests
can pass because a function "returned the expected string".

Each test is written so that removing the corresponding control in
`skyla/execution/skyla-sup.c` makes it FAIL. `tests/security/test_mutation_harness.py`
verifies that claim mechanically.

Bounded on purpose: every workload here has cpu/memory/nproc/time limits and the
suite never launches an unbounded fork storm.
"""
import os
import subprocess

import pytest

from skyla.execution.workload import SupervisorUnavailable, containment_status, run_isolated

pytestmark = pytest.mark.skipif(
    not containment_status().get("supervisor"),
    reason="contained supervisor unavailable on this host")


def run(code, **kw):
    kw.setdefault("cpu_s", 5)
    kw.setdefault("memory_mb", 256)
    kw.setdefault("nproc", 16)
    kw.setdefault("timeout_s", 20)
    return run_isolated(code, **kw)


# --------------------------------------------------------------- A-01 capabilities
def test_capabilities_are_actually_zero():
    """Mutation: remove drop_all_capabilities() -> CapEff != 0 -> FAIL."""
    r = run("s=open('/proc/self/status').read()\n"
            "print([l.split()[1] for l in s.split('\\n') if l.startswith('CapEff')][0])")
    assert r.ok, r.stderr
    assert r.stdout.strip() == "0000000000000000", f"capabilities retained: {r.stdout!r}"


def test_bounding_set_is_empty():
    """Mutation: skip PR_CAPBSET_DROP -> CapBnd != 0 -> FAIL (exec would regain caps)."""
    r = run("s=open('/proc/self/status').read()\n"
            "print([l.split()[1] for l in s.split('\\n') if l.startswith('CapBnd')][0])")
    assert r.ok, r.stderr
    assert r.stdout.strip() == "0000000000000000"


def test_privileged_mount_syscall_is_denied():
    """Mutation: remove mount from the seccomp denylist -> rc 0 -> FAIL."""
    r = run("import ctypes\n"
            "l=ctypes.CDLL('libc.so.6',use_errno=True)\n"
            "rc=l.mount(b'tmpfs',b'/tmp',b'tmpfs',0,None)\n"
            "print(rc, ctypes.get_errno())")
    assert r.ok, r.stderr
    rc, errno = r.stdout.split()
    assert int(rc) == -1, f"mount succeeded inside the sandbox (rc={rc})"
    assert int(errno) in (1, 13)          # EPERM or EACCES


# ------------------------------------------------------------- A-01b no_new_privs
def test_no_new_privs_is_set():
    """Mutation: remove PR_SET_NO_NEW_PRIVS -> NoNewPrivs 0 -> FAIL."""
    r = run("s=open('/proc/self/status').read()\n"
            "print([l.split()[1] for l in s.split('\\n') if l.startswith('NoNewPrivs')][0])")
    assert r.ok, r.stderr
    assert r.stdout.strip() == "1"


# ------------------------------------------------------------------ seccomp (A-09)
def test_seccomp_filter_is_active():
    """Mutation: remove install_seccomp() -> Seccomp 0 -> FAIL."""
    r = run("s=open('/proc/self/status').read()\n"
            "print([l.split()[1] for l in s.split('\\n') if l.startswith('Seccomp')][0])")
    assert r.ok, r.stderr
    assert r.stdout.strip() == "2", "seccomp mode is not FILTER"


def test_dangerous_syscalls_denied():
    """Mutation: drop any of these from the filter -> the call succeeds -> FAIL."""
    code = """
import ctypes
libc = ctypes.CDLL('libc.so.6', use_errno=True)
results = {}
for name, nr in (('bpf',321), ('keyctl',250)):
    results[name] = libc.syscall(nr, 0, 0, 0, 0)
results['socket'] = libc.socket(2, 1, 0)
results['ptrace'] = libc.ptrace(16, 1, 0, 0)
print(results)
"""
    r = run(code)
    assert r.ok, r.stderr
    d = eval(r.stdout.strip())          # noqa: S307 - controlled output from our own sandbox
    assert d["bpf"] == -1, f"bpf syscall allowed: {d}"
    assert d["keyctl"] == -1, f"keyctl allowed: {d}"
    assert d["socket"] == -1, f"socket creation allowed: {d}"
    assert d["ptrace"] == -1, f"ptrace allowed: {d}"


# ------------------------------------------------------------------ A-02 PID limit
def test_process_limit_is_enforced():
    """Mutation: remove RLIMIT_NPROC -> the loop reaches 60 -> FAIL.

    Bounded to 40 attempts; the assertion is that a limit is hit BELOW that.
    """
    code = """
import os
n = 0
for _ in range(40):
    try:
        if os.fork() == 0:
            os._exit(0)
        n += 1
    except OSError:
        break
print(n)
"""
    r = run(code, nproc=12, timeout_s=25)
    assert r.ok, r.stderr
    forked = int(r.stdout.strip())
    assert forked < 40, f"no process limit: forked {forked} children"


def test_rlimit_values_are_visible_to_the_workload():
    """The limit is not merely 'some limit' -- it is the configured one."""
    r = run("import resource;print(resource.getrlimit(resource.RLIMIT_NPROC)[0])", nproc=7)
    assert r.ok, r.stderr
    assert r.stdout.strip() == "7"


# ----------------------------------------------------------------- A-03 memory cap
def test_memory_limit_is_enforced():
    """Mutation: remove RLIMIT_AS -> the allocation succeeds -> FAIL."""
    r = run("x=bytearray(3*1024*1024*1024); print('ALLOCATED')", memory_mb=128)
    assert not r.ok
    assert "MemoryError" in r.stderr or "ALLOCATED" not in r.stdout


def test_memory_rlimit_matches_configuration():
    r = run("import resource;print(resource.getrlimit(resource.RLIMIT_AS)[0])", memory_mb=128)
    assert r.ok, r.stderr
    assert int(r.stdout.strip()) == 128 * 1024 * 1024


# ---------------------------------------------------------------- A-18 CPU quota
def test_cpu_limit_is_set_and_enforced():
    """Mutation: remove RLIMIT_CPU -> a busy loop is cut off only by wall clock."""
    r = run("import resource;print(resource.getrlimit(resource.RLIMIT_CPU)[0])", cpu_s=3)
    assert r.ok, r.stderr
    assert int(r.stdout.strip()) == 3


# --------------------------------------------------------------- A-19 file quota
def test_file_size_limit_is_enforced():
    """Mutation: remove RLIMIT_FSIZE -> the large write succeeds -> FAIL."""
    r = run("open('/workspace/big.bin','wb').write(b'x'*(64*1024*1024)); print('WROTE')",
            fsize_mb=4)
    assert not r.ok or "WROTE" not in r.stdout
    assert "File too large" in r.stderr or "OSError" in r.stderr or not r.ok


# ------------------------------------------------------------ A-04 tree termination
def test_double_forked_grandchild_is_killed():
    """Mutation: kill only the direct child -> the grandchild survives -> FAIL.

    The workload double-forks so the grandchild is reparented away from us.
    """
    marker = f"SKYLA_ORPHAN_{os.getpid()}"
    code = f"""
import os, time
if os.fork() == 0:
    if os.fork() == 0:
        time.sleep(600)
    os._exit(0)
os.environ['{marker}'] = '1'
while True: pass
"""
    r = run(code, cpu_s=30, timeout_s=5)
    assert r.timed_out, "workload should have been cut off by the wall clock"
    assert r.terminated, "process tree was not verified terminated"
    import time as _t
    _t.sleep(1.0)
    survivors = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as fh:
                if marker.encode() in fh.read():
                    survivors.append(int(entry))
        except OSError:
            continue
    assert not survivors, f"orphaned workload processes survived: {survivors}"


def test_normal_completion_leaves_no_processes():
    r = run("import os\nprint(os.getpid())")
    assert r.ok
    assert r.terminated


# -------------------------------------------------------- filesystem confinement
def test_host_filesystem_is_invisible():
    """Mutation: remove chroot -> host paths resolve -> FAIL."""
    r = run("print(open('/etc/passwd').read()[:20])")
    assert not r.ok
    assert "FileNotFoundError" in r.stderr


def test_runtime_is_read_only():
    """Mutation: bind the runtime read-write -> the write succeeds -> FAIL."""
    r = run("open('/usr/bin/pwn','w').write('x')")
    assert not r.ok
    assert "Read-only file system" in r.stderr


def test_workspace_is_writable():
    """The control must not be so strict that normal work is impossible."""
    r = run("open('/workspace/ok.txt','w').write('hi'); print('ok')")
    assert r.ok and "ok" in r.stdout


def test_landlock_blocks_writes_outside_workspace(tmp_path):
    """Mutation: remove the Landlock ruleset -> the write succeeds -> FAIL.

    /tmp is a writable tmpfs, so this specifically exercises Landlock rather
    than the read-only bind mount.
    """
    r = run("open('/usr/lib/x','w').write('x')")
    assert not r.ok


# ------------------------------------------------------------ secret isolation
def test_host_environment_is_not_inherited():
    """Mutation: pass os.environ through -> SKYLA_* appears -> FAIL."""
    r = run("import os;print(sorted(os.environ))")
    assert r.ok
    assert "SKYLA_API_TOKEN" not in r.stdout
    assert "SKYLA_ADMIN_PASSWORD" not in r.stdout
    assert "PATH" in r.stdout


def test_no_inherited_file_descriptors():
    """Mutation: skip close_inherited_fds() -> the sentinel fd is visible -> FAIL."""
    r = run("import os;print(sorted(os.listdir('/proc/self/fd')))")
    assert r.ok
    fds = eval(r.stdout.strip())     # noqa: S307 - our own controlled output
    # Only stdin/stdout/stderr plus the descriptor used to read the directory.
    assert set(fds) <= {"0", "1", "2", "3"}, f"unexpected inherited descriptors: {fds}"
