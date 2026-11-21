"""WS1 adversarial tests for the namespace execution provider."""
import pytest

from skyla.execution.providers import NamespaceProvider, get_execution_provider


@pytest.fixture(scope="module")
def provider():
    p = NamespaceProvider()
    if not p.status()["available"]:
        pytest.skip("unshare/chroot unavailable in this environment")
    return p


def test_provider_status_honest(provider):
    s = provider.status()
    assert s["provider"] == "namespace"
    assert s["isolated"] is True
    assert s["safe_for_untrusted"] is True


def test_basic_execution(provider):
    r = provider.run("print('isolated-ok')")
    assert r["ok"] and "isolated-ok" in r["stdout"]


def test_host_filesystem_invisible(provider):
    """Adversarial: host /etc/hostname must NOT be readable inside chroot."""
    r = provider.run("import os; print(os.path.exists('/etc/hostname'))")
    assert r["ok"] and "False" in r["stdout"]


def test_host_write_blocked(provider):
    """Adversarial: writes outside /workspace must fail."""
    r = provider.run("open('/etc/pwned','w').write('x')")
    assert not r["ok"]


def test_workspace_writable(provider):
    r = provider.run("open('/workspace/out.txt','w').write('hi'); print('wrote')")
    assert r["ok"] and "wrote" in r["stdout"]


def test_network_disabled_by_default(provider):
    """Adversarial: a REAL host listener must be unreachable from the sandbox."""
    import socket

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    srv.settimeout(0.5)
    try:
        code = f"""
import socket
s = socket.socket(); s.settimeout(3)
try:
    s.connect(('127.0.0.1', {port})); print('CONNECTED')
except OSError as e:
    print('BLOCKED', e.errno)
"""
        r = provider.run(code)
        # v0.3.0: socket() itself is denied by the seccomp allowlist, so the
        # isolation is stronger than "connection refused". Either way, no bytes
        # may reach the host listener.
        assert "CONNECTED" not in r["stdout"], r["stdout"]
        assert ("PermissionError" in r["stderr"] or "BLOCKED" in r["stdout"]
                or "not permitted" in r["stderr"]), (r["stdout"], r["stderr"])
        # no connection ever reached the host listener
        try:
            srv.accept()
            accepted = True
        except (socket.timeout, OSError):
            accepted = False
        assert accepted is False
    finally:
        srv.close()


def test_subprocess_contained(provider):
    """Subprocesses run inside the namespace (fake root, no host escape)."""
    r = provider.run("import subprocess; print(subprocess.run(['id'],capture_output=True,text=True).stdout)")
    assert r["ok"] and "uid=" in r["stdout"]


def test_memory_limit_enforced(provider):
    r = provider.run("x = bytearray(2*1024*1024*1024); print(len(x))", memory_mb=256)
    assert not r["ok"]


def test_timeout_enforced(provider):
    r = provider.run("while True: pass", timeout_s=2)
    assert not r["ok"] and "Timed out" in r["stderr"]


def test_output_capped(provider):
    r = provider.run("print('x'*50000)")
    assert len(r["stdout"]) <= 8000


def test_no_inherited_secrets(provider):
    r = provider.run("import os; print(sorted(os.environ.keys()))")
    assert r["ok"]
    assert "SKYLA_API_TOKEN" not in r["stdout"]
    assert "OPENAI_API_KEY" not in r["stdout"]


def test_default_provider_selection():
    p = get_execution_provider()
    assert p.name in ("namespace", "container", "restricted", "disabled")
    if p.name == "restricted":
        assert p.isolated is False  # never falsely claims isolation
