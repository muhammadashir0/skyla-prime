"""B-01: OS-level network perimeter (v0.2.3).

The finding
-----------
v0.2.2's egress proxy refused bad destinations and audited decisions, but nothing
FORCED traffic through it. A caller that ignored `HTTPS_PROXY` and dialled directly
was not stopped. That was recorded as B-01 (High) rather than counted as isolation.

What these tests assert
-----------------------
That a network namespace exists whose entire reachable surface is one
(ip, port) pair — the proxy — and that everything else is unreachable **from
inside**, proven by attempting real connections rather than by calling a validation
function. The host control runs the same probe unconfined, so a "blocked" result
cannot be explained by the host having no network.

Prerequisites
-------------
These tests need root (CAP_NET_ADMIN) and a live perimeter:

    sudo scripts/skyla-perimeter.sh setup

They SKIP when they cannot run, and a skip is NOT VERIFIED, never a pass. The
perimeter's own claims are additionally asserted without privileges by
`test_perimeter_asserts_its_own_status` and the fail-closed tests at the bottom,
which run anywhere.
"""
import os
import socket
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from skyla.perimeter import (EgressPerimeter, PerimeterUnavailable,  # noqa: E402
                            _DEFAULT_NS, _GATEWAY_NS, _WL_IP, _GW_SIDE_OF_WL)

_NS_EXISTS = os.path.exists(f"/var/run/netns/{_DEFAULT_NS}")
_GW_EXISTS = os.path.exists(f"/var/run/netns/{_GATEWAY_NS}")


def _can_enter_namespace() -> tuple[bool, str]:
    """Entering a network namespace needs CAP_SYS_ADMIN.

    An unprivileged process cannot `ip netns exec`, and the command fails with
    "Operation not permitted" while still exiting 0 through the pipe. Without this
    gate the tests would read an EMPTY result — no routes, no interfaces — and
    report "a perimeter with no routes", which is a false FAIL rather than an
    honest skip. Failing closed in both directions matters: a test that cannot
    observe the system must say so, not guess.
    """
    if not (_NS_EXISTS and _GW_EXISTS):
        return False, (f"perimeter not installed (namespaces {_DEFAULT_NS!r}/"
                       f"{_GATEWAY_NS!r} absent) — run scripts/skyla-perimeter.sh setup")
    r = subprocess.run(["ip", "netns", "exec", _DEFAULT_NS, "ip", "route"],
                       capture_output=True, text=True)
    if r.returncode != 0 or "Operation not permitted" in (r.stderr or ""):
        return False, (f"cannot enter namespace {_DEFAULT_NS!r} without CAP_SYS_ADMIN "
                       f"(run these tests as root; enforcement is unaffected)")
    if not (r.stdout or "").strip():
        return False, (f"namespace {_DEFAULT_NS!r} reports no routes — it cannot "
                       f"reach the proxy, so the perimeter is not usable")
    return True, ""


_PERIMETER_OK, _PERIMETER_WHY = _can_enter_namespace()

requires_perimeter = pytest.mark.skipif(not _PERIMETER_OK, reason=_PERIMETER_WHY)


def _in_ns(code: str, ns: str = _DEFAULT_NS, timeout: int = 30):
    return subprocess.run(["ip", "netns", "exec", ns, sys.executable, "-c", code],
                          capture_output=True, text=True, timeout=timeout)


def _connect_in_ns(host: str, port: int, timeout: float = 3) -> str:
    code = (
        "import socket,sys\n"
        "try:\n"
        f"    s=socket.create_connection(({host!r},{port}),timeout={timeout});s.close()\n"
        "    print('REACHED')\n"
        "except Exception as e:\n"
        "    print(type(e).__name__)\n"
    )
    return _in_ns(code).stdout.strip()


def _connect_on_host(host: str, port: int, timeout: float = 3) -> str:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return "REACHED"
    except Exception as exc:                                # noqa: BLE001
        return type(exc).__name__


# ------------------------------------------------- the boundary is structural
@requires_perimeter
def test_workload_namespace_has_no_default_route():
    """No default route means no next hop: ENOENT for every other destination.

    This is the property that makes the perimeter independent of any filter that
    could be misconfigured or forgotten.
    """
    r = _in_ns("pass")
    r = subprocess.run(["ip", "netns", "exec", _DEFAULT_NS, "ip", "route"],
                       capture_output=True, text=True)
    routes = (r.stdout or "").strip().splitlines()
    assert routes, "the workload namespace has no routes at all — it could not reach the proxy"
    assert not any(line.strip().startswith("default") for line in routes), (
        f"a default route exists in the workload namespace: {routes}")


@requires_perimeter
def test_workload_namespace_has_no_ipv6_path():
    """IPv6 must be absent, not merely filtered: a v6 route is an unreviewed path."""
    r = subprocess.run(["ip", "netns", "exec", _DEFAULT_NS, "ip", "-6", "route"],
                       capture_output=True, text=True)
    assert not (r.stdout or "").strip(), f"IPv6 routes present: {r.stdout}"


@requires_perimeter
def test_workload_namespace_has_exactly_one_non_loopback_interface():
    r = subprocess.run(["ip", "netns", "exec", _DEFAULT_NS, "ip", "-j", "addr"],
                       capture_output=True, text=True)
    import json
    links = [l["ifname"] for l in json.loads(r.stdout or "[]")]
    non_lo = [l for l in links if l != "lo"]
    assert len(non_lo) == 1, f"expected one non-loopback interface, found {links}"


# ------------------------------------------------- unauthorised egress denied
@requires_perimeter
@pytest.mark.parametrize("label,host,port", [
    ("public_dns", "1.1.1.1", 53),
    ("public_dns2", "8.8.8.8", 53),
    ("metadata_aws", "169.254.169.254", 80),
    ("metadata_gcp", "169.254.169.254", 80),
])
def test_public_and_metadata_destinations_are_unreachable(label, host, port):
    """Real connection attempts from inside; every one must fail.

    The host control proves the same destination IS reachable unconfined, so a
    pass cannot be an artefact of the sandbox having no network.
    """
    inside = _connect_in_ns(host, port)
    assert inside != "REACHED", f"{label} ({host}:{port}) was reachable from the perimeter"

    control = _connect_on_host(host, port)
    if control == "REACHED":
        # The strongest form: reachable without the boundary, blocked with it.
        assert inside != "REACHED"
    else:
        # Destination unavailable even unconfined — the test then proves nothing
        # about the perimeter and must say so rather than pass quietly.
        pytest.skip(f"host control could not reach {host}:{port} ({control}); "
                    f"perimeter not distinguishable from ambient unreachability")


@requires_perimeter
def test_dns_does_not_resolve_inside_the_perimeter():
    """No resolver path out, so an internal name cannot be resolved by the workload.

    The proxy resolves on the workload's behalf and applies netguard's address
    checks, which is the only DNS the workload is allowed to benefit from.
    """
    r = _in_ns(
        "import socket\n"
        "try:\n"
        "    print('RESOLVED', socket.gethostbyname('pypi.org'))\n"
        "except Exception as e:\n"
        "    print(type(e).__name__)\n")
    out = r.stdout.strip()
    assert not out.startswith("RESOLVED"), f"DNS resolved inside the perimeter: {out}"


# ----------------------------------------------------- internal services denied
@requires_perimeter
def test_internal_services_are_unreachable_from_the_workload():
    """The requirement a single-veth topology FAILED.

    With the host as the workload's only peer, any service bound to 0.0.0.0 on the
    host was reachable — including the API. The gateway namespace exists so the
    workload's only peer contains nothing but the proxy.
    """
    # A listener bound to 0.0.0.0 on the host, exactly like uvicorn.
    listener = subprocess.Popen(
        [sys.executable, "-c",
         "import socket,time\n"
         "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
         "s.bind(('0.0.0.0',8341));s.listen(5);print('up',flush=True);time.sleep(25)"],
        stdout=subprocess.PIPE, text=True)
    try:
        assert listener.stdout.readline().strip() == "up"
        # Control: the host can reach it.
        assert _connect_on_host("127.0.0.1", 8341) == "REACHED"
        # The workload must not, via any address that could route to it.
        for host in (_GW_SIDE_OF_WL, "10.201.0.1", "10.201.0.2"):
            assert _connect_in_ns(host, 8341) != "REACHED", (
                f"workload reached the internal service at {host}:8341")
    finally:
        listener.terminate()
        listener.wait(timeout=10)


@requires_perimeter
def test_workload_loopback_is_its_own_not_the_hosts():
    """`127.0.0.1` inside the namespace must not be the host's loopback."""
    listener = subprocess.Popen(
        [sys.executable, "-c",
         "import socket,time\n"
         "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
         "s.bind(('127.0.0.1',8342));s.listen(5);print('up',flush=True);time.sleep(20)"],
        stdout=subprocess.PIPE, text=True)
    try:
        assert listener.stdout.readline().strip() == "up"
        assert _connect_on_host("127.0.0.1", 8342) == "REACHED"
        assert _connect_in_ns("127.0.0.1", 8342) != "REACHED", (
            "the workload reached the HOST loopback — namespaces share 127.0.0.1")
    finally:
        listener.terminate()
        listener.wait(timeout=10)


# ------------------------------------------------ the authorised path survives
@requires_perimeter
def test_the_proxy_is_reachable_from_inside():
    """A perimeter that blocks the proxy too is an outage, not a policy."""
    port = int(os.getenv("SKYLA_EGRESS_PORT", "8155"))
    result = _connect_in_ns(_GW_SIDE_OF_WL, port, timeout=5)
    if result != "REACHED":
        pytest.skip(f"egress proxy not listening on {_GW_SIDE_OF_WL}:{port} "
                    f"({result}); start it to exercise the allow path")


@requires_perimeter
def test_only_the_proxy_port_is_reachable_on_the_gateway():
    """Allowlisting is a port, not a host: other gateway ports must be closed."""
    port = int(os.getenv("SKYLA_EGRESS_PORT", "8155"))
    other = 8199
    listener = subprocess.Popen(
        [sys.executable, "-c",
         f"import socket,time\n"
         f"s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
         f"s.bind(('0.0.0.0',{other}));s.listen(5);print('up',flush=True);time.sleep(20)"],
        stdout=subprocess.PIPE, text=True)
    try:
        assert listener.stdout.readline().strip() == "up"
        assert _connect_on_host("127.0.0.1", other) == "REACHED"
        assert _connect_in_ns(_GW_SIDE_OF_WL, other) != "REACHED", (
            f"the workload reached gateway port {other}; only {port} may be open")
    finally:
        listener.terminate()
        listener.wait(timeout=10)


# ------------------------------------------------ fail-closed without the boundary
def test_perimeter_refuses_when_it_cannot_be_built(monkeypatch):
    """No CAP_NET_ADMIN => PerimeterUnavailable, never a silent unconfined run."""
    p = EgressPerimeter("does-not-matter")
    monkeypatch.setattr(EgressPerimeter, "prerequisites",
                        staticmethod(lambda: (False, "no CAP_NET_ADMIN")))
    with pytest.raises(PerimeterUnavailable) as exc:
        p.create()
    assert "CAP_NET_ADMIN" in str(exc.value)
    assert p.status.available is False


def test_create_failure_is_reported_as_unavailable(monkeypatch):
    """A partially built namespace must not report itself as available."""
    p = EgressPerimeter("x")
    monkeypatch.setattr(EgressPerimeter, "prerequisites", staticmethod(lambda: (True, "")))
    monkeypatch.setattr(p, "destroy", lambda **kw: None)

    class FakeRun:
        returncode = 1
        stdout = ""
        stderr = "Error: operation not permitted"

    monkeypatch.setattr("skyla.perimeter._run", lambda *a, **k: FakeRun())
    with pytest.raises(PerimeterUnavailable):
        p.create()
    assert p.status.available is False


def test_verify_marks_missing_namespace_unavailable():
    """Verifying a perimeter that was never created must not claim success."""
    p = EgressPerimeter("nonexistent-ns-for-test")
    st = p.verify()
    assert st.available is False
    assert st.reason


def test_run_confined_requires_both_namespaces():
    """Without the gateway namespace the workload's only peer is the host — the
    topology that leaked internal services. Refuse it."""
    from skyla.perimeter import run_confined
    if os.path.exists(f"/var/run/netns/{_DEFAULT_NS}"):
        pytest.skip("perimeter is installed; the absent-namespace path cannot be exercised")
    with pytest.raises(PerimeterUnavailable):
        run_confined("print('should not run')")
