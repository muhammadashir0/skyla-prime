"""EXEC-01: local execution must not inherit host networking (v0.2.5).

The defect these tests exist to prevent: `sandbox.run_python` used to execute the
child in the **host** network namespace while its docstring claimed "no network".
Nothing enforced the claim.

Two classes of assertion, deliberately separated:

* **Isolation assertions** — a workload cannot reach the internet, host loopback
  services, private networks or the metadata plane, including from subprocesses
  and after DNS resolution. These run anywhere `unshare -n` works.
* **Honesty assertions** — when isolation cannot be verified, execution must be
  REFUSED and must not report `verified: true`. These are the ones that matter
  most, because the original defect was a false claim rather than a broken
  control: the code ran fine and simply was not isolated.

A refusal is asserted to leave `stdout` empty, because a refused workload that
still ran would be the original bug wearing a different message.
"""
from __future__ import annotations

import pytest

from skyla.execution import sandbox
from skyla.execution.providers import RestrictedProvider, NamespaceProvider

needs_unshare = pytest.mark.skipif(
    not sandbox.shutil.which("unshare"),
    reason="unshare(1) unavailable; local isolation cannot be established on this host")


# --------------------------------------------------------------- isolation

NETWORK_REACHES = {
    "public_dns": "import socket\nsocket.create_connection(('1.1.1.1', 53), 3)",
    "host_loopback_egress_proxy": "import socket\nsocket.create_connection(('127.0.0.1', 8155), 3)",
    "metadata_plane": "import socket\nsocket.create_connection(('169.254.169.254', 80), 3)",
    "perimeter_gateway": "import socket\nsocket.create_connection(('10.201.0.2', 8155), 3)",
    "private_network": "import socket\nsocket.create_connection(('10.0.0.1', 80), 3)",
    "dns_resolution": "import socket\nsocket.getaddrinfo('pypi.org', 443)",
    "subprocess_child": (
        "import subprocess, sys\n"
        "subprocess.run([sys.executable, '-c', "
        "'import socket; socket.create_connection((\"1.1.1.1\",53),3)'], check=True)"),
    "socket_direct": (
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.settimeout(3)\n"
        "s.connect(('1.1.1.1', 53))"),
}


@needs_unshare
@pytest.mark.parametrize("case", sorted(NETWORK_REACHES))
def test_a_local_workload_cannot_reach_the_network(case):
    """Every path out of the sandbox is blocked, not just the convenient one.

    Parametrising by case means a regression names the exact vector that leaked
    rather than reporting a generic "network test failed".
    """
    result = sandbox.run_python(NETWORK_REACHES[case], timeout_s=20)
    assert result.get("isolation", {}).get("verified") is True, \
        f"isolation was not verified; result={result}"
    assert result["ok"] is False, f"{case} REACHED the network from the sandbox"
    assert "REACHED" not in result["stdout"]


@needs_unshare
def test_the_sandbox_namespace_has_no_default_route():
    """A route table with a default entry means traffic has somewhere to go."""
    probe = sandbox.verification_probe()
    for line in (probe.get("routes") or "").splitlines()[1:]:
        fields = line.split()
        assert len(fields) <= 1 or fields[1] != "00000000", \
            f"sandbox namespace has a default route: {line}"


@needs_unshare
def test_ordinary_code_still_runs_inside_the_sandbox():
    """Isolation must not be achieved by breaking execution."""
    result = sandbox.run_python("print(6 * 7)")
    assert result["ok"] is True
    assert result["stdout"].strip() == "42"
    assert result["isolation"]["verified"] is True


@needs_unshare
def test_the_sandbox_reports_its_own_isolation_state():
    status = sandbox.isolation_status()
    assert status["verified"] is True
    assert status["has_default_route"] is False
    assert status["reachable"] == []


# ---------------------------------------------------------------- honesty

def test_an_unverifiable_boundary_refuses_execution(monkeypatch):
    """If the probe cannot run, the workload must not run either.

    This is the core lesson: "we could not prove isolation" and "we are isolated"
    are different statements, and only one of them is safe to act on.
    """
    def broken():
        raise sandbox.IsolationUnavailable("simulated: probe failed")

    monkeypatch.setattr(sandbox, "verification_probe", broken)
    result = sandbox.run_python("print('should not run')")
    assert result["ok"] is False
    assert result.get("refused") is True
    assert "should not run" not in result["stdout"]
    assert result["isolation"]["verified"] is False


def test_a_reachable_target_refuses_execution(monkeypatch):
    """A deny target that responded means the boundary does not hold."""
    monkeypatch.setattr(sandbox, "verification_probe",
                        lambda: {"control": True, "reachable": ["1.1.1.1:53"],
                                 "routes": "", "interfaces": ""})
    result = sandbox.run_python("print('should not run')")
    assert result["ok"] is False and result.get("refused") is True
    assert "should not run" not in result["stdout"]


def test_a_failed_host_control_refuses_execution(monkeypatch):
    """No positive control means a 'blocked' reading proves nothing.

    Without this, a host whose networking is simply down would report perfect
    isolation — the failure mode that made the v0.2.3 perimeter proof worthless.
    """
    monkeypatch.setattr(sandbox, "verification_probe",
                        lambda: {"control": False, "reachable": [],
                                 "routes": "", "interfaces": ""})
    result = sandbox.run_python("print('should not run')")
    assert result["ok"] is False and result.get("refused") is True
    assert "cannot be verified" in result["stderr"]


def test_a_default_route_refuses_execution(monkeypatch):
    """Even with all deny targets unreachable, a default route is a failure."""
    route = ("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
             "eth0\t00000000\t0102A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n")
    monkeypatch.setattr(sandbox, "verification_probe",
                        lambda: {"control": True, "reachable": [], "routes": route,
                                 "interfaces": "eth0 lo"})
    result = sandbox.run_python("print('should not run')")
    assert result["ok"] is False and result.get("refused") is True
    assert "default route" in result["stderr"]


# --------------------------------------------------------------- provider

def test_the_local_provider_refuses_network_enabled_execution():
    """No authorised egress path is wired to local execution, so deny it."""
    result = RestrictedProvider().run("print(1)", network=True)
    assert result["ok"] is False and result.get("refused") is True
    assert "deny by default" in result["stderr"]


def test_the_local_provider_does_not_claim_to_be_safe_for_untrusted_code():
    """Network confinement alone is not the full boundary.

    The namespace provider adds seccomp, Landlock and PID-namespace termination.
    The local provider has none of those, so it must not be advertised as
    equivalent — a weaker control reported as strong is how EXEC-01 survived.
    """
    provider = RestrictedProvider()
    assert provider.safe_for_untrusted is False
    assert provider.status()["safe_for_untrusted"] is False
    assert "weaker_than" in provider.status()


@needs_unshare
def test_the_local_provider_reports_its_verified_isolation():
    status = RestrictedProvider().status()
    assert status["network_isolation"]["verified"] is True
    assert status["isolated"] is True


def test_the_namespace_provider_still_refuses_network_execution():
    """The strong provider keeps its original deny-by-default behaviour."""
    result = NamespaceProvider().run("print(1)", network=True)
    assert result["ok"] is False
    assert "deny by default" in result["stderr"]


# ------------------------------------------- firewall / proxy composition
def test_local_isolation_does_not_depend_on_the_host_firewall_state():
    """EXEC-01 isolation must hold with the host firewall in EITHER state.

    Why this test exists: v0.2.5 measured that the host default-deny firewall and
    the egress proxy's own upstream connectivity are mutually exclusive on this
    kernel (the proxy runs in the host netns, the `owner` match extension is
    absent, and no rule excepts its upstream). The consequence is that the
    firewall blocks the proxy itself, so no authorised egress succeeds while the
    firewall is active.

    That finding is about the *authorised* path. The *denied* path — the sandbox —
    must be independent of it, or disabling the firewall to restore provider
    access would silently un-isolate local execution. This test asserts the
    sandbox stays isolated on its own, without relying on netfilter.
    """
    if not sandbox.shutil.which("unshare"):
        pytest.skip("unshare unavailable; local isolation cannot be established")
    result = sandbox.run_python(
        "import socket\nsocket.create_connection(('1.1.1.1', 53), 3)", timeout_s=20)
    assert result["ok"] is False
    assert result["isolation"]["verified"] is True
    assert "REACHED" not in result["stdout"]
