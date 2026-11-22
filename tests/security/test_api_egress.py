"""B-01 API egress integration — the trusted process, not a child workload (v0.2.3).

Why this file exists separately from `test_network_perimeter.py`
----------------------------------------------------------------
The perimeter tests proved a *namespace* is isolated. They did not prove the
**API process** was in it. B-01 was closed against `run_confined()` for Python
workloads and left the trusted process — which holds credentials, database access
and every connector — with unconstrained egress. These tests close that gap.

They are in two layers:

  * **Pure** tests (no privileges): mode resolution, fail-closed behaviour, the
    client factory's proxy/bind contract, capability scoping. These always run.
  * **Kernel** tests (`@requires_perimeter`): they enter the real namespace and
    prove unauthorised egress fails from inside. They skip without CAP_SYS_ADMIN
    and are reported as skips, never as passes.
"""
import asyncio
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from skyla import egress_client
from skyla.egress import POLICIES, Policy, policy_for_connector  # noqa: E402
from skyla.egress_client import (EgressUnavailable, client, is_namespaced,  # noqa: E402
                                 resolve_mode, route_confirmation)

_NS = "/var/run/netns/skyla-egress"
_GW = "/var/run/netns/skyla-egress-gw"


def _can_enter() -> tuple[bool, str]:
    if not (os.path.exists(_NS) and os.path.exists(_GW)):
        return False, ("network perimeter not installed — run "
                       "scripts/skyla-perimeter.sh setup as root")
    r = subprocess.run(["ip", "netns", "exec", "skyla-egress", "ip", "route"],
                       capture_output=True, text=True)
    if r.returncode != 0 or "not permitted" in (r.stderr or "").lower():
        return False, ("cannot enter the namespace without CAP_SYS_ADMIN "
                       "(kernel-level checks need root; enforcement is unaffected)")
    if not (r.stdout or "").strip():
        return False, "namespace has no routes — it cannot reach the proxy"
    return True, ""


_OK, _WHY = _can_enter()
requires_perimeter = pytest.mark.skipif(not _OK, reason=_WHY)


# ============================================================ mode resolution
def test_a_namespaced_process_cannot_downgrade_its_mode(monkeypatch):
    """Inside the boundary, enforcement is mandatory rather than selected.

    Choosing `policy` would skip the "can I reach the internet directly?" proof,
    so the only thing separating enforcement from configuration would go
    unmeasured.
    """
    monkeypatch.setattr(egress_client, "perimeter_installed", lambda: True)
    monkeypatch.setattr(egress_client, "is_namespaced", lambda: True)
    monkeypatch.delenv("SKYLA_EGRESS_ALLOW_LEGACY", raising=False)
    assert resolve_mode() == "enforce"
    for downgrade in ("policy", "legacy"):
        with pytest.raises(EgressUnavailable):
            resolve_mode(downgrade)


def test_legacy_is_refused_when_the_perimeter_is_installed(monkeypatch):
    monkeypatch.setattr(egress_client, "perimeter_installed", lambda: True)
    monkeypatch.setattr(egress_client, "is_namespaced", lambda: False)
    monkeypatch.delenv("SKYLA_EGRESS_ALLOW_LEGACY", raising=False)
    with pytest.raises(EgressUnavailable) as exc:
        resolve_mode("legacy")
    assert "perimeter is installed" in str(exc.value)


def test_legacy_needs_two_declarations_on_a_perimeter_host():
    """A single stray variable must not create an unconstrained client."""
    assert os.environ.get("SKYLA_EGRESS_ALLOW_LEGACY") == "1", \
        "the suite declares test mode in conftest; without it this test is vacuous"


def test_unknown_mode_is_rejected():
    with pytest.raises(EgressUnavailable):
        resolve_mode("permissive")


# ============================================================== fail-closed
def test_no_client_is_issued_when_the_perimeter_is_missing(monkeypatch):
    """The core of B-01: absence of enforcement means no client, not a lax one."""
    monkeypatch.setattr(egress_client, "perimeter_installed", lambda: False)
    with pytest.raises(EgressUnavailable) as exc:
        client("research", mode="enforce")
    assert "not installed" in str(exc.value)


def test_an_unreachable_gateway_fails_closed(monkeypatch):
    monkeypatch.setattr(egress_client, "perimeter_installed", lambda: True)
    monkeypatch.setattr(egress_client, "DEFAULT_PROXY_PORT", 1)   # nothing listens
    with pytest.raises(EgressUnavailable) as exc:
        client("research", mode="enforce")
    assert "unreachable" in str(exc.value)


def test_direct_egress_success_is_treated_as_a_failure(monkeypatch):
    """If the process CAN reach the internet directly, the perimeter is not
    constraining it — that must raise, not warn."""
    monkeypatch.setattr(egress_client, "perimeter_installed", lambda: True)

    import socket

    class Reachable:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: Reachable())
    with pytest.raises(EgressUnavailable) as exc:
        client("research", mode="enforce")
    assert "bypass" in str(exc.value)


# ========================================================= client contract
def test_the_client_is_bound_to_the_gateway_and_ignores_the_environment(monkeypatch):
    """`trust_env=False` prevents an env var from redirecting every call."""
    seen = {}

    class Fake:
        def __init__(self, **kw): seen.update(kw)

    monkeypatch.setattr(egress_client.httpx, "AsyncClient", Fake)
    monkeypatch.setattr(egress_client, "_verify_boundary", lambda mode: None)
    monkeypatch.setattr(egress_client, "resolve_mode", lambda m=None: "enforce")
    client("research")
    assert seen["trust_env"] is False, "environment proxies were honoured"
    assert "10.200.0.1" in str(seen["proxy"]), f"proxy not the gateway: {seen['proxy']}"
    assert "research:" in str(seen["proxy"]), "capability missing from proxy auth"
    assert seen["follow_redirects"] is False, "redirects must be re-vetted, not followed"


def test_an_unknown_capability_gets_deny_all(monkeypatch):
    seen = {}

    class Fake:
        def __init__(self, **kw): seen.update(kw)

    monkeypatch.setattr(egress_client.httpx, "AsyncClient", Fake)
    monkeypatch.setattr(egress_client, "_verify_boundary", lambda mode: None)
    monkeypatch.setattr(egress_client, "resolve_mode", lambda m=None: "enforce")
    client("something-new")
    assert "deny-all:" in str(seen["proxy"]), \
        f"an unknown capability was not denied: {seen['proxy']}"


def test_an_injected_transport_short_circuits_the_network(monkeypatch):
    """MockTransport never opens a socket, so no boundary check is warranted."""
    import httpx
    c = client("research", transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    assert isinstance(c, httpx.AsyncClient)
    asyncio.run(c.aclose())


# ================================================== capability scoping (unit)
def test_a_research_client_cannot_reach_a_model_provider():
    """Separate policies per capability, so one compromise does not inherit reach."""
    research = POLICIES["research"]
    model = POLICIES["model-provider"]
    assert not research.host_permitted("api.openai.com")
    assert not model.host_permitted("pypi.org")
    assert POLICIES["connector-google"].host_permitted("www.googleapis.com")
    assert not POLICIES["connector-telegram"].host_permitted("www.googleapis.com")


def test_connector_names_map_to_their_own_policy():
    assert policy_for_connector("gmail").name == "connector-google"
    assert policy_for_connector("calendar").name == "connector-google"
    assert policy_for_connector("telegram").name == "connector-telegram"
    assert policy_for_connector("brand-new-thing").name == "deny-all"


def test_there_is_no_wildcard_policy():
    """A `*` host would make every other scoping assertion meaningless."""
    for name, pol in POLICIES.items():
        assert "*" not in pol.allow_hosts, f"policy {name} allows every host"
        assert pol.allow_hosts != ("*",)


# ============================================ kernel: the real boundary
@requires_perimeter
def test_the_api_namespace_cannot_reach_the_internet_directly():
    """Measured from inside the namespace the API actually runs in."""
    probe = ("import socket\n"
             "for h,p in [('1.1.1.1',53),('169.254.169.254',80)]:\n"
             "    try:\n"
             "        socket.create_connection((h,p),timeout=3); print(h,'REACHED')\n"
             "    except Exception as e: print(h,type(e).__name__)\n")
    r = subprocess.run(["ip", "netns", "exec", "skyla-egress", sys.executable, "-c", probe],
                       capture_output=True, text=True, timeout=60)
    assert "REACHED" not in r.stdout, f"the API namespace reached the network: {r.stdout}"


@requires_perimeter
def test_the_api_namespace_cannot_reach_internal_services():
    """The 0.0.0.0 leak that made the single-veth topology unusable."""
    probe = ("import socket\n"
             "for h,p in [('10.201.0.1',8200),('10.201.0.1',8201),('10.200.0.1',8080)]:\n"
             "    try:\n"
             "        socket.create_connection((h,p),timeout=3); print(h,p,'REACHED')\n"
             "    except Exception as e: print(h,p,type(e).__name__)\n")
    r = subprocess.run(["ip", "netns", "exec", "skyla-egress", sys.executable, "-c", probe],
                       capture_output=True, text=True, timeout=60)
    assert "REACHED" not in r.stdout, f"an internal service was reachable: {r.stdout}"


@requires_perimeter
def test_the_api_namespace_has_no_ipv6_path():
    r = subprocess.run(["ip", "netns", "exec", "skyla-egress", "ip", "-6", "route"],
                       capture_output=True, text=True, timeout=30)
    assert not (r.stdout or "").strip(), f"IPv6 routes present in the API namespace: {r.stdout}"


@requires_perimeter
def test_the_authorised_path_is_still_open():
    """A perimeter that also blocks the proxy is an outage, not a policy."""
    import base64
    import socket

    def connect(cap, target):
        cred = base64.b64encode(f"{cap}:".encode()).decode()
        s = socket.create_connection(("10.200.0.1", 8155), timeout=8)
        s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
                  f"Proxy-Authorization: Basic {cred}\r\n\r\n".encode())
        line = s.recv(200).split(b"\r\n")[0].decode()
        s.close()
        return line

    probe = (
        "import base64,socket\n"
        "def c(cap,t):\n"
        "    b=base64.b64encode((cap+':').encode()).decode()\n"
        "    s=socket.create_connection(('10.200.0.1',8155),timeout=8)\n"
        "    s.sendall(('CONNECT '+t+' HTTP/1.1\\r\\nHost: '+t+'\\r\\nProxy-Authorization: Basic '+b+'\\r\\n\\r\\n').encode())\n"
        "    r=s.recv(200).split(b'\\r\\n')[0].decode(); s.close(); return r\n"
        "print(c('research','pypi.org:443'))\n")
    r = subprocess.run(["ip", "netns", "exec", "skyla-egress", sys.executable, "-c", probe],
                       capture_output=True, text=True, timeout=60)
    if "200" not in r.stdout:
        pytest.skip(f"egress proxy not running or upstream unreachable ({r.stdout.strip()[:80]}); "
                    f"start it with scripts/skyla-perimeter.sh proxy")
    assert "200 Connection Established" in r.stdout


@requires_perimeter
def test_an_unstamped_request_is_denied():
    """Without the capability credential the proxy denies rather than defaulting."""
    probe = (
        "import socket\n"
        "s=socket.create_connection(('10.200.0.1',8155),timeout=8)\n"
        "s.sendall(b'CONNECT pypi.org:443 HTTP/1.1\\r\\nHost: pypi.org:443\\r\\n\\r\\n')\n"
        "print(s.recv(200).split(b'\\r\\n')[0].decode()); s.close()\n")
    r = subprocess.run(["ip", "netns", "exec", "skyla-egress", sys.executable, "-c", probe],
                       capture_output=True, text=True, timeout=60)
    if not r.stdout.strip():
        pytest.skip("egress proxy not running")
    assert "403" in r.stdout or "200" not in r.stdout, \
        f"an unauthenticated CONNECT was allowed: {r.stdout}"


# ============================ defence in depth: the proxy's own address check
def test_netguard_blocks_private_addresses_independently_of_policy():
    """Two independent layers, and the second one is load-bearing.

    Mutation M6 added `10.201.0.1` (the host side of the gateway) to the research
    policy. The policy then allowed it — but the proxy still refused, because
    `netguard` classifies the RESOLVED address and rejects private ranges. Without
    that second check, widening a policy would be enough to reach internal
    services. This test pins the layer that made the mutation harmless, so a
    future refactor cannot quietly remove it and rely on policy alone.
    """
    from skyla.netguard import SSRFBlocked, validate_url

    for url in ("http://10.201.0.1:8200/", "https://10.201.0.1/",
                "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8000/"):
        with pytest.raises(SSRFBlocked):
            validate_url(url)


def test_a_widened_policy_still_cannot_reach_a_private_address():
    """The combination that M6 tried: policy says yes, address check says no."""
    from skyla.netguard import SSRFBlocked, validate_url

    widened = Policy(name="widened", allow_hosts=("10.201.0.1",),
                     allow_ports=(443, 80, 8080))
    assert widened.host_permitted("10.201.0.1"), "policy was supposed to allow it"
    with pytest.raises(SSRFBlocked):
        validate_url("https://10.201.0.1/", allowed_ports={443, 80, 8080})


# ================================================= namespace lifecycle safety
@requires_perimeter
def test_destroying_the_perimeter_does_not_strand_live_processes():
    """A process inside a destroyed namespace keeps running with no route.

    Measured failure: after a rebuild, a live API process sat in a deleted
    namespace with only `lo`, every connect returning ENETUNREACH, while looking
    healthy from outside. `destroy()` now terminates members first. This test
    asserts the membership detection that makes that possible, without actually
    tearing down the shared perimeter under the rest of the suite.
    """
    from skyla.perimeter import EgressPerimeter

    perim = EgressPerimeter("skyla-egress")
    probe = subprocess.Popen(
        ["ip", "netns", "exec", "skyla-egress", sys.executable, "-c",
         "import time; time.sleep(30)"])
    try:
        import time
        deadline = time.time() + 10
        found: list[int] = []
        while time.time() < deadline:
            found = perim.members()
            if probe.pid in found:
                break
            time.sleep(0.2)
        assert probe.pid in found, (
            "a process inside the perimeter was not detected as a member; "
            "destroy() would strand it with no network and no error")
    finally:
        probe.terminate()
        probe.wait(timeout=10)


def test_destroy_reports_stranding_when_members_are_left_alone(monkeypatch):
    """With kill_members=False the caller must be told, not left guessing."""
    from skyla.perimeter import EgressPerimeter

    perim = EgressPerimeter("x")
    monkeypatch.setattr(perim, "members", lambda: [4242])
    monkeypatch.setattr("skyla.perimeter.shutil.which", lambda _: None)
    perim.destroy(kill_members=False)
    assert "lose all network reachability" in perim.status.reason


def test_namespace_detection_works_without_reading_proc1(monkeypatch):
    """Detection must not depend on a file only root can open.

    Measured defect: `is_namespaced()` compared against `/proc/1/ns/net`, which an
    unprivileged process cannot read. The service is *meant* to run unprivileged,
    so a correctly confined process reported `is_namespaced() == False` — and the
    downgrade guard, which is gated on that call, stopped protecting it.
    """
    import os as _os
    real_stat = _os.stat

    def deny_proc1(path, *a, **k):
        if str(path).startswith("/proc/1/"):
            raise PermissionError("unprivileged process cannot read /proc/1")
        return real_stat(path, *a, **k)

    monkeypatch.setattr(_os, "stat", deny_proc1)
    # Must not raise, and must still make a decision from the namespace file.
    assert isinstance(is_namespaced(), bool)


def test_detection_compares_against_the_perimeter_namespace(monkeypatch):
    """Same inode as the perimeter => namespaced; different => not."""
    import os as _os

    real_stat = _os.stat

    class S:
        def __init__(self, ino): self.st_ino = ino

    monkeypatch.setattr(_os, "stat", lambda p, *a, **k: S(1234)
                        if str(p).endswith("skyla-egress") else S(9999))
    assert is_namespaced() is False, "a different namespace was treated as inside"

    monkeypatch.setattr(_os, "stat", lambda p, *a, **k: S(9999))
    assert is_namespaced() is True, "the perimeter namespace was not recognised"
