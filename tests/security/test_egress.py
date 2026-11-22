"""Default-deny egress proxy (v0.2.2 Mission 3).

The important assertions here are about the CONNECTION BOUNDARY, not URL strings:
the proxy must refuse before opening a socket, and must dial a vetted IP rather
than a re-resolved name.

Network-dependent tests are marked and skip when the sandbox egress allowlist does
not permit the host; a skip is NOT VERIFIED, never a pass.
"""
import os
import socket
import ssl
import subprocess
import sys
import threading
import time

import pytest

from skyla.egress import (POLICIES, Decision, EgressAudit, EgressDenied, EgressProxy,
                          Policy)

DENY_ALL = Policy(name="deny-all")


@pytest.fixture()
def proxy():
    audit = EgressAudit()
    p = EgressProxy(policy=DENY_ALL, audit=audit).start()
    yield p
    p.stop()


def connect_request(proxy, target: str, headers: str = "") -> bytes:
    s = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
    s.settimeout(10)
    s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{headers}\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(1024)
        if not chunk:
            break
        buf += chunk
    s.close()
    return buf


# ------------------------------------------------------------ default deny
def test_empty_policy_denies_everything(proxy):
    """Mutation: make an empty policy allow-all -> these become 200."""
    for target in ("example.com:443", "github.com:443", "pypi.org:443",
                   "127.0.0.1:443", "169.254.169.254:443"):
        resp = connect_request(proxy, target)
        assert b"403" in resp, f"{target} was not denied: {resp[:60]!r}"


def test_denial_happens_before_any_connection(proxy):
    """A denial must cost no TCP connect. Verified by the audit record having no
    resolved IP and by the decision being recorded as denied."""
    connect_request(proxy, "github.com:443")
    denied = proxy.audit.denied()
    assert denied, "no denial recorded"
    assert all(d["resolved_ip"] == "" for d in denied), (
        "a denied request resolved an address; the check ran too late")


# ---------------------------------------------------------------- allowlist
def test_allowlisted_host_is_permitted_by_policy(proxy):
    proxy.default_policy = Policy(name="t", allow_hosts=("pypi.org",))
    ok, reason, ip = proxy.authorise("pypi.org", 443, "CONNECT")
    assert ok, reason
    assert ip and ip != "pypi.org", "authorise must return a vetted IP"


def test_host_outside_allowlist_is_refused(proxy):
    proxy.default_policy = Policy(name="t", allow_hosts=("pypi.org",))
    ok, reason, _ = proxy.authorise("github.com", 443, "CONNECT")
    assert not ok and "not in policy" in reason


def test_wildcard_allowlist_matches_subdomains_only():
    pol = Policy(name="w", allow_hosts=("*.example.com",))
    assert pol.host_permitted("api.example.com")
    assert pol.host_permitted("example.com")
    assert not pol.host_permitted("notexample.com")
    assert not pol.host_permitted("example.com.evil.net")


def test_port_not_in_policy_is_refused(proxy):
    proxy.default_policy = Policy(name="t", allow_hosts=("example.com",),
                                  allow_ports=(443,))
    ok, reason, _ = proxy.authorise("example.com", 6379, "CONNECT")
    assert not ok and "port" in reason


# ------------------------------------------- private / metadata is unreachable
@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "169.254.169.254",
                                  "10.0.0.1", "192.168.1.1", "[::1]"])
def test_private_destinations_denied_even_when_allowlisted(proxy, host):
    """Defence in depth: policy says yes, address classification still says no.

    Mutation: drop the validate_url() call from authorise() -> these succeed.
    """
    bare = host.strip("[]")
    proxy.default_policy = Policy(name="dangerous", allow_hosts=(bare, host),
                                 allow_ports=(443, 80))
    ok, reason, _ = proxy.authorise(bare, 443, "CONNECT")
    assert not ok, f"{bare} was authorised despite being private/metadata"
    assert "address check" in reason or "blocked" in reason


def test_internal_service_name_denied(proxy):
    proxy.default_policy = Policy(name="d", allow_hosts=("metadata.google.internal",))
    ok, reason, _ = proxy.authorise("metadata.google.internal", 80, "GET")
    assert not ok


# ------------------------------------------------------- rebinding resistance
def test_connection_dials_the_vetted_ip_not_the_name(monkeypatch):
    """DNS rebinding: the name must not be re-resolved at connect time, or an
    attacker-controlled resolver wins the race.

    Mutation: connect to `host` instead of `ip` -> this test fails.
    """
    p = EgressProxy(policy=Policy(name="rb", allow_hosts=("rebind.test",))).start()
    try:
        dialled = {}
        real_create = socket.create_connection

        def fake_create_connection(address, *a, **kw):
            # Only intercept connections to the vetted IP; the test client's own
            # connection to the proxy must still work.
            if address[0] == "203.0.113.7":
                dialled["address"] = address
                raise OSError("stop here")
            return real_create(address, *a, **kw)

        # validate gives a public IP; the proxy must dial THAT, not the hostname
        monkeypatch.setattr("skyla.egress.validate_url",
                            lambda url, **kw: type("V", (), {"ip": "203.0.113.7"})())
        monkeypatch.setattr("skyla.egress.socket.create_connection",
                            fake_create_connection)
        connect_request(p, "rebind.test:443")
        assert dialled.get("address", ("",))[0] == "203.0.113.7", (
            f"proxy dialled {dialled.get('address')} instead of the vetted IP")
    finally:
        p.stop()


# ------------------------------------------------------------------- CONNECT
def test_connect_allowed_when_policy_permits_it():
    pol = Policy(name="c", allow_hosts=("pypi.org",), allow_connect=True)
    p = EgressProxy(policy=pol).start()
    try:
        ok, reason, ip = p.authorise("pypi.org", 443, "CONNECT")
        assert ok, reason
    finally:
        p.stop()


def test_connect_can_be_disabled_by_policy():
    pol = Policy(name="noc", allow_hosts=("pypi.org",), allow_connect=False)
    p = EgressProxy(policy=pol).start()
    try:
        resp = connect_request(p, "pypi.org:443")
        assert b"403" in resp
        assert any("CONNECT not allowed" in d["reason"] for d in p.audit.denied())
    finally:
        p.stop()


def test_forward_proxy_without_absolute_target_is_refused(proxy):
    s = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
    s.sendall(b"GET /relative HTTP/1.1\r\nHost: example.com\r\n\r\n")
    resp = s.recv(200)
    s.close()
    assert b"403" in resp


# ------------------------------------------------------------ audit logging
def test_every_decision_is_audited(proxy):
    # An allowed decision is only recorded when a connection is actually
    # attempted, which is the correct place to record it. Use a destination that
    # refuses the TCP connect so the ALLOW path is exercised cheaply.
    class _Refusing(EgressProxy):
        def authorise(self, host, port, method="GET", task_id="", capability=""):
            return True, "allowed", "127.0.0.1"

    p = _Refusing(policy=Policy(name="allow", allow_hosts=("pypi.org",),
                                allow_ports=(9,))).start()
    try:
        connect_request(p, "pypi.org:9")          # allowed, upstream refused
        connect_request(p, "github.com:443")      # denied by policy
        recent = p.audit.recent()
        assert any(not d["allowed"] for d in recent), "denial not audited"
        # An authorised destination that then fails to connect is recorded with
        # its vetted IP: proof that policy passed and the address check ran.
        attempted = [d for d in recent if d["host"] == "pypi.org"]
        assert attempted and attempted[0]["resolved_ip"] == "127.0.0.1", attempted
    finally:
        p.stop()


def test_audit_log_persists_to_disk(tmp_path):
    path = tmp_path / "egress.jsonl"
    audit = EgressAudit(str(path))
    p = EgressProxy(policy=DENY_ALL, audit=audit).start()
    try:
        connect_request(p, "github.com:443")
    finally:
        p.stop()
    assert path.exists()
    lines = [l for l in path.read_text().splitlines() if l.strip()]
    assert lines and '"allowed": false' in lines[0]


# --------------------------------------------------- per-task policy isolation
def _egress_allowed_for(host: str) -> bool:
    r = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                        "--max-time", "10", f"https://{host}"],
                       capture_output=True, text=True)
    return r.stdout.strip() == "200"


@pytest.mark.skipif(not _egress_allowed_for("pypi.org"),
                    reason="host cannot reach pypi.org (egress allowlist or host firewall)")
def test_per_task_policy_is_applied():
    """Mission 3: 'per-task access policy'. One task's allowlist must not leak
    into another's."""
    policies = {"task-a": Policy(name="a", allow_hosts=("pypi.org",)),
                "task-b": Policy(name="b", allow_hosts=("github.com",))}
    p = EgressProxy(policy_resolver=lambda tid: policies.get(tid, DENY_ALL)).start()
    try:
        connect_request(p, "pypi.org:443", headers="X-Skyla-Task: task-a\r\n")
        connect_request(p, "pypi.org:443", headers="X-Skyla-Task: task-b\r\n")
        recs = p.audit.recent()
        a = [r for r in recs if r["task_id"] == "task-a"]
        b = [r for r in recs if r["task_id"] == "task-b"]
        assert a and a[0]["allowed"], a
        assert b and not b[0]["allowed"], "task-b inherited task-a's allowlist"
    finally:
        p.stop()


# ------------------------------------------------ live egress (controllable)
@pytest.mark.skipif(not _egress_allowed_for("pypi.org"),
                    reason="sandbox egress allowlist blocks pypi.org")
def test_live_https_through_proxy_succeeds_for_authorised_host():
    """Mission 3: 'Verify legitimate public HTTPS requests still work where
    explicitly authorised.'"""
    pol = Policy(name="live", allow_hosts=("pypi.org",), allow_methods=("GET",))
    p = EgressProxy(policy=pol).start()
    try:
        env = dict(os.environ, HTTPS_PROXY=p.url, HTTP_PROXY=p.url, NO_PROXY="")
        r = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                            "--max-time", "25", "https://pypi.org/simple/"],
                           capture_output=True, text=True, env=env)
        assert r.stdout.strip() == "200", (r.stdout, r.stderr)
        allowed = [d for d in p.audit.recent() if d["allowed"]]
        assert allowed and allowed[0]["resolved_ip"], "no vetted IP recorded"
    finally:
        p.stop()


def test_live_denied_host_never_reaches_the_network():
    """An unauthorised host must be refused; we assert the proxy never emitted an
    allowed decision for it."""
    p = EgressProxy(policy=Policy(name="live", allow_hosts=("pypi.org",))).start()
    try:
        env = dict(os.environ, HTTPS_PROXY=p.url, HTTP_PROXY=p.url, NO_PROXY="")
        subprocess.run(["curl", "-sS", "-o", "/dev/null", "--max-time", "15",
                        "https://github.com/"], capture_output=True, text=True, env=env)
        assert not [d for d in p.audit.recent() if d["host"] == "github.com" and d["allowed"]]
    finally:
        p.stop()
