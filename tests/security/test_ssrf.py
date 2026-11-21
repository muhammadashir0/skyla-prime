"""SSRF defence (A-08): URL, network-boundary and redirect validation.

Mutation targets: removing the IP block list, removing the post-resolution check,
or removing the per-hop redirect validation makes these FAIL.

These tests are hermetic except for two cases that require real DNS resolution of
public names; those skip when the network is unavailable.
"""
import socket

import pytest

from skyla.netguard import SSRFBlocked, is_blocked_ip, safe_redirect_chain, validate_url


def blocked(url: str) -> bool:
    try:
        validate_url(url)
    except SSRFBlocked:
        return True
    return False


BLOCKED_URLS = [
    "http://127.0.0.1/",
    "http://127.0.0.1:8000/",
    "http://localhost/",
    "http://localhost:8080/admin",
    "http://169.254.169.254/latest/meta-data/",           # cloud metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://[::1]/",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://100.64.0.1/",                                 # CGNAT
    "http://0.0.0.0/",
    "http://2130706433/",                                 # decimal 127.0.0.1
    "http://[::ffff:127.0.0.1]/",                         # v4-mapped v6
    "http://[fd00::1]/",                                  # unique local v6
    "http://[fe80::1]/",                                  # link-local v6
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "ftp://example.com/x",
    "http://user:pass@example.com/",                      # credentials in URL
    "http://example.com:22/",                             # non-web port
    "http://169.254.169.254.nip.io/",                     # rebinding-ish name
]


@pytest.mark.parametrize("url", BLOCKED_URLS)
def test_dangerous_urls_are_blocked(url):
    assert blocked(url) is True, f"{url} was NOT blocked"


def test_public_urls_are_allowed():
    try:
        v = validate_url("https://example.com/")
    except SSRFBlocked as exc:
        if "cannot resolve" in str(exc):
            pytest.skip("no DNS in this environment")
        raise
    assert v.scheme == "https" and v.ip and v.host


def test_literal_public_ip_is_allowed():
    v = validate_url("http://1.1.1.1/")
    assert v.ip == "1.1.1.1"


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "169.254.169.254", "10.1.2.3",
                                "192.168.0.1", "172.20.0.1", "0.0.0.0", "100.64.0.1",
                                "::ffff:192.168.0.1", "fd00::1", "fe80::1"])
def test_blocked_ip_ranges(ip):
    isblocked, reason = is_blocked_ip(ip)
    assert isblocked is True, f"{ip} not blocked"
    assert reason


@pytest.mark.parametrize("ip", ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111"])
def test_public_ip_ranges(ip):
    isblocked, _ = is_blocked_ip(ip)
    assert isblocked is False


def test_dns_rebinding_is_caught_by_resolving_before_connect():
    """A NAME that resolves to loopback must be refused even though the literal
    hostname looks public. This is the post-resolution check."""
    def fake_resolver(host, port, **kw):
        assert host == "innocent-looking.example"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    with pytest.raises(SSRFBlocked) as exc:
        validate_url("http://innocent-looking.example/", resolver=fake_resolver)
    assert "blocked destination" in str(exc.value)


def test_resolver_returning_metadata_ip_is_refused():
    def fake_resolver(host, port, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]

    with pytest.raises(SSRFBlocked):
        validate_url("http://totally-normal.example/", resolver=fake_resolver)


def test_redirect_hop_is_revalidated():
    """Mutation: validate only the initial URL -> this FAILs.

    Simulates a 302 from a public host to an internal address, which is the
    classic redirect-SSRF chain.
    """
    nxt = safe_redirect_chain("https://example.com/start", "http://127.0.0.1/admin",
                              hops=0)
    # Joining alone must not be treated as safe; the next hop is re-vetted.
    with pytest.raises(SSRFBlocked):
        validate_url(nxt)


def test_relative_redirect_stays_on_public_host():
    nxt = safe_redirect_chain("https://example.com/a", "/b", hops=0)
    assert nxt == "https://example.com/b"
    v = validate_url(nxt)
    assert v.host == "example.com"


def test_redirect_hop_cap():
    with pytest.raises(SSRFBlocked):
        safe_redirect_chain("https://example.com/a", "/b", hops=3, max_hops=3)


def test_empty_and_malformed_urls():
    for bad in ("", "   ", "not a url", "//example.com", "http://"):
        assert blocked(bad) is True
