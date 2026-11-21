"""Centralized outbound URL validation (v0.3.0, audit finding A-08).

v0.2.0's `fetch_url` accepted any http(s) URL, resolved it, and followed
redirects without re-validation -- so an operator could make the server read
internal endpoints or cloud metadata.

This module validates at the **connection boundary**: resolution happens here,
the resolved addresses are checked, and the caller connects to the vetted IP
with the original Host header. Every redirect hop is re-validated.

Protected:
  loopback, private IPv4/IPv6, link-local, CGNAT, multicast, reserved,
  unspecified, unique-local IPv6, IPv4-mapped IPv6, cloud metadata addresses,
  non-http(s) schemes, and URLs carrying credentials.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

# Cloud metadata endpoints. 169.254.169.254 is covered by link-local, but the
# named services are listed explicitly so intent is auditable.
METADATA_HOSTS = {
    "metadata.google.internal", "metadata.goog",
    "instance-data", "metadata",
}
METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),   # AWS/GCP/Azure IMDS
    ipaddress.ip_address("100.100.100.200"),   # Alibaba Cloud
    ipaddress.ip_address("fd00:ec2::254"),     # AWS IPv6 IMDS
}

_EXTRA_BLOCKED_V4 = [
    ipaddress.ip_network("0.0.0.0/8"),        # "this host"
    ipaddress.ip_network("10.0.0.0/8"),       # private
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("172.16.0.0/12"),    # private
    ipaddress.ip_network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.ip_network("192.168.0.0/16"),   # private
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking
    ipaddress.ip_network("240.0.0.0/4"),      # reserved
    ipaddress.ip_network("255.255.255.255/32"),
]
_EXTRA_BLOCKED_V6 = [
    ipaddress.ip_network("::/128"),           # unspecified
    ipaddress.ip_network("::1/128"),          # loopback
    ipaddress.ip_network("::ffff:0:0/96"),    # IPv4-mapped (re-check the v4 part)
    ipaddress.ip_network("64:ff9b::/96"),     # NAT64
    ipaddress.ip_network("fc00::/7"),         # unique-local
    ipaddress.ip_network("fe80::/10"),        # link-local
]

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 8080, 8443}


class SSRFBlocked(ValueError):
    """Raised when a URL resolves to a destination we refuse to contact."""


@dataclass
class VettedURL:
    url: str
    host: str
    port: int
    scheme: str
    ip: str          # the vetted address to actually connect to


def _describe(host: str) -> str:
    return host.lower().strip(".")


def is_blocked_ip(addr: str | ipaddress._BaseAddress, *, allow_loopback: bool = False) -> tuple[bool, str]:
    """Classify an IP. Returns (blocked, reason)."""
    ip = ipaddress.ip_address(addr) if isinstance(addr, str) else addr

    # Unwrap IPv4-mapped IPv6 (::ffff:127.0.0.1) so the v4 rules apply.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip in METADATA_IPS:
        return True, "cloud metadata endpoint"
    if ip.is_multicast or ip.is_reserved:
        return True, f"multicast/reserved address ({ip})"
    if ip.is_link_local:
        return True, f"link-local address ({ip})"
    if ip.is_loopback:
        return (not allow_loopback), f"loopback address ({ip})"
    if ip.is_private:
        return True, f"private address ({ip})"
    if ip.is_unspecified:
        return True, "unspecified address"

    nets = _EXTRA_BLOCKED_V4 if ip.version == 4 else _EXTRA_BLOCKED_V6
    for net in nets:
        if ip.version == net.version and ip in net:
            return True, f"blocked range {net} ({ip})"
    return False, ""


def validate_url(url: str, *, allow_loopback: bool = False,
                 allowed_ports: set[int] | None = None,
                 resolver=socket.getaddrinfo) -> VettedURL:
    """Parse, resolve and vet a URL. Raises SSRFBlocked on any problem.

    Resolution happens HERE so the caller can connect to a known-good IP,
    which closes the DNS-rebinding window between check and connect.
    """
    if not isinstance(url, str) or not url.strip():
        raise SSRFBlocked("empty URL")
    parts = urlsplit(url.strip())

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise SSRFBlocked(f"scheme '{parts.scheme}' is not permitted (http/https only)")
    if parts.username or parts.password:
        raise SSRFBlocked("URLs carrying credentials are not permitted")
    host = parts.hostname
    if not host:
        raise SSRFBlocked("URL has no host")

    # Alternate IP representations (decimal, octal, hex, integer) are normalised
    # by the resolver; we additionally reject literal integers outright because
    # some resolvers interpret them as addresses.
    if host.isdigit() and "." not in host:
        raise SSRFBlocked(f"ambiguous numeric host '{host}'")

    if _describe(host) in METADATA_HOSTS:
        raise SSRFBlocked(f"cloud metadata host '{host}'")

    port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    ports = allowed_ports or ALLOWED_PORTS
    if port not in ports:
        raise SSRFBlocked(f"port {port} is not permitted (allowed: {sorted(ports)})")

    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise SSRFBlocked(f"cannot resolve '{host}': {exc}") from exc
    if not infos:
        raise SSRFBlocked(f"no addresses resolved for '{host}'")

    vetted: list[str] = []
    for info in infos:
        addr = info[4][0]
        blocked, reason = is_blocked_ip(addr, allow_loopback=allow_loopback)
        if blocked:
            raise SSRFBlocked(f"'{host}' resolves to blocked destination: {reason}")
        vetted.append(addr)
    if not vetted:
        raise SSRFBlocked(f"'{host}' has no usable address")

    return VettedURL(url=url, host=host, port=port,
                     scheme=parts.scheme.lower(), ip=vetted[0])


def safe_redirect_chain(current: str, location: str, *, hops: int,
                        max_hops: int = 3) -> str:
    """Join a redirect Location against the current URL and enforce the hop cap."""
    if hops >= max_hops:
        raise SSRFBlocked(f"too many redirects (>{max_hops})")
    if not location:
        raise SSRFBlocked("redirect without a Location header")
    from urllib.parse import urljoin
    nxt = urljoin(current, location)
    # The next hop is validated by the caller with validate_url() before use.
    return nxt
