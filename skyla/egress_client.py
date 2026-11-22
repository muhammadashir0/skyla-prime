"""The single place the API process is allowed to build an outbound HTTP client.

Why a factory and not scattered `httpx.AsyncClient(...)` calls
--------------------------------------------------------------
v0.2.2 had eleven independent `httpx.AsyncClient(...)` constructions across six
modules. Not one passed `proxy=`, and nothing in the application ever set
`HTTPS_PROXY`. So every outbound call — research, model providers, Gmail,
Calendar, Telegram, OAuth refresh — dialled the internet directly, regardless of
what `skyla/egress.py` said it did.

That is B-01, and it is a *construction* problem: a policy is only binding if
there is exactly one way to obtain a client, and that way is constrained. This
module is that one way.

Two layers, and the first is the one that matters
-------------------------------------------------
1. **Route enforcement (kernel).** The API runs inside a network namespace whose
   only route is to the egress gateway. `mode="enforce"` additionally proves that
   constraint is actually in place, and refuses if it is not. A caller cannot opt
   out of this by forgetting to pass an argument: forgetting is a refusal.

2. **Policy enforcement (proxy).** The client is pointed at the gateway proxy,
   which applies a per-capability allowlist. `mode="policy"` uses this layer
   without requiring the namespace.

`mode="legacy"` exists for exactly one purpose: tests that use `httpx.MockTransport`
and never open a socket. It is refused outright if the perimeter is installed, so
it cannot quietly become the production path.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

from .egress import POLICIES, Policy, policy_for_connector

_PERIMETER_NS = "skyla-egress"

# Where the workload namespace reaches the egress gateway.
GATEWAY_ADDRESS = os.getenv("SKYLA_EGRESS_GATEWAY", "10.200.0.1")
DEFAULT_PROXY_PORT = int(os.getenv("SKYLA_EGRESS_PORT", "8155"))

_MODES = ("enforce", "policy", "legacy")


class EgressUnavailable(RuntimeError):
    """Raised rather than returning a client that could reach anything.

    Never caught to fall back to an unrestricted client — see `client()`.
    """


@dataclass
class RouteConfirmation:
    """What was actually true when a client was handed out."""
    mode: str
    proxy_url: str
    namespaced: bool
    inode: str
    policy: str


def _netns_inode() -> str:
    try:
        return os.readlink("/proc/self/ns/net")
    except OSError:  # pragma: no cover - /proc absent
        return ""


def _perimeter_ns_inode() -> int:
    try:
        return os.stat(f"/var/run/netns/{_PERIMETER_NS}").st_ino
    except OSError:
        return -1


def is_namespaced() -> bool:
    """True when this process is inside the egress perimeter namespace.

    Compares against `/var/run/netns/skyla-egress` rather than `/proc/1/ns/net`.
    The earlier implementation read the host namespace through `/proc/1/ns/net`,
    which an **unprivileged** process cannot open — and unprivileged is exactly how
    the service is meant to run. The result was `is_namespaced() == False` for a
    correctly confined process, which disabled the downgrade guard below: the one
    check that stops a confined process from selecting a weaker mode. Measured on
    a live uid-1001 API inside the perimeter before this fix.

    The namespace file is world-readable (`-r--r--r--`), so this works as any uid.
    """
    try:
        mine = os.stat("/proc/self/ns/net").st_ino
    except OSError:
        return False
    want = _perimeter_ns_inode()
    return want != -1 and mine == want


def perimeter_installed() -> bool:
    return (os.path.exists("/var/run/netns/skyla-egress")
            and os.path.exists("/var/run/netns/skyla-egress-gw"))


def resolve_mode(explicit: str | None = None) -> str:
    """Decide the mode, failing closed when the perimeter is present.

    A process that is namespaced must never be handed an unconstrained client,
    even if misconfigured: the boundary is there, so use it. This is the one place
    where the environment overrides the caller.

    `SKYLA_EGRESS_MODE=legacy` needs a second, explicit declaration
    (`SKYLA_EGRESS_ALLOW_LEGACY=1`) when a perimeter is installed. That pairing
    exists because the test suite legitimately needs mock transports on a host
    where the perimeter happens to be installed; a single variable reaching
    production by accident is exactly the kind of quiet bypass this module exists
    to prevent, and two deliberate declarations are not an accident.
    """
    installed = perimeter_installed()
    namespaced = is_namespaced()
    allow_legacy = os.getenv("SKYLA_EGRESS_ALLOW_LEGACY", "0") == "1"

    if explicit is not None:
        if explicit not in _MODES:
            raise EgressUnavailable(
                f"unknown egress mode {explicit!r}; expected one of {_MODES}")
        # A caller may not downgrade out of an enforced boundary.
        if explicit == "legacy" and (installed or namespaced) and not allow_legacy:
            raise EgressUnavailable(
                "egress mode 'legacy' refused: the network perimeter is installed. "
                "A direct client here would bypass the boundary the host provides. "
                "(Set SKYLA_EGRESS_ALLOW_LEGACY=1 only in a test process.)")
        # A namespaced process is already inside the boundary. Letting it select
        # `policy` would skip the "can I reach the internet directly?" proof, so
        # the one thing distinguishing enforcement from configuration would go
        # unmeasured. Inside the namespace the answer is always `enforce`.
        if namespaced and explicit != "enforce" and not allow_legacy:
            raise EgressUnavailable(
                f"egress mode {explicit!r} refused: this process is inside the "
                f"network perimeter, so enforcement is mandatory, not optional")
        return explicit

    if namespaced:
        return "enforce"
    env = os.getenv("SKYLA_EGRESS_MODE", "").strip().lower()
    if env in _MODES:
        if env == "legacy" and installed and not allow_legacy:
            raise EgressUnavailable(
                "SKYLA_EGRESS_MODE=legacy refused: the network perimeter is installed")
        return env
    return "enforce" if installed else "policy"


def _policy_or_deny(name: str | Policy | None) -> Policy:
    if isinstance(name, Policy):
        return name
    if name is None:
        return POLICIES["deny-all"]
    return POLICIES.get(name) if name in POLICIES else policy_for_connector(name)


def _verify_boundary(mode: str) -> None:
    """Prove the kernel constraint before handing out a client.

    In `enforce` mode this is not advisory: if the process can reach the internet
    directly, the perimeter is not doing its job and we refuse.
    """
    if mode != "enforce":
        return
    if not perimeter_installed():
        raise EgressUnavailable(
            "egress enforcement required but the perimeter is not installed — "
            "run scripts/skyla-perimeter.sh setup (as root, once)")

    import socket
    # The gateway proxy must be reachable...
    try:
        with socket.create_connection((GATEWAY_ADDRESS, DEFAULT_PROXY_PORT), timeout=5):
            pass
    except OSError as exc:
        raise EgressUnavailable(
            f"egress gateway {GATEWAY_ADDRESS}:{DEFAULT_PROXY_PORT} unreachable "
            f"({type(exc).__name__}: {exc}) — protected operations refuse to run"
        ) from exc

    # ...and the internet must NOT be. A direct route means the namespace is wrong.
    try:
        with socket.create_connection(("1.1.1.1", 53), timeout=3):
            raise EgressUnavailable(
                "direct egress succeeded: this process can bypass the egress gateway. "
                "Refusing to continue — the perimeter is not constraining it.")
    except EgressUnavailable:
        raise
    except OSError:
        pass  # expected: no route to anything but the gateway


def client(capability: str | Policy | None = None, *,
           mode: str | None = None, timeout: float | httpx.Timeout = 30.0,
           **kwargs) -> httpx.AsyncClient:
    """Build the only kind of outbound client the application may use.

    `capability` selects the egress policy (`research`, `model-provider`,
    `connector-google`, `connector-telegram`, `api-egress`) or accepts a Policy
    directly. An unknown name resolves to `deny-all`.
    """
    resolved = resolve_mode(mode)
    policy = _policy_or_deny(capability)

    # A supplied transport short-circuits the network entirely: `httpx.MockTransport`
    # never opens a socket, so a proxy argument would be dead configuration and a
    # namespace check would be meaningless. This is the seam tests use, and it is
    # safe precisely because an injected transport cannot reach the network.
    if kwargs.get("transport") is not None:
        return httpx.AsyncClient(timeout=timeout, trust_env=False, **kwargs)

    if resolved == "legacy":
        # No proxy, no verification. Only reachable when the caller explicitly
        # asked for it AND declared SKYLA_EGRESS_ALLOW_LEGACY=1.
        kwargs.pop("proxy", None)
        return httpx.AsyncClient(timeout=timeout, trust_env=False, **kwargs)

    _verify_boundary(resolved)

    secret = os.getenv("SKYLA_EGRESS_SECRET", "")
    # The capability must ride in the proxy URL's userinfo, not a request header.
    # Measured: httpx sends only `host` and `accept` on a CONNECT, so a custom
    # header never arrives for HTTPS — the capability would be unknown precisely
    # where it is needed. Proxy-Authorization is part of the CONNECT handshake.
    auth = f"{policy.name}:{secret}" if secret else f"{policy.name}:"
    proxy_url = f"http://{auth}@{GATEWAY_ADDRESS}:{DEFAULT_PROXY_PORT}"
    # `trust_env=False` is not cosmetic: httpx honours HTTP(S)_PROXY from the
    # environment by default, so a stray variable could redirect every call to an
    # attacker-controlled proxy. The route is set here and nowhere else.
    return httpx.AsyncClient(proxy=proxy_url, trust_env=False, timeout=timeout,
                             follow_redirects=False, **kwargs)


def route_confirmation(capability: str | Policy | None = None,
                       mode: str | None = None) -> RouteConfirmation:
    """What `client()` would do right now, for reporting and startup checks."""
    resolved = resolve_mode(mode)
    policy = _policy_or_deny(capability)
    return RouteConfirmation(
        mode=resolved,
        proxy_url="" if resolved == "legacy" else f"http://{GATEWAY_ADDRESS}:{DEFAULT_PROXY_PORT}",
        namespaced=is_namespaced(),
        inode=_netns_inode(),
        policy=policy.name,
    )


def startup_check() -> dict:
    """Fail-closed startup gate. Called once, before the API accepts traffic.

    Returns a dict on success; raises `EgressUnavailable` when the process would
    be able to reach the network unconstrained.
    """
    mode = resolve_mode()
    conf = route_confirmation("api-egress", mode=mode)
    if mode == "enforce":
        _verify_boundary(mode)
    return {
        "mode": conf.mode,
        "proxy": conf.proxy_url,
        "namespaced": conf.namespaced,
        "netns_inode": conf.inode,
        "policy": conf.policy,
        "enforced": mode == "enforce",
    }
