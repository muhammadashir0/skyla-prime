"""Default-deny egress proxy (v0.2.2 PRIME QUALIFICATION, Mission 3).

Why a proxy and not just URL validation
---------------------------------------
v0.3.0's `netguard.validate_url()` validated a URL then handed it to an HTTP
client. That leaves three gaps the audit and the mission both call out:

  1. **It only guards code paths that remember to call it.** Any library that
     opens a socket directly bypasses it entirely.
  2. **The connection is still made to the hostname**, so a DNS answer that
     changes between validation and connect (rebinding) wins the race.
  3. **There is no chokepoint to audit.** Refusals are scattered across callers.

This module is a real HTTP proxy. Workloads and connectors are pointed at it via
`HTTP_PROXY`/`HTTPS_PROXY`, and it:

  * refuses everything by default (no allowlist match = 403 before any TCP connect);
  * validates the **resolved IP at connect time**, then dials that exact IP, so a
    rebinding resolver cannot redirect the connection;
  * re-validates every redirect hop (the proxy sees each request);
  * enforces an explicit per-task/per-connector policy with host + port + method;
  * logs every decision as a structured audit record.

It is deliberately small: HTTP forwarding + CONNECT tunnelling, no caching, no
authentication of its own (it binds loopback and is a *policy* boundary, not a
network perimeter). For a real deployment it should also be the only egress route
enforced by the host firewall — see EGRESS_PROXY_ASSESSMENT.md.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import socketserver
import threading
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

from .netguard import SSRFBlocked, is_blocked_ip, validate_url

MAX_HEADER_BYTES = 64 * 1024
CONNECT_TIMEOUT_S = 10
IDLE_TIMEOUT_S = 30


class EgressDenied(PermissionError):
    """A destination was refused before any connection was made."""

    def __init__(self, reason: str, destination: str = ""):
        self.reason = reason
        self.destination = destination
        super().__init__(f"egress denied ({reason}): {destination}")


@dataclass
class Policy:
    """Per-task or per-connector egress policy. Default deny.

    `allow_hosts` are exact hostnames or `*.suffix` wildcards. An empty policy
    allows nothing at all.
    """
    name: str = "default"
    allow_hosts: tuple[str, ...] = ()
    allow_ports: tuple[int, ...] = (443, 80)
    allow_methods: tuple[str, ...] = ("GET", "HEAD", "POST")
    allow_connect: bool = True          # needed for HTTPS tunnelling
    max_conns: int = 8

    def host_permitted(self, host: str) -> bool:
        host = (host or "").lower().rstrip(".")
        if not host:
            return False
        for pattern in self.allow_hosts:
            p = pattern.lower().rstrip(".")
            if p.startswith("*."):
                if host.endswith(p[1:]) or host == p[2:]:
                    return True
            elif host == p:
                return True
        return False


# A starting policy set. Deliberately tiny: every host here had to be justified.
POLICIES: dict[str, Policy] = {
    "deny-all": Policy(name="deny-all"),
    "research": Policy(
        name="research",
        allow_hosts=("*.wikipedia.org", "wikipedia.org", "example.com",
                     "*.example.com", "pypi.org", "files.pythonhosted.org"),
        allow_methods=("GET", "HEAD"),
    ),
    "connector-google": Policy(
        name="connector-google",
        allow_hosts=("oauth2.googleapis.com", "www.googleapis.com",
                     "gmail.googleapis.com", "www.google.com",
                     "accounts.google.com"),
        allow_methods=("GET", "POST", "PUT", "PATCH"),
    ),
    "connector-telegram": Policy(
        name="connector-telegram",
        allow_hosts=("api.telegram.org",),
        allow_methods=("GET", "POST"),
    ),
    # Research retrieval is a distinct capability from model inference: one reads
    # untrusted documents, the other spends money and holds an API key. Separate
    # policies mean a compromise of the reader does not carry the spender's reach.
    "model-provider": Policy(
        name="model-provider",
        allow_hosts=(
            "api.openai.com",          # OpenAI-compatible
            "api.deepseek.com",
            "dashscope.aliyuncs.com",  # Qwen
            "api.z.ai",                # GLM
        ),
        allow_methods=("GET", "POST"),
    ),
    # The union used by the API process, which plays every role at once. Kept as
    # an explicit union rather than a wildcard so adding a capability is a
    # deliberate edit to a named policy, not a silent widening.
    "api-egress": Policy(
        name="api-egress",
        allow_hosts=(
            # research
            "*.wikipedia.org", "wikipedia.org", "example.com", "*.example.com",
            # model providers
            "api.openai.com", "api.deepseek.com", "dashscope.aliyuncs.com", "api.z.ai",
            # google oauth + gmail + calendar
            "oauth2.googleapis.com", "www.googleapis.com", "gmail.googleapis.com",
            "www.google.com", "accounts.googleapis.com", "accounts.google.com",
            # telegram
            "api.telegram.org",
        ),
        allow_methods=("GET", "HEAD", "POST", "PUT", "PATCH"),
    ),
}


def policy_for_connector(connector: str) -> Policy:
    """Map a connector name to its policy, denying by default.

    Used by the client factory so each call is scoped to the capability that
    needs it. An unknown connector gets `deny-all`, never a permissive default.
    """
    name = (connector or "").strip().lower()
    if name in ("gmail", "calendar", "google", "gmail-connector"):
        return POLICIES["connector-google"]
    if name in ("telegram",):
        return POLICIES["connector-telegram"]
    if name in ("research", "fetch", "web"):
        return POLICIES["research"]
    if name in ("model", "provider", "llm"):
        return POLICIES["model-provider"]
    if name in ("api", "api-egress"):
        return POLICIES["api-egress"]
    return POLICIES["deny-all"]


@dataclass
class Decision:
    ts: float
    policy: str
    host: str
    port: int
    method: str
    allowed: bool
    reason: str
    resolved_ip: str = ""
    task_id: str = ""
    bytes_tx: int = 0

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["ts"] = round(self.ts, 3)
        return d


class EgressAudit:
    """Append-only, line-delimited JSON decision log."""

    def __init__(self, path: str | None = None):
        self.path = path or os.getenv("SKYLA_EGRESS_AUDIT", "")
        self._lock = threading.Lock()
        self._memory: list[Decision] = []

    def record(self, d: Decision) -> None:
        with self._lock:
            self._memory.append(d)
            if len(self._memory) > 5000:
                del self._memory[:1000]
            if self.path:
                try:
                    with open(self.path, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(d.as_dict()) + "\n")
                except OSError:
                    pass

    def recent(self, limit: int = 100) -> list[dict]:
        with self._lock:
            return [d.as_dict() for d in self._memory[-limit:]]

    def denied(self) -> list[dict]:
        with self._lock:
            return [d.as_dict() for d in self._memory if not d.allowed]


class EgressProxy:
    """Threaded HTTP/HTTPS forward proxy with default-deny policy."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 *, policy: Policy | None = None,
                 audit: EgressAudit | None = None,
                 policy_resolver: Callable[[str], Policy] | None = None,
                 share_secret: str = "", require_auth: bool = False):
        self.host = host
        self.port = port
        self.default_policy = policy or POLICIES["deny-all"]
        self.audit = audit or EgressAudit()
        self.policy_resolver = policy_resolver
        self.share_secret = share_secret or os.getenv("SKYLA_EGRESS_SECRET", "")
        self.require_auth = require_auth or os.getenv("SKYLA_EGRESS_REQUIRE_AUTH", "0") == "1"
        self._server: socketserver.ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------ lifecycle
    def start(self) -> "EgressProxy":
        proxy = self

        class Handler(socketserver.StreamRequestHandler):
            timeout = IDLE_TIMEOUT_S

            def handle(self):
                proxy._handle(self.request, self.client_address)

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self._server = Server((self.host, self.port), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True, name="skyla-egress")
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    # -------------------------------------------------------------- policy
    def _capability_from(self, headers: dict) -> tuple[str, str]:
        """Extract the capability from Proxy-Authorization.

        Format: `Basic base64("<capability>:<token>")`. The username names the
        policy; the password is a shared secret so an arbitrary process on the
        host cannot borrow a capability by guessing its name. When
        `require_auth` is set, a missing or wrong credential is denied rather
        than falling back to the default policy.
        """
        raw = headers.get("proxy-authorization", "")
        if not raw:
            return "", "" if not self.require_auth else "proxy authentication required"
        scheme, _, blob = raw.partition(" ")
        if scheme.lower() != "basic":
            return "", f"unsupported proxy auth scheme {scheme!r}"
        try:
            import base64
            decoded = base64.b64decode(blob).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return "", "malformed proxy credentials"
        cap, _, token = decoded.partition(":")
        cap = cap.strip()
        if self.share_secret and token != self.share_secret:
            return "", "invalid proxy credential"
        valid = set(POLICIES) | {"research", "model-provider", "connector-google",
                                 "connector-telegram", "api-egress"}
        if cap not in valid:
            return "", f"unknown capability {cap!r}"
        return cap, ""

    def _policy_for(self, task_id: str) -> Policy:
        if self.policy_resolver:
            return self.policy_resolver(task_id)
        return self.default_policy

    def authorise(self, host: str, port: int, method: str = "GET",
                  task_id: str = "", capability: str = "") -> tuple[bool, str, str]:
        """Decide whether a destination may be contacted. Returns (ok, reason, ip).

        Order matters: policy first (cheap, and denies most things without doing
        any DNS work), then resolution, then IP classification.
        """
        policy = self._policy_for(task_id)
        if capability:
            # A named capability is authoritative: the request is judged by that
            # policy and nothing else. No fan-out, no union.
            declared = POLICIES.get(capability) or policy_for_connector(capability)
            if not declared.host_permitted(host):
                return False, (f"host '{host}' not permitted for capability "
                               f"'{declared.name}'"), ""
            if port not in declared.allow_ports:
                return False, f"port {port} not permitted for '{declared.name}'", ""
            if method.upper() != "CONNECT" and method.upper() not in declared.allow_methods:
                return False, f"method {method} not permitted for '{declared.name}'", ""
            try:
                vetted = validate_url(
                    f"https://{host}:{port}/" if port in (443, 8443)
                    else f"http://{host}:{port}/",
                    allowed_ports=set(declared.allow_ports))
            except SSRFBlocked as exc:
                return False, f"address check failed: {exc}", ""
            return True, f"allowed by capability '{declared.name}'", vetted.ip
        if not policy.host_permitted(host):
            # One proxy serves several capabilities (research, model providers,
            # Google, Telegram) because the API is a single process. Rather than
            # run four listeners — four bind addresses to get wrong — a host that
            # the *default* policy would allow is permitted when an explicitly
            # named per-capability policy allows it. The union is the named
            # `api-egress` policy's host list, so this cannot widen silently: a
            # destination still has to appear in a reviewed policy.
            if self.default_policy.name in ("api-egress", "multi-capability"):
                for alt_name in ("research", "model-provider", "connector-google",
                                 "connector-telegram"):
                    alt = POLICIES.get(alt_name)
                    if alt and alt.host_permitted(host) and port in alt.allow_ports \
                            and (method.upper() == "CONNECT"
                                 or method.upper() in alt.allow_methods):
                        # Resolve here too. Returning a bare "" made the caller
                        # dial ("", 443), which fails with "Name or service not
                        # known" and is reported as "upstream unreachable" — a
                        # misleading verdict that hid a correct policy decision.
                        try:
                            vetted = validate_url(
                                f"https://{host}:{port}/" if port in (443, 8443)
                                else f"http://{host}:{port}/",
                                allowed_ports=set(alt.allow_ports))
                        except SSRFBlocked as exc:
                            return False, f"address check failed: {exc}", ""
                        return True, f"allowed by '{alt_name}'", vetted.ip
            return False, f"host '{host}' not in policy '{policy.name}'", ""
        if port not in policy.allow_ports:
            return False, f"port {port} not permitted", ""
        # CONNECT is a tunnel-establishment request, not an application method, so
        # it is governed by allow_connect. Filtering it through allow_methods would
        # make every HTTPS request impossible whenever a policy lists specific
        # HTTP verbs (found by testing: research policy allows GET/HEAD only).
        if method.upper() != "CONNECT" and method.upper() not in policy.allow_methods:
            return False, f"method {method} not permitted", ""
        try:
            vetted = validate_url(f"https://{host}:{port}/"
                                  if port in (443, 8443) else f"http://{host}:{port}/",
                                  allowed_ports=set(policy.allow_ports))
        except SSRFBlocked as exc:
            return False, f"address check failed: {exc}", ""
        return True, "allowed", vetted.ip

    # ------------------------------------------------------------ handling
    def _handle(self, conn: socket.socket, addr) -> None:
        try:
            data = self._read_headers(conn)
        except OSError:
            return
        if not data:
            return
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        if not lines:
            return
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            self._deny(conn, "", 0, "malformed", "malformed request line")
            return
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        task_id = headers.get("x-skyla-task", "")
        # The client factory stamps every request with the capability it was
        # built for. The proxy enforces that capability's policy alone, so a
        # research client cannot reach a model provider and a connector cannot
        # reach an arbitrary host, even though both use the same listener.
        # Capability travels in Proxy-Authorization, not a custom header.
        # Measured: httpx forwards only `host` and `accept` on a CONNECT request,
        # so a custom header never reaches the proxy for HTTPS — the capability
        # would be silently unknown exactly where it matters. Proxy-Authorization
        # is part of the CONNECT handshake and survives.
        capability, auth_reason = self._capability_from(headers)
        if not auth_reason and not capability:
            capability = headers.get("x-skyla-capability", "").strip()

        if method.upper() == "CONNECT":
            self._handle_connect(conn, target, task_id, rest, capability)
        else:
            self._handle_forward(conn, method, target, headers, rest, task_id,
                                 capability)

    @staticmethod
    def _read_headers(conn: socket.socket) -> bytes:
        buf = b""
        conn.settimeout(IDLE_TIMEOUT_S)
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return b""
            buf += chunk
            if len(buf) > MAX_HEADER_BYTES:
                raise OSError("header too large")
        return buf

    def _deny(self, conn, host, port, method, reason, task_id="") -> None:
        self.audit.record(Decision(time.time(), self._policy_for(task_id).name,
                                   host, port, method, False, reason, task_id=task_id))
        body = f"SKYLA egress denied: {reason}\n".encode()
        try:
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\n"
                         b"Content-Type: text/plain\r\n"
                         b"X-Skyla-Egress: denied\r\n"
                         + f"Content-Length: {len(body)}\r\n".encode()
                         + b"Connection: close\r\n\r\n" + body)
        except OSError:
            pass

    def _handle_connect(self, conn: socket.socket, target: str,
                        task_id: str, rest: bytes, capability: str = "") -> None:
        host, _, port_s = target.partition(":")
        try:
            port = int(port_s or "443")
        except ValueError:
            self._deny(conn, host, 0, "CONNECT", "bad port", task_id)
            return
        policy = self._policy_for(task_id)
        if not policy.allow_connect:
            self._deny(conn, host, port, "CONNECT",
                       f"CONNECT not allowed by policy '{policy.name}'", task_id)
            return
        ok, reason, ip = self.authorise(host, port, "CONNECT", task_id, capability)
        if not ok:
            self._deny(conn, host, port, "CONNECT", reason, task_id)
            return
        # Dial the VETTED IP, not the name: closes the rebinding window.
        try:
            upstream = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT_S)
        except OSError as exc:
            self.audit.record(Decision(time.time(), policy.name, host, port,
                                       "CONNECT", False, f"connect failed: {exc}",
                                       resolved_ip=ip, task_id=task_id))
            self._deny(conn, host, port, "CONNECT", "upstream unreachable", task_id)
            return
        self.audit.record(Decision(time.time(), policy.name, host, port, "CONNECT",
                                   True, "tunnel established", resolved_ip=ip,
                                   task_id=task_id))
        try:
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._tunnel(conn, upstream)
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    def _handle_forward(self, conn, method, target, headers, rest, task_id,
                        capability: str = "") -> None:
        parts = urlsplit(target)
        host = parts.hostname or headers.get("host", "").split(":")[0]
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if not parts.scheme:
            self._deny(conn, host, port, method,
                       "proxy requires absolute-form request target", task_id)
            return
        ok, reason, ip = self.authorise(host, port, method, task_id, capability)
        if not ok:
            self._deny(conn, host, port, method, reason, task_id)
            return
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        fwd = [f"{method} {path} {parts.scheme.upper() if False else 'HTTP/1.1'}"]
        for k, v in headers.items():
            if k in ("proxy-connection", "proxy-authorization"):
                continue
            fwd.append(f"{k}: {v}")
        fwd.append("Connection: close")
        payload = ("\r\n".join(fwd) + "\r\n\r\n").encode("latin-1") + rest
        try:
            upstream = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT_S)
        except OSError as exc:
            self.audit.record(Decision(time.time(), self._policy_for(task_id).name,
                                       host, port, method, False,
                                       f"connect failed: {exc}", resolved_ip=ip,
                                       task_id=task_id))
            self._deny(conn, host, port, method, "upstream unreachable", task_id)
            return
        try:
            upstream.sendall(payload)
            self.audit.record(Decision(time.time(), self._policy_for(task_id).name,
                                       host, port, method, True, "forwarded",
                                       resolved_ip=ip, task_id=task_id))
            self._tunnel(conn, upstream)
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    def _tunnel(self, a: socket.socket, b: socket.socket) -> None:
        """Bidirectional copy until both directions close."""
        def pump(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t = threading.Thread(target=pump, args=(b, a), daemon=True)
        t.start()
        pump(a, b)
        t.join(timeout=5)


def proxy_from_env() -> EgressProxy | None:
    """Build a proxy from SKYLA_EGRESS_* env if configured.

    Under the v0.2.3 perimeter (`skyla.perimeter`) the workload namespace can
    reach exactly one address: `10.200.0.1`, the gateway, which DNATs one port to
    this proxy. So the proxy must be bound to the **host side of the gateway veth**
    (`10.201.0.1`), not to loopback and not to `0.0.0.0`:

      * bound to loopback, the workload cannot reach it at all;
      * bound to `0.0.0.0`, every other process on this host — and anything that can
        route to the host — can use this proxy as an open relay, which is the
        uncontrolled egress path B-01 is about.

    `SKYLA_EGRESS_BIND` selects the address; it defaults to loopback so behaviour
    is unchanged when no perimeter is installed.
    """
    policy_name = os.getenv("SKYLA_EGRESS_POLICY", "")
    enabled = os.getenv("SKYLA_EGRESS_ENABLED", "0") == "1"
    if not (enabled or policy_name):
        return None
    policy = POLICIES.get(policy_name, POLICIES["deny-all"])
    bind = os.getenv("SKYLA_EGRESS_BIND", "127.0.0.1")
    if bind == "0.0.0.0":
        # Refuse rather than warn: an open relay is the finding, not a preference.
        raise EgressDenied(
            "refusing to bind the egress proxy to 0.0.0.0 — that makes it an open "
            "relay for every process on the host; bind the perimeter's host-side "
            "gateway address (10.201.0.1) or loopback", destination=bind)
    return EgressProxy(host=bind, port=int(os.getenv("SKYLA_EGRESS_PORT", "0")),
                       policy=policy)


# Singleton, started on demand by the API when enabled.
egress_proxy: EgressProxy | None = None
egress_audit = EgressAudit()
